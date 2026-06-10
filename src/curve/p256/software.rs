//! Pure-software P-256 private key implementation.
//!
//! Uses `eccoxide` for elliptic curve arithmetic. Randomness is
//! sourced from the operating system's CSPRNG by default, but
//! callers can supply their own via [`P256r1PrivateKey::generate_with`]
//! and [`P256r1PrivateKey::sign_with`].
//!
//! The 32 bytes held by [`P256r1PrivateKey`] are the canonical
//! big-endian encoding of the secp256r1 private scalar `d`, which is
//! always in the valid range `[1, n-1]` (`n` is the curve order).
//! [`from_bytes`](P256r1PrivateKey::from_bytes) validates this, and
//! [`to_bytes`](P256r1PrivateKey::to_bytes) round-trips it — so keys
//! interoperate with any standard SEC1 / RFC-conformant P-256 tooling.

use super::{Error, P256, P256Signature, P256r1PublicKey, input_to_scalar};
use crate::curve::{CryptoProvider, SharedSecret};

use eccoxide::curve::sec2::p256r1::{Point, Scalar};
use rand_core::{CryptoRng, RngCore};
use std::fmt;

#[derive(Clone)]
pub struct P256r1PrivateKey([u8; Self::SIZE]);

impl P256r1PrivateKey {
    pub const SIZE: usize = 32;

    /// Upper bound on rejection-sampling iterations when generating a
    /// scalar. A valid 256-bit value lands outside `[1, n-1]` with
    /// probability `< 2^-32`, so this is never reached with a sound
    /// CSPRNG; exceeding it indicates a broken RNG.
    const MAX_SCALAR_RETRIES: usize = 128;

    /// Wrap 32 bytes into a private key, validating that they encode a
    /// canonical secp256r1 scalar in `[1, n-1]`.
    ///
    /// Returns [`Error::InvalidPrivateKey`] if the value is zero or
    /// greater than or equal to the curve order `n`.
    #[inline]
    pub fn from_bytes(bytes: [u8; Self::SIZE]) -> Result<Self, Error> {
        if Self::scalar_of(&bytes).is_some() {
            Ok(Self(bytes))
        } else {
            Err(Error::InvalidPrivateKey)
        }
    }

    /// The canonical big-endian encoding of the private scalar `d`.
    #[inline]
    pub fn to_bytes(&self) -> &[u8; Self::SIZE] {
        &self.0
    }

    #[inline]
    pub fn generate_ephemeral() -> Result<Self, Error> {
        Self::generate()
    }

    #[inline]
    pub fn generate() -> Result<Self, Error> {
        let mut bytes = [0; Self::SIZE];
        for _ in 0..Self::MAX_SCALAR_RETRIES {
            getrandom::fill(&mut bytes).map_err(|e| Error::Rng(e.to_string()))?;
            if Self::scalar_of(&bytes).is_some() {
                return Ok(Self(bytes));
            }
        }
        Err(Error::Rng("failed to sample a valid scalar".into()))
    }

    pub fn generate_with<RNG>(mut rng: RNG) -> Result<Self, Error>
    where
        RNG: RngCore + CryptoRng,
    {
        let mut bytes = [0; Self::SIZE];
        for _ in 0..Self::MAX_SCALAR_RETRIES {
            rng.fill_bytes(&mut bytes);
            if Self::scalar_of(&bytes).is_some() {
                return Ok(Self(bytes));
            }
        }
        Err(Error::Rng("failed to sample a valid scalar".into()))
    }

    /// Parse `bytes` as a canonical scalar in `[1, n-1]`.
    ///
    /// Returns `None` if the value is zero or `>= n`. `from_slice`
    /// already rejects out-of-range encodings; the explicit zero check
    /// rejects the remaining invalid value.
    #[inline]
    fn scalar_of(bytes: &[u8; Self::SIZE]) -> Option<Scalar> {
        match Scalar::from_slice(bytes) {
            Some(s) if s != Scalar::zero() => Some(s),
            _ => None,
        }
    }

    /// The private scalar `d`. Infallible: every constructor validates
    /// the stored bytes, so the encoding is always canonical.
    #[inline]
    fn scalar(&self) -> Scalar {
        Self::scalar_of(&self.0).expect("private key validated on construction")
    }

    pub fn public(&self) -> P256r1PublicKey {
        let point = &self.scalar() * &Point::generator();
        P256r1PublicKey::from_point(point)
    }

    pub fn sign(&self, data: impl AsRef<[u8]>) -> Result<P256Signature, Error> {
        let mut nonce = [0u8; 32];
        getrandom::fill(&mut nonce).map_err(|e| Error::Rng(e.to_string()))?;
        self.sign_with_nonce(nonce, data)
    }

    pub fn sign_with<RNG>(
        &self,
        mut rng: RNG,
        data: impl AsRef<[u8]>,
    ) -> Result<P256Signature, Error>
    where
        RNG: CryptoRng + RngCore,
    {
        let mut nonce = [0u8; 32];
        rng.fill_bytes(&mut nonce);
        self.sign_with_nonce(nonce, data)
    }

    /// Produce an ECDSA signature from a caller-provided 32-byte nonce.
    ///
    /// The nonce **must** be unique and unpredictable for every
    /// signature under a given key; reusing or leaking it allows
    /// recovery of the private key.
    fn sign_with_nonce(
        &self,
        nonce: [u8; 32],
        data: impl AsRef<[u8]>,
    ) -> Result<P256Signature, Error> {
        let k = input_to_scalar(nonce);
        let d = self.scalar();
        let e = input_to_scalar(data);

        let x = &k * &Point::generator();
        let px = x.to_affine().ok_or(Error::InvalidPoint)?;
        let (x1, _) = px.to_coordinate();
        let r = Scalar::from_bytes(&x1.to_bytes()).unwrap();
        let kinv = k.inverse();
        let s = kinv * (e + &r * d);

        let mut v = [0u8; 64];
        v[..32].copy_from_slice(&r.to_bytes()[..32]);
        v[32..].copy_from_slice(&s.to_bytes()[..32]);
        P256Signature::try_from_bytes(v)
    }

    pub fn dh(&self, other: &P256r1PublicKey) -> SharedSecret {
        let scalar = self.scalar();
        let point = other.to_point().unwrap();
        let shared_point = &scalar * &point;
        let shared_point = shared_point.to_affine().unwrap();
        let (x, _) = shared_point.to_coordinate();
        SharedSecret::new(x.to_bytes())
    }
}

// ── CryptoProvider ──────────────────────────────────────────────

/// Pure-software [`CryptoProvider`] for P-256.
///
/// Uses `eccoxide` for all curve operations. Works on every
/// platform (including WASM). All operations resolve immediately —
/// no hardware interaction, no biometric prompts.
#[derive(Clone, Copy)]
pub struct SoftwareCryptoProvider;

impl CryptoProvider<P256> for SoftwareCryptoProvider {
    type Error = Error;
    type PrivateKey = P256r1PrivateKey;

    async fn generate_static_key(&self) -> Result<Self::PrivateKey, Self::Error> {
        P256r1PrivateKey::generate()
    }

    async fn generate_ephemeral_key(&self) -> Result<Self::PrivateKey, Self::Error> {
        P256r1PrivateKey::generate()
    }

    fn public_key(&self, key: &Self::PrivateKey) -> Result<P256r1PublicKey, Self::Error> {
        Ok(key.public())
    }

    async fn sign(
        &self,
        key: &Self::PrivateKey,
        message: &[u8],
    ) -> Result<P256Signature, Self::Error> {
        key.sign(message)
    }

    async fn dh(
        &self,
        key: &Self::PrivateKey,
        peer: &P256r1PublicKey,
    ) -> Result<SharedSecret, Self::Error> {
        Ok(key.dh(peer))
    }
}

#[cfg(not(test))]
impl fmt::Debug for P256r1PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("P256r1PrivateKey").finish_non_exhaustive()
    }
}

#[cfg(test)]
impl fmt::Debug for P256r1PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("P256r1PrivateKey")
            .field(&hex::encode(self.0))
            .finish()
    }
}

impl Drop for P256r1PrivateKey {
    fn drop(&mut self) {
        crate::zeroize::zeroize_array(&mut self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn arbitrary_secret_key() -> impl Strategy<Value = P256r1PrivateKey> {
        // Arbitrary bytes are validated as a canonical scalar; the
        // vanishingly rare out-of-range value (< 2^-32) is filtered out.
        any::<[u8; P256r1PrivateKey::SIZE]>()
            .prop_filter_map("not a canonical scalar", |b| P256r1PrivateKey::from_bytes(b).ok())
    }

    #[test]
    fn from_bytes_rejects_zero() {
        let err = P256r1PrivateKey::from_bytes([0u8; 32]).unwrap_err();
        assert!(matches!(err, Error::InvalidPrivateKey));
    }

    #[test]
    fn from_bytes_rejects_value_at_or_above_order() {
        // All-0xFF exceeds the curve order n, so it is not a canonical
        // scalar and must be rejected.
        let err = P256r1PrivateKey::from_bytes([0xFF; 32]).unwrap_err();
        assert!(matches!(err, Error::InvalidPrivateKey));
    }

    #[test]
    fn from_bytes_accepts_canonical_scalar_and_round_trips() {
        let bytes = [0x11u8; 32]; // < n, non-zero
        let key = P256r1PrivateKey::from_bytes(bytes).expect("valid scalar");
        // The stored bytes are the scalar itself — exact round-trip.
        assert_eq!(key.to_bytes(), &bytes);
    }

    #[test]
    fn stored_bytes_are_the_scalar_not_a_seed() {
        // Public key derivation must use the stored scalar directly:
        // the same bytes always yield the same public key, and equal
        // scalars yield equal keys (no hashing of the seed in between).
        let bytes = [0x11u8; 32];
        let k1 = P256r1PrivateKey::from_bytes(bytes).unwrap();
        let k2 = P256r1PrivateKey::from_bytes(bytes).unwrap();
        assert_eq!(k1.public(), k2.public());

        // A one-bit change in the scalar changes the public key.
        let mut other = bytes;
        other[31] ^= 0x01;
        let k3 = P256r1PrivateKey::from_bytes(other).unwrap();
        assert_ne!(k1.public(), k3.public());
    }

    proptest! {
        #[test]
        fn signing_verify_works(
            signing_key in arbitrary_secret_key(),
            message in any::<Vec<u8>>(),
        ) {
            let public_key = signing_key.public();
            let signature = signing_key.sign(&message).unwrap();

            prop_assert!(
                public_key.verify(signature, &message)
            )
        }
    }

    /// Exercises the [`SoftwareCryptoProvider`] through the
    /// [`CryptoProvider`] trait — sign/verify and ECDH.
    #[tokio::test]
    async fn provider_sign_and_dh() {
        let provider = SoftwareCryptoProvider;

        let sk1 = provider.generate_static_key().await.unwrap();
        let pk1 = provider.public_key(&sk1).unwrap();

        let sk2 = provider.generate_ephemeral_key().await.unwrap();
        let pk2 = provider.public_key(&sk2).unwrap();

        // Sign and verify
        const MSG: &[u8] = b"hello bubble";
        let sig = provider.sign(&sk1, MSG).await.unwrap();
        assert!(pk1.verify(sig, MSG));
        assert!(!pk2.verify(sig, MSG));

        // DH symmetry
        let ss1 = provider.dh(&sk1, &pk2).await.unwrap();
        let ss2 = provider.dh(&sk2, &pk1).await.unwrap();
        assert_eq!(ss1, ss2);
    }
}
