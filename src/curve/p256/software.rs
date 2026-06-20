//! Pure-software P-256 private key implementation.
//!
//! Uses `eccoxide` for elliptic curve arithmetic. Key generation draws
//! randomness from a caller-supplied CSPRNG via
//! [`P256r1PrivateKey::generate`] (the crate has no built-in entropy
//! source). Signing is deterministic (RFC 6979) and uses no randomness.
//!
//! The 32 bytes held by [`P256r1PrivateKey`] are the canonical
//! big-endian encoding of the secp256r1 private scalar `d`, which is
//! always in the valid range `[1, n-1]` (`n` is the curve order).
//! [`from_bytes`](P256r1PrivateKey::from_bytes) validates this, and
//! [`to_bytes`](P256r1PrivateKey::to_bytes) round-trips it — so keys
//! interoperate with any standard SEC1 / RFC-conformant P-256 tooling.

use super::{Error, P256Signature, P256r1PublicKey};
use crate::curve::SharedSecret;

use eccoxide::curve::sec2::p256r1::{Point, Scalar};
use rand_core::{CryptoRng, RngCore};
use std::fmt;

/// Software (`eccoxide`-backed) secp256r1 private key — the canonical
/// big-endian encoding of the scalar `d`, in `[1, n-1]`.
///
/// This is the pure-software P-256 backend; the bytes are zeroised on drop.
pub struct P256r1PrivateKey([u8; Self::SIZE]);

impl P256r1PrivateKey {
    /// Length in bytes of the secp256r1 private scalar (32).
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

    /// Generate a private key from a caller-supplied CSPRNG.
    ///
    /// The caller owns the entropy source — pass `rand::rng()` in
    /// production, or a seeded RNG for deterministic tests. A `&mut R`
    /// is itself `RngCore + CryptoRng`, so a borrowed RNG works too.
    /// Rejection-samples into `[1, n-1]`; only a broken RNG can exhaust
    /// the retries.
    pub fn generate<RNG>(mut rng: RNG) -> Result<Self, Error>
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
        Err(Error::ScalarSamplingFailed)
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

    /// Derive the corresponding public key `d·G`.
    pub fn public(&self) -> P256r1PublicKey {
        // Public key is `d·G`. Use the fixed-base comb multiply of the
        // generator: constant-time and ~4x faster than the general
        // variable-base `*` path, because the generator's multiples are
        // precomputed (requires eccoxide's `table` feature; without it
        // `mul_base` falls back to the general multiply, still correct).
        let point = Point::mul_base(&self.scalar());
        P256r1PublicKey::from_point(point)
    }

    /// Produce a deterministic ECDSA signature over `data`.
    ///
    /// The per-signature nonce is generated with **RFC 6979** (an
    /// HMAC-SHA256 DRBG keyed by the private key and the message), so
    /// signing requires no randomness and the same `(key, message)` always
    /// yields the same signature — eliminating the catastrophic
    /// nonce-reuse / weak-RNG failure modes of randomized ECDSA. The `s`
    /// value is low-S normalized, so each signature has one canonical
    /// encoding. Returns `Result` only for parity with the
    /// [`DhProviderAsync`](crate::provider::DhProviderAsync)
    /// trait; signing does not fail in practice.
    pub fn sign(&self, data: impl AsRef<[u8]>) -> Result<P256Signature, Error> {
        Ok(super::ecdsa_sign_rfc6979(&self.0, data.as_ref()))
    }

    /// Diffie-Hellman key agreement: derive the shared secret from this
    /// private key and a peer's public key.
    ///
    /// The returned [`SharedSecret`] is the big-endian x-coordinate of the
    /// point `self · peer`, as the Noise specification requires.
    ///
    /// # Errors
    ///
    /// * [`Error::InvalidPoint`] / [`Error::InvalidFieldElement`] /
    ///   [`Error::UnknownPrefix`] — the peer key does not decode to a valid
    ///   on-curve point.
    /// * [`Error::InvalidSharedSecret`] — the agreement produced the point
    ///   at infinity (an identity or low-order peer key). A successfully
    ///   decoded P-256 peer key cannot reach this, but the explicit check
    ///   is the load-bearing contract for cofactor > 1 curves and ensures
    ///   `dh` never panics on attacker-supplied input.
    pub fn dh(&self, other: &P256r1PublicKey) -> Result<SharedSecret, Error> {
        shared_secret_from(&self.scalar(), &other.to_point()?)
    }
}

/// Compute the ECDH shared secret `scalar · peer`, rejecting a degenerate
/// (point-at-infinity) result with an error instead of panicking.
///
/// Factored out of [`P256r1PrivateKey::dh`] so the rejection branch can be
/// exercised directly with an identity peer point — a state a parsed
/// [`P256r1PublicKey`] can never represent.
fn shared_secret_from(scalar: &Scalar, peer: &Point) -> Result<SharedSecret, Error> {
    let shared = (scalar * peer)
        .to_affine()
        .ok_or(Error::InvalidSharedSecret)?;
    let (x, _) = shared.to_coordinate();
    Ok(SharedSecret::new(x.to_bytes()))
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
    use crate::curve::p256::P256;
    use crate::provider::{
        CryptoKeyProviderAsync, DhProviderAsync, EphemeralOnly, ProviderExt, SigningProviderAsync,
    };
    use proptest::prelude::*;
    use rand::{SeedableRng, rngs::StdRng};

    fn arbitrary_secret_key() -> impl Strategy<Value = P256r1PrivateKey> {
        // Arbitrary bytes are validated as a canonical scalar; the
        // vanishingly rare out-of-range value (< 2^-32) is filtered out.
        any::<[u8; P256r1PrivateKey::SIZE]>().prop_filter_map("not a canonical scalar", |b| {
            P256r1PrivateKey::from_bytes(b).ok()
        })
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

    /// Exercises the [`EphemeralOnly`] through the
    /// [`DhProviderAsync`] trait — sign/verify and ECDH.
    #[tokio::test]
    async fn provider_sign_and_dh() {
        let mut provider = EphemeralOnly::new(StdRng::from_os_rng());

        let sk1 = CryptoKeyProviderAsync::<P256>::generate_static_key_async(&mut provider)
            .await
            .unwrap();
        let pk1 = provider.public(&sk1).unwrap();

        let sk2 = CryptoKeyProviderAsync::<P256>::generate_ephemeral_key_async(&mut provider)
            .await
            .unwrap();
        let pk2 = provider.public(&sk2).unwrap();

        // Sign and verify
        const MSG: &[u8] = b"hello hiss";
        let sig = SigningProviderAsync::<P256>::sign_async(&provider, &sk1, MSG)
            .await
            .unwrap();
        assert!(pk1.verify(sig, MSG));
        assert!(!pk2.verify(sig, MSG));

        // DH symmetry
        let ss1 = DhProviderAsync::<P256>::dh_async(&provider, &sk1, &pk2)
            .await
            .unwrap();
        let ss2 = DhProviderAsync::<P256>::dh_async(&provider, &sk2, &pk1)
            .await
            .unwrap();
        assert_eq!(ss1, ss2);
    }

    #[test]
    fn dh_rejects_degenerate_shared_secret() {
        // A parsed `P256r1PublicKey` can never hold the identity, so drive
        // the rejection branch directly: `scalar · O = O`, which has no
        // affine x-coordinate and must surface as an error, not a panic.
        let sk = P256r1PrivateKey::from_bytes([0x11; 32]).unwrap();
        let err = shared_secret_from(&sk.scalar(), &Point::infinity()).unwrap_err();
        assert!(matches!(err, Error::InvalidSharedSecret));
    }

    proptest! {
        /// `from_bytes` must never panic on arbitrary attacker-supplied
        /// bytes — it either decodes a valid on-curve key or returns an
        /// error (the A3.3 no-panic-on-peer-data contract).
        #[test]
        fn from_bytes_never_panics(bytes in any::<Vec<u8>>()) {
            let _ = P256r1PublicKey::from_bytes(&bytes);
        }

        /// `dh` must never panic and must succeed for any well-formed peer
        /// key, across a wide range of private/peer scalar pairs.
        #[test]
        fn dh_succeeds_for_any_valid_peer(
            sk in arbitrary_secret_key(),
            peer_sk in arbitrary_secret_key(),
        ) {
            prop_assert!(sk.dh(&peer_sk.public()).is_ok());
        }
    }
}
