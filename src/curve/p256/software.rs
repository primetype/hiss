//! Pure-software P-256 private key implementation.
//!
//! Uses `eccoxide` for elliptic curve arithmetic. Randomness is
//! sourced from the operating system's CSPRNG by default, but
//! callers can supply their own via [`P256r1PrivateKey::generate_with`]
//! and [`P256r1PrivateKey::sign_with`].

use super::{Error, P256, P256Signature, P256r1PublicKey, input_to_scalar};
use crate::curve::{CryptoProvider, SharedSecret};

use eccoxide::curve::sec2::p256r1::{Point, Scalar};
use rand_core::{CryptoRng, RngCore};
use std::fmt;

#[derive(Clone)]
pub struct P256r1PrivateKey([u8; Self::SIZE]);

impl P256r1PrivateKey {
    pub const SIZE: usize = 32;

    #[inline]
    pub fn from_bytes(bytes: [u8; Self::SIZE]) -> Self {
        Self(bytes)
    }

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
        getrandom::fill(&mut bytes).map_err(|e| Error::Rng(e.to_string()))?;
        Ok(Self(bytes))
    }

    pub fn generate_with<RNG>(mut rng: RNG) -> Result<Self, Error>
    where
        RNG: RngCore + CryptoRng,
    {
        let mut bytes = [0; Self::SIZE];
        rng.fill_bytes(&mut bytes);
        Ok(Self(bytes))
    }

    pub fn public(&self) -> P256r1PublicKey {
        let s = input_to_scalar(self.0);
        let point = &s * &Point::generator();
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
        let d = input_to_scalar(self.0);
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
        let scalar = input_to_scalar(self.0);
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

    prop_compose! {
        fn arbitrary_secret_key()(
            bytes in any::<[u8; P256r1PrivateKey::SIZE]>()
        ) -> P256r1PrivateKey {
            P256r1PrivateKey(bytes)
        }
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
