//! Ed25519 signing and key exchange.
//!
//! Ed25519 is used for signing message headers — where the signature
//! can double as a `message_id` — and, via the birational equivalence
//! between Edwards and Montgomery forms, for Diffie–Hellman key
//! exchange.
//!
//! This module implements the [`Curve`] trait for Ed25519; the provider
//! backends that perform its operations live in [`crate::provider`].
//!
//! # Backends
//!
//! * **Software** ([`SoftwareEd25519PrivateKey`], always available) —
//!   pure-Rust implementation using `cryptoxide`. Suitable for tests,
//!   WASM, and any platform without native Ed25519 support.
//!
//! * **Apple** (iOS/macOS) — Ed25519 is still **software**-signed (the
//!   Secure Enclave has no Ed25519 support), but the 32-byte seed is
//!   sealed at rest to the device's Secure Enclave P-256 key. See
//!   [`AppleSecureEnclave`](crate::provider::AppleSecureEnclave).
//!
//! Both backends share the same [`Ed25519PublicKey`] and
//! [`Ed25519Signature`] types, and both produce RFC 8032-compliant
//! deterministic signatures.
//!
//! # Determinism
//!
//! Ed25519 signatures are deterministic per RFC 8032 — the same
//! input always produces the same signature. This is critical
//! because `message_id = signature`, so non-deterministic signatures
//! would produce non-reproducible message identifiers.
//!
//! # Key exchange
//!
//! DH is performed by converting Ed25519 keys to their Curve25519
//! (Montgomery) equivalents via `cryptoxide::ed25519::exchange`.
//! The shared secret is 32 bytes — the x-coordinate of the shared
//! point on Curve25519.
//!
//! This Ed25519 DH is a **standalone** capability over Ed25519 keys; it
//! is **not** the Noise `25519` DH function. A Noise handshake that wants
//! Curve25519 key agreement must use [`X25519`](super::x25519::X25519),
//! whose public keys are bare Montgomery u-coordinates and interoperate
//! byte-for-byte with other Noise implementations. The two are **not**
//! wire-compatible — an Edwards-point encoding here versus a Montgomery
//! u-coordinate there.

use std::fmt;

use cryptoxide::ed25519 as ed;
use packtool::Packed;
use rand_core::{CryptoRng, RngCore};

use super::{Curve, DhCurve, SharedSecret, SigningCurve};

// ── Errors ─────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("invalid public key length: expected 32 bytes, got {0}")]
    InvalidPublicKeyLength(usize),
    #[error("invalid signature length: expected 64 bytes, got {0}")]
    InvalidSignatureLength(usize),
    /// A platform entropy/key operation failed (Apple `SecRandom` seed path).
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    #[error("{0}")]
    Platform(String),
}

// ── Curve marker ───────────────────────────────────────────────

/// Ed25519 curve marker.
///
/// Zero-sized type implementing [`Curve`] that ties together the
/// concrete [`Ed25519PublicKey`], [`Ed25519Signature`], and
/// [`SharedSecret`] types. Used as a type parameter for
/// [`DhProviderAsync`](crate::provider::DhProviderAsync).
pub struct Ed25519;

impl Curve for Ed25519 {
    const NAME: &'static str = "Ed25519";
    const PUBLIC_KEY_SIZE: usize = 32;
    const PRIVATE_KEY_SIZE: usize = 32;

    type Error = Error;
    type PublicKey = Ed25519PublicKey;

    fn public_key_from_bytes(bytes: &[u8]) -> Result<Self::PublicKey, Self::Error> {
        Ed25519PublicKey::from_bytes(bytes)
    }
}

impl DhCurve for Ed25519 {
    const DHLEN: usize = 32;
    type SharedSecret = SharedSecret;
}

impl SigningCurve for Ed25519 {
    type Signature = Ed25519Signature;
}

// ── Public key ─────────────────────────────────────────────────

/// An Ed25519 public key (32 bytes).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Packed)]
pub struct Ed25519PublicKey(#[packed(accessor = false)] [u8; 32]);

impl Ed25519PublicKey {
    /// Construct from a 32-byte slice.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| Error::InvalidPublicKeyLength(bytes.len()))?;
        Ok(Self(arr))
    }

    /// Return the raw 32 bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Verify an Ed25519 signature over `message`.
    pub fn verify(&self, signature: Ed25519Signature, message: impl AsRef<[u8]>) -> bool {
        ed::verify(message.as_ref(), &self.0, &signature.0)
    }
}

impl AsRef<[u8]> for Ed25519PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for Ed25519PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl fmt::Debug for Ed25519PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

// ── Signature ──────────────────────────────────────────────────

/// An Ed25519 signature (64 bytes).
///
/// When a signature doubles as a message identifier, it is
/// unforgeable, deterministic (RFC 8032), and self-verifying.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Packed)]
pub struct Ed25519Signature(#[packed(accessor = false)] [u8; 64]);

impl Ed25519Signature {
    /// Construct from a 64-byte slice.
    pub fn try_from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let arr: [u8; 64] = bytes
            .try_into()
            .map_err(|_| Error::InvalidSignatureLength(bytes.len()))?;
        Ok(Self(arr))
    }

    /// Return the raw 64 bytes.
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

impl AsRef<[u8]> for Ed25519Signature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for Ed25519Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl fmt::Debug for Ed25519Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

// ── Software private key ───────────────────────────────────────

/// Software Ed25519 private key (32-byte seed + cached keypair).
///
/// The seed is expanded internally by `cryptoxide` per RFC 8032
/// when signing. Both the seed and cached keypair are zeroised on
/// drop.
///
/// This is the software backend — always available, and the only
/// Ed25519 backend; on Apple platforms its seed is sealed at rest to
/// the Secure Enclave P-256 key (see
/// [`AppleSecureEnclave`](crate::provider::AppleSecureEnclave)).
pub struct SoftwareEd25519PrivateKey {
    /// The 32-byte seed.
    seed: [u8; 32],
    /// The 64-byte keypair (seed ‖ public key) cached for signing.
    keypair: [u8; 64],
}

impl SoftwareEd25519PrivateKey {
    /// Generate a new random Ed25519 key pair.
    ///
    /// The caller supplies the RNG, which must be cryptographically
    /// secure. This makes generation compatible with platform-provided
    /// CSPRNGs and allows reproducible tests with a seeded RNG.
    pub fn generate<R: RngCore + CryptoRng>(mut rng: R) -> Self {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        Self::from_seed(seed)
    }

    /// Construct from a known 32-byte seed.
    ///
    /// Useful for testing with deterministic keys or for restoring
    /// a key from storage.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let (keypair, _public) = ed::keypair(&seed);
        Self { seed, keypair }
    }

    /// Return the corresponding public key.
    pub fn public_key(&self) -> Ed25519PublicKey {
        let pk_bytes: [u8; 32] = self.keypair[32..64].try_into().unwrap();
        Ed25519PublicKey(pk_bytes)
    }

    /// Sign `message` with this key. Deterministic per RFC 8032.
    pub fn sign(&self, message: &[u8]) -> Ed25519Signature {
        Ed25519Signature(ed::signature(message, &self.keypair))
    }

    /// Perform Diffie–Hellman key exchange with a peer's public key.
    ///
    /// Converts Ed25519 keys to their Curve25519 (Montgomery)
    /// equivalents via `cryptoxide::ed25519::exchange`.
    pub fn dh(&self, peer: &Ed25519PublicKey) -> SharedSecret {
        SharedSecret::new(ed::exchange(&peer.0, &self.seed))
    }

    /// Return the raw 32-byte seed.
    ///
    /// Use with care — this is secret material. Intended for
    /// persisting the key to storage (Keychain, sealed blob, etc.).
    pub fn seed(&self) -> &[u8; 32] {
        &self.seed
    }
}

impl Drop for SoftwareEd25519PrivateKey {
    fn drop(&mut self) {
        crate::zeroize::zeroize_array(&mut self.seed);
        crate::zeroize::zeroize_array(&mut self.keypair);
    }
}

#[cfg(not(test))]
impl fmt::Debug for SoftwareEd25519PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SoftwareEd25519PrivateKey")
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
impl fmt::Debug for SoftwareEd25519PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SoftwareEd25519PrivateKey")
            .field("seed", &hex::encode(self.seed))
            .finish()
    }
}

// ── Tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::{
        CryptoKeyProviderAsync, DhProviderAsync, EphemeralOnly, ProviderExt, SigningProviderAsync,
    };
    use rand::{SeedableRng, rngs::StdRng};

    // ── Direct API tests ─────────────────────────────────────────

    #[test]
    fn generate_and_sign_verify() {
        let sk = SoftwareEd25519PrivateKey::generate(rand::rng());
        let pk = sk.public_key();
        let msg = b"Hello hiss";

        let sig = sk.sign(msg);
        assert!(pk.verify(sig, msg));
    }

    #[test]
    fn deterministic_signatures() {
        let sk = SoftwareEd25519PrivateKey::generate(rand::rng());
        let msg = b"determinism matters";

        let sig1 = sk.sign(msg);
        let sig2 = sk.sign(msg);
        assert_eq!(
            sig1, sig2,
            "Ed25519 signatures must be deterministic (RFC 8032)"
        );
    }

    #[test]
    fn wrong_message_fails_verification() {
        let sk = SoftwareEd25519PrivateKey::generate(rand::rng());
        let pk = sk.public_key();

        let sig = sk.sign(b"correct message");
        assert!(!pk.verify(sig, b"wrong message"));
    }

    #[test]
    fn wrong_key_fails_verification() {
        let sk1 = SoftwareEd25519PrivateKey::generate(rand::rng());
        let sk2 = SoftwareEd25519PrivateKey::generate(rand::rng());
        let pk2 = sk2.public_key();

        let sig = sk1.sign(b"signed by sk1");
        assert!(!pk2.verify(sig, b"signed by sk1"));
    }

    #[test]
    fn corrupted_signature_fails() {
        let sk = SoftwareEd25519PrivateKey::generate(rand::rng());
        let pk = sk.public_key();
        let sig = sk.sign(b"test");

        let mut raw = *sig.as_bytes();
        raw[16] ^= 0xFF;
        let corrupted = Ed25519Signature::try_from_bytes(&raw).unwrap();

        assert!(!pk.verify(corrupted, b"test"));
    }

    #[test]
    fn zero_signature_fails() {
        let sk = SoftwareEd25519PrivateKey::generate(rand::rng());
        let pk = sk.public_key();

        let zero_sig = Ed25519Signature::try_from_bytes(&[0u8; 64]).unwrap();
        assert!(!pk.verify(zero_sig, b"anything"));
    }

    #[test]
    fn public_key_round_trip() {
        let sk = SoftwareEd25519PrivateKey::generate(rand::rng());
        let pk = sk.public_key();

        let pk2 = Ed25519PublicKey::from_bytes(pk.as_bytes()).unwrap();
        assert_eq!(pk, pk2);
    }

    #[test]
    fn public_key_wrong_length_rejected() {
        let err = Ed25519PublicKey::from_bytes(&[0u8; 31]).unwrap_err();
        assert!(matches!(err, Error::InvalidPublicKeyLength(31)));

        let err = Ed25519PublicKey::from_bytes(&[0u8; 33]).unwrap_err();
        assert!(matches!(err, Error::InvalidPublicKeyLength(33)));
    }

    #[test]
    fn signature_wrong_length_rejected() {
        let err = Ed25519Signature::try_from_bytes(&[0u8; 63]).unwrap_err();
        assert!(matches!(err, Error::InvalidSignatureLength(63)));

        let err = Ed25519Signature::try_from_bytes(&[0u8; 65]).unwrap_err();
        assert!(matches!(err, Error::InvalidSignatureLength(65)));
    }

    #[test]
    fn from_seed_is_deterministic() {
        let seed = [42u8; 32];
        let sk1 = SoftwareEd25519PrivateKey::from_seed(seed);
        let sk2 = SoftwareEd25519PrivateKey::from_seed(seed);

        assert_eq!(sk1.public_key(), sk2.public_key());

        let sig1 = sk1.sign(b"same seed same key");
        let sig2 = sk2.sign(b"same seed same key");
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn different_seeds_produce_different_keys() {
        let sk1 = SoftwareEd25519PrivateKey::from_seed([1u8; 32]);
        let sk2 = SoftwareEd25519PrivateKey::from_seed([2u8; 32]);

        assert_ne!(sk1.public_key(), sk2.public_key());
    }

    // ── DH tests ─────────────────────────────────────────────────

    #[test]
    fn dh_is_symmetric() {
        let sk1 = SoftwareEd25519PrivateKey::generate(rand::rng());
        let pk1 = sk1.public_key();
        let sk2 = SoftwareEd25519PrivateKey::generate(rand::rng());
        let pk2 = sk2.public_key();

        let ss1 = sk1.dh(&pk2);
        let ss2 = sk2.dh(&pk1);
        assert_eq!(ss1, ss2);
    }

    #[test]
    fn dh_different_peers_produce_different_secrets() {
        let sk = SoftwareEd25519PrivateKey::generate(rand::rng());
        let peer1 = SoftwareEd25519PrivateKey::generate(rand::rng())
            .public_key();
        let peer2 = SoftwareEd25519PrivateKey::generate(rand::rng())
            .public_key();

        let ss1 = sk.dh(&peer1);
        let ss2 = sk.dh(&peer2);
        assert_ne!(ss1, ss2);
    }

    // ── DhProviderAsync trait tests ───────────────────────────────

    #[tokio::test]
    async fn provider_sign_and_dh() {
        let mut provider = EphemeralOnly::new(StdRng::from_os_rng());

        let sk1 = CryptoKeyProviderAsync::<Ed25519>::generate_static_key_async(&mut provider)
            .await
            .unwrap();
        let pk1 = provider.public(&sk1).unwrap();

        let sk2 = CryptoKeyProviderAsync::<Ed25519>::generate_ephemeral_key_async(&mut provider)
            .await
            .unwrap();
        let pk2 = provider.public(&sk2).unwrap();

        // Sign and verify
        const MSG: &[u8] = b"hello hiss";
        let sig = SigningProviderAsync::<Ed25519>::sign_async(&provider, &sk1, MSG)
            .await
            .unwrap();
        assert!(pk1.verify(sig, MSG));
        assert!(!pk2.verify(sig, MSG));

        // DH symmetry
        let ss1 = DhProviderAsync::<Ed25519>::dh_async(&provider, &sk1, &pk2)
            .await
            .unwrap();
        let ss2 = DhProviderAsync::<Ed25519>::dh_async(&provider, &sk2, &pk1)
            .await
            .unwrap();
        assert_eq!(ss1, ss2);
    }
}
