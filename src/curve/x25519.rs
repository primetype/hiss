//! X25519 Diffie–Hellman — the Noise `25519` DH function.
//!
//! X25519 is the Curve25519-based ECDH function defined by
//! [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748). It is the
//! dominant Diffie–Hellman function in deployed Noise (libp2p-noise,
//! WireGuard-style protocols), and the spec name component is the bare
//! string `"25519"` — so the protocol name reads e.g.
//! `Noise_XX_25519_ChaChaPoly_BLAKE2b`.
//!
//! This module implements the [`Curve`] and [`DhCurve`] traits for
//! X25519; the provider backend that performs its operations lives in
//! [`crate::provider`]. X25519 is **DH-only** — it deliberately does
//! *not* implement [`SigningCurve`](super::SigningCurve). For signatures
//! over the 25519 family use [`Ed25519`](super::ed25519::Ed25519).
//!
//! # Backend
//!
//! * **Software** ([`SoftwareX25519PrivateKey`], always available) —
//!   pure-Rust implementation using `cryptoxide`'s `x25519`. Suitable
//!   for tests, WASM, and any platform without hardware key storage.
//!
//! There is **no** Apple Secure Enclave backend: the Secure Enclave is
//! P-256-only, so X25519 is software on every platform.
//!
//! # Wire format and interop
//!
//! Public keys and shared secrets are plain 32-byte values; there is no
//! point compression flag or KDF. `cryptoxide` clamps the scalar per
//! RFC 7748 inside `dh`/`base`, exactly as `snow` does, so handshakes are
//! byte-for-byte interoperable.
//!
//! Per RFC 7748, X25519 has small-order input points whose shared secret
//! is all-zero. The Noise `25519` DH function performs no validation
//! (unlike this crate's P-256, which rejects the identity), so DH never
//! fails here — a contributing low-order key simply yields an all-zero
//! secret, matching `snow` and every conformant Noise implementation.

use std::fmt;

use cryptoxide::x25519;
use packtool::Packed;
use rand_core::{CryptoRng, RngCore};

use super::{Curve, DhCurve, SharedSecret};

// ── Errors ─────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("invalid public key length: expected 32 bytes, got {0}")]
    InvalidPublicKeyLength(usize),
}

// ── Curve marker ───────────────────────────────────────────────

/// X25519 curve marker — the Noise `25519` DH function.
///
/// Zero-sized type implementing [`Curve`] + [`DhCurve`] (but **not**
/// [`SigningCurve`](super::SigningCurve)) that ties together the concrete
/// [`X25519PublicKey`] and [`SharedSecret`] types. Used as the `Cu` type
/// parameter of a Noise protocol and of
/// [`DhProvider`](crate::provider::DhProvider).
pub struct X25519;

impl Curve for X25519 {
    const NAME: &'static str = "25519";
    const PUBLIC_KEY_SIZE: usize = 32;
    const PRIVATE_KEY_SIZE: usize = 32;

    type Error = Error;
    type PublicKey = X25519PublicKey;

    fn public_key_from_bytes(bytes: &[u8]) -> Result<Self::PublicKey, Self::Error> {
        X25519PublicKey::from_bytes(bytes)
    }
}

impl DhCurve for X25519 {
    const DHLEN: usize = 32;
    type SharedSecret = SharedSecret;
}

// Deliberately no `impl SigningCurve for X25519`: X25519 is DH-only.

// ── Public key ─────────────────────────────────────────────────

/// An X25519 public key — a 32-byte Curve25519 u-coordinate.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Packed)]
pub struct X25519PublicKey(#[packed(accessor = false)] [u8; 32]);

impl X25519PublicKey {
    /// Construct from a 32-byte slice.
    ///
    /// Only the length is checked: every 32-byte string is a valid
    /// Curve25519 u-coordinate (RFC 7748 masks the high bit internally),
    /// so there is nothing else to reject.
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
}

impl AsRef<[u8]> for X25519PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for X25519PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl fmt::Debug for X25519PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

// ── Software private key ───────────────────────────────────────

/// Software X25519 private key — 32 raw scalar bytes.
///
/// The scalar is stored un-clamped; `cryptoxide` applies the RFC 7748
/// clamp inside every `dh`/`base` call, so the on-wire and shared-secret
/// bytes match `snow` and any conformant peer. The bytes are zeroised on
/// drop.
///
/// This is the software backend — always available, and the only X25519
/// backend (the Apple Secure Enclave is P-256-only).
pub struct SoftwareX25519PrivateKey {
    /// The 32-byte scalar (un-clamped).
    secret: [u8; 32],
}

impl SoftwareX25519PrivateKey {
    /// Generate a new random X25519 key.
    ///
    /// The caller supplies the RNG, which must be cryptographically
    /// secure. This makes generation compatible with platform-provided
    /// CSPRNGs and allows reproducible tests with a seeded RNG.
    pub fn generate<R: RngCore + CryptoRng>(mut rng: R) -> Self {
        let mut secret = [0u8; 32];
        rng.fill_bytes(&mut secret);
        Self { secret }
    }

    /// Construct from known 32-byte scalar material.
    ///
    /// Useful for testing with deterministic keys or for restoring a key
    /// from storage. The bytes are used as-is (clamped at use time).
    pub fn from_bytes(secret: [u8; 32]) -> Self {
        Self { secret }
    }

    /// Return the corresponding public key (`X25519(scalar, 9)`).
    pub fn public_key(&self) -> X25519PublicKey {
        let public: [u8; 32] = x25519::base(&x25519::SecretKey::from(self.secret)).into();
        X25519PublicKey(public)
    }

    /// Perform Diffie–Hellman key exchange with a peer's public key.
    ///
    /// Returns the 32-byte Curve25519 shared secret. Never fails: per
    /// RFC 7748 a low-order peer key yields an all-zero secret rather than
    /// an error, matching the Noise `25519` DH function.
    pub fn dh(&self, peer: &X25519PublicKey) -> SharedSecret {
        let shared: [u8; 32] = x25519::dh(
            &x25519::SecretKey::from(self.secret),
            &x25519::PublicKey::from(peer.0),
        )
        .into();
        SharedSecret::new(shared)
    }

    /// Return the raw 32-byte scalar.
    ///
    /// Use with care — this is secret material. Intended for persisting
    /// the key to storage (Keychain, sealed blob, etc.).
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.secret
    }
}

impl Drop for SoftwareX25519PrivateKey {
    fn drop(&mut self) {
        crate::zeroize::zeroize_array(&mut self.secret);
    }
}

#[cfg(not(test))]
impl fmt::Debug for SoftwareX25519PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SoftwareX25519PrivateKey")
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
impl fmt::Debug for SoftwareX25519PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SoftwareX25519PrivateKey")
            .field("secret", &hex::encode(self.secret))
            .finish()
    }
}

// ── Tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// Decode a 32-byte hex string into a fixed array.
    fn h32(s: &str) -> [u8; 32] {
        hex::decode(s).unwrap().try_into().unwrap()
    }

    /// RFC 7748 §6.1 — the authoritative X25519 ECDH known-answer test:
    /// derive both public keys from the listed scalars and agree on the
    /// listed shared secret, both directions.
    #[test]
    fn rfc7748_section_6_1_ecdh_known_answer() {
        let alice_sk = h32("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let alice_pk = h32("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        let bob_sk = h32("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        let bob_pk = h32("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        let shared = h32("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

        let alice = SoftwareX25519PrivateKey::from_bytes(alice_sk);
        let bob = SoftwareX25519PrivateKey::from_bytes(bob_sk);

        // Public keys derive correctly.
        assert_eq!(alice.public_key().as_bytes(), &alice_pk);
        assert_eq!(bob.public_key().as_bytes(), &bob_pk);

        // Both sides agree on the published shared secret.
        let ss_ab = alice.dh(&X25519PublicKey::from_bytes(&bob_pk).unwrap());
        let ss_ba = bob.dh(&X25519PublicKey::from_bytes(&alice_pk).unwrap());
        assert_eq!(ss_ab.as_bytes(), &shared);
        assert_eq!(ss_ba.as_bytes(), &shared);
    }

    /// RFC 7748 §5.2 — the authoritative single-iteration scalar/u-coordinate
    /// known-answer test (a non-base u-coordinate, exercising the ladder
    /// directly rather than only the base point).
    #[test]
    fn rfc7748_section_5_2_scalarmult_known_answer() {
        let scalar = h32("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
        let u = h32("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
        let expected = h32("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");

        let sk = SoftwareX25519PrivateKey::from_bytes(scalar);
        let out = sk.dh(&X25519PublicKey::from_bytes(&u).unwrap());
        assert_eq!(out.as_bytes(), &expected);
    }

    #[test]
    fn dh_is_symmetric() {
        let sk1 = SoftwareX25519PrivateKey::generate(rand::rng());
        let pk1 = sk1.public_key();
        let sk2 = SoftwareX25519PrivateKey::generate(rand::rng());
        let pk2 = sk2.public_key();

        assert_eq!(sk1.dh(&pk2), sk2.dh(&pk1));
    }

    #[test]
    fn dh_different_peers_produce_different_secrets() {
        let sk = SoftwareX25519PrivateKey::generate(rand::rng());
        let peer1 = SoftwareX25519PrivateKey::generate(rand::rng()).public_key();
        let peer2 = SoftwareX25519PrivateKey::generate(rand::rng()).public_key();

        assert_ne!(sk.dh(&peer1), sk.dh(&peer2));
    }

    #[test]
    fn public_key_round_trip() {
        let sk = SoftwareX25519PrivateKey::generate(rand::rng());
        let pk = sk.public_key();

        let pk2 = X25519PublicKey::from_bytes(pk.as_bytes()).unwrap();
        assert_eq!(pk, pk2);
    }

    #[test]
    fn public_key_wrong_length_rejected() {
        let err = X25519PublicKey::from_bytes(&[0u8; 31]).unwrap_err();
        assert!(matches!(err, Error::InvalidPublicKeyLength(31)));

        let err = X25519PublicKey::from_bytes(&[0u8; 33]).unwrap_err();
        assert!(matches!(err, Error::InvalidPublicKeyLength(33)));
    }

    /// Contrast with P-256, which rejects the identity: X25519 performs no
    /// validation, so a low-order (here all-zero) peer key yields an
    /// all-zero shared secret rather than an error — exactly the Noise
    /// `25519` behaviour, byte-for-byte with `snow`.
    #[test]
    fn low_order_point_yields_zero_secret_per_spec() {
        let sk = SoftwareX25519PrivateKey::generate(rand::rng());
        let low_order = X25519PublicKey::from_bytes(&[0u8; 32]).unwrap();
        assert_eq!(sk.dh(&low_order).as_bytes(), &[0u8; 32]);
    }

    proptest! {
        /// DH never panics for arbitrary 32-byte peer keys.
        #[test]
        fn dh_never_panics(peer_bytes in any::<[u8; 32]>(), secret in any::<[u8; 32]>()) {
            let sk = SoftwareX25519PrivateKey::from_bytes(secret);
            let peer = X25519PublicKey::from_bytes(&peer_bytes).unwrap();
            let _ = sk.dh(&peer);
        }
    }
}
