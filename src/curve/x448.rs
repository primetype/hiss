//! X448 Diffie–Hellman — the Noise `448` DH function.
//!
//! X448 is the Curve448-based ECDH function defined by
//! [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748). It offers a higher
//! security margin (~224-bit) than X25519, and the spec name component is
//! the bare string `"448"` — so the protocol name reads e.g.
//! `Noise_XX_448_ChaChaPoly_BLAKE2b`.
//!
//! This module implements the [`Curve`] and [`DhCurve`] traits for X448;
//! the provider backend that performs its operations lives in
//! [`crate::provider`]. X448 is **DH-only** — it deliberately does *not*
//! implement [`SigningCurve`](super::SigningCurve) (Curve448 has no
//! signature scheme in this crate).
//!
//! # Backend
//!
//! * **Software** ([`SoftwareX448PrivateKey`], always available) — pure-Rust
//!   implementation using `eccoxide`'s `protocol::x448`. Unlike X25519
//!   (which uses `cryptoxide`), X448 lives in `eccoxide`, since `cryptoxide`
//!   ships no Curve448. The ECDH is a constant-time Montgomery ladder, so it
//!   is safe to run on the secret scalar.
//!
//! There is **no** Apple Secure Enclave backend: the Secure Enclave is
//! P-256-only, so X448 is software on every platform.
//!
//! # Wire format and interop
//!
//! Public keys and shared secrets are plain 56-byte little-endian values
//! (RFC 7748); there is no point compression flag or KDF. `eccoxide` clamps
//! the scalar per RFC 7748 inside every exchange, so handshakes are
//! byte-for-byte interoperable with any conformant X448 peer.
//!
//! Per RFC 7748, X448 has small-order input points whose shared secret is
//! all-zero. The Noise `448` DH function performs no validation (like this
//! crate's X25519, and unlike its P-256 which rejects the identity), so DH
//! never fails here — a low-order key simply yields an all-zero secret,
//! matching every conformant Noise implementation.

use std::fmt;

use eccoxide::protocol::x448;
use packtool::Packed;
use rand_core::{CryptoRng, RngCore};

use super::{Curve, DhCurve, SharedSecret};

// ── Errors ─────────────────────────────────────────────────────

/// Errors produced by the X448 DH curve.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A public-key byte string was not the expected 56 bytes; the wrapped
    /// value is the length supplied. Decoding never fails otherwise — every
    /// 56-byte string is a valid Curve448 u-coordinate (RFC 7748).
    #[error("invalid public key length: expected 56 bytes, got {0}")]
    InvalidPublicKeyLength(usize),
}

// ── Curve marker ───────────────────────────────────────────────

/// X448 curve marker — the Noise `448` DH function.
///
/// Zero-sized type implementing [`Curve`] + [`DhCurve`] (but **not**
/// [`SigningCurve`](super::SigningCurve)) that ties together the concrete
/// [`X448PublicKey`] and [`SharedSecret`] types. Used as the `Cu` type
/// parameter of a Noise protocol and of
/// [`DhProvider`](crate::provider::DhProvider).
#[derive(Debug, Clone, Copy, Default)]
pub struct X448;

impl Curve for X448 {
    const NAME: &'static str = "448";
    const PUBLIC_KEY_SIZE: usize = 56;
    const PRIVATE_KEY_SIZE: usize = 56;

    type Error = Error;
    type PublicKey = X448PublicKey;

    fn public_key_from_bytes(bytes: &[u8]) -> Result<Self::PublicKey, Self::Error> {
        X448PublicKey::from_bytes(bytes)
    }
}

impl DhCurve for X448 {
    const DHLEN: usize = 56;
    type SharedSecret = SharedSecret<56>;
}

// Deliberately no `impl SigningCurve for X448`: X448 is DH-only.

// ── Public key ─────────────────────────────────────────────────

/// An X448 public key — a 56-byte Curve448 u-coordinate (little-endian).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Packed)]
pub struct X448PublicKey(#[packed(accessor = false)] [u8; 56]);

impl X448PublicKey {
    /// Construct from a 56-byte slice.
    ///
    /// Only the length is checked: every 56-byte string is a valid Curve448
    /// u-coordinate (RFC 7748 masks no bits for the 448-bit field), so there
    /// is nothing else to reject.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let arr: [u8; 56] = bytes
            .try_into()
            .map_err(|_| Error::InvalidPublicKeyLength(bytes.len()))?;
        Ok(Self(arr))
    }

    /// Return the raw 56 bytes.
    pub fn as_bytes(&self) -> &[u8; 56] {
        &self.0
    }
}

impl AsRef<[u8]> for X448PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for X448PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl fmt::Debug for X448PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

// ── Software private key ───────────────────────────────────────

/// Software X448 private key — 56 raw scalar bytes.
///
/// The scalar is stored un-clamped; `eccoxide` applies the RFC 7748 clamp
/// inside every exchange, so the on-wire and shared-secret bytes match any
/// conformant peer. The bytes are zeroised on drop.
///
/// This is the software backend — always available, and the only X448
/// backend (the Apple Secure Enclave is P-256-only).
pub struct SoftwareX448PrivateKey {
    /// The 56-byte scalar (un-clamped).
    secret: [u8; 56],
}

impl SoftwareX448PrivateKey {
    /// Generate a new random X448 key.
    ///
    /// The caller supplies the RNG, which must be cryptographically secure.
    /// This makes generation compatible with platform-provided CSPRNGs and
    /// allows reproducible tests with a seeded RNG.
    pub fn generate<R: RngCore + CryptoRng>(mut rng: R) -> Self {
        let mut secret = [0u8; 56];
        rng.fill_bytes(&mut secret);
        let key = Self { secret };
        crate::zeroize::zeroize_array(&mut secret);
        key
    }

    /// Construct from known 56-byte scalar material.
    ///
    /// Useful for testing with deterministic keys or for restoring a key
    /// from storage. The bytes are used as-is (clamped at use time).
    pub fn from_bytes(secret: [u8; 56]) -> Self {
        Self { secret }
    }

    /// Return the corresponding public key (`X448(scalar, 5)`).
    pub fn public_key(&self) -> X448PublicKey {
        let public = x448::SecretKey::from_bytes(self.secret)
            .public_key()
            .to_bytes();
        X448PublicKey(public)
    }

    /// Perform Diffie–Hellman key exchange with a peer's public key.
    ///
    /// Returns the 56-byte Curve448 shared secret. Never fails: per RFC 7748
    /// a low-order peer key yields an all-zero secret rather than an error,
    /// matching the Noise `448` DH function.
    pub fn dh(&self, peer: &X448PublicKey) -> SharedSecret<56> {
        let shared = x448::SecretKey::from_bytes(self.secret)
            .diffie_hellman(&x448::PublicKey::from_bytes(peer.0))
            .to_bytes();
        SharedSecret::new(shared)
    }

    /// Return the raw 56-byte scalar.
    ///
    /// Use with care — this is secret material. Intended for persisting the
    /// key to storage.
    pub fn as_bytes(&self) -> &[u8; 56] {
        &self.secret
    }
}

impl Drop for SoftwareX448PrivateKey {
    fn drop(&mut self) {
        crate::zeroize::zeroize_array(&mut self.secret);
    }
}

#[cfg(not(test))]
impl fmt::Debug for SoftwareX448PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SoftwareX448PrivateKey")
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
impl fmt::Debug for SoftwareX448PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SoftwareX448PrivateKey")
            .field("secret", &hex::encode(self.secret))
            .finish()
    }
}

// ── Tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// Decode a 56-byte hex string into a fixed array.
    fn h56(s: &str) -> [u8; 56] {
        hex::decode(s).unwrap().try_into().unwrap()
    }

    /// RFC 7748 §6.2 — the authoritative X448 ECDH known-answer test: derive
    /// both public keys from the listed scalars and agree on the listed
    /// shared secret, both directions.
    #[test]
    fn rfc7748_section_6_2_ecdh_known_answer() {
        let alice_sk = h56("9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28d\
             d9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b");
        let alice_pk = h56("9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c\
             22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0");
        let bob_sk = h56("1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d\
             6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d");
        let bob_pk = h56("3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b430\
             27d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609");
        let shared = h56("07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282b\
             b60c0b56fd2464c335543936521c24403085d59a449a5037514a879d");

        let alice = SoftwareX448PrivateKey::from_bytes(alice_sk);
        let bob = SoftwareX448PrivateKey::from_bytes(bob_sk);

        // Public keys derive correctly.
        assert_eq!(alice.public_key().as_bytes(), &alice_pk);
        assert_eq!(bob.public_key().as_bytes(), &bob_pk);

        // Both sides agree on the published shared secret.
        let ss_ab = alice.dh(&X448PublicKey::from_bytes(&bob_pk).unwrap());
        let ss_ba = bob.dh(&X448PublicKey::from_bytes(&alice_pk).unwrap());
        assert_eq!(ss_ab.as_bytes(), &shared);
        assert_eq!(ss_ba.as_bytes(), &shared);
    }

    /// RFC 7748 §5.2 — the authoritative single-iteration scalar/u-coordinate
    /// known-answer test (a non-base u-coordinate, exercising the ladder
    /// directly rather than only the base point).
    #[test]
    fn rfc7748_section_5_2_scalarmult_known_answer() {
        let scalar = h56("3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121\
             700a779c984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3");
        let u = h56("06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f020f08f9\
             814dc031ddbdc38c19c6da2583fa5429db94ada18aa7a7fb4ef8a086");
        let expected = h56("ce3e4ff95a60dc6697da1db1d85e6afbdf79b50a2412d7546d5f239f\
             e14fbaadeb445fc66a01b0779d98223961111e21766282f73dd96b6f");

        let sk = SoftwareX448PrivateKey::from_bytes(scalar);
        let out = sk.dh(&X448PublicKey::from_bytes(&u).unwrap());
        assert_eq!(out.as_bytes(), &expected);
    }

    #[test]
    fn dh_is_symmetric() {
        let sk1 = SoftwareX448PrivateKey::generate(rand::rng());
        let pk1 = sk1.public_key();
        let sk2 = SoftwareX448PrivateKey::generate(rand::rng());
        let pk2 = sk2.public_key();

        assert_eq!(sk1.dh(&pk2), sk2.dh(&pk1));
    }

    #[test]
    fn dh_different_peers_produce_different_secrets() {
        let sk = SoftwareX448PrivateKey::generate(rand::rng());
        let peer1 = SoftwareX448PrivateKey::generate(rand::rng()).public_key();
        let peer2 = SoftwareX448PrivateKey::generate(rand::rng()).public_key();

        assert_ne!(sk.dh(&peer1), sk.dh(&peer2));
    }

    #[test]
    fn public_key_round_trip() {
        let sk = SoftwareX448PrivateKey::generate(rand::rng());
        let pk = sk.public_key();

        let pk2 = X448PublicKey::from_bytes(pk.as_bytes()).unwrap();
        assert_eq!(pk, pk2);
    }

    #[test]
    fn public_key_wrong_length_rejected() {
        let err = X448PublicKey::from_bytes(&[0u8; 55]).unwrap_err();
        assert!(matches!(err, Error::InvalidPublicKeyLength(55)));

        let err = X448PublicKey::from_bytes(&[0u8; 57]).unwrap_err();
        assert!(matches!(err, Error::InvalidPublicKeyLength(57)));
    }

    /// Contrast with P-256, which rejects the identity: X448 performs no
    /// validation, so a low-order (here all-zero) peer key yields an all-zero
    /// shared secret rather than an error — exactly the Noise `448` behaviour.
    #[test]
    fn low_order_point_yields_zero_secret_per_spec() {
        let sk = SoftwareX448PrivateKey::generate(rand::rng());
        let low_order = X448PublicKey::from_bytes(&[0u8; 56]).unwrap();
        assert_eq!(sk.dh(&low_order).as_bytes(), &[0u8; 56]);
    }

    proptest! {
        /// DH never panics for arbitrary 56-byte peer keys.
        #[test]
        fn dh_never_panics(peer_bytes in any::<[u8; 56]>(), secret in any::<[u8; 56]>()) {
            let sk = SoftwareX448PrivateKey::from_bytes(secret);
            let peer = X448PublicKey::from_bytes(&peer_bytes).unwrap();
            let _ = sk.dh(&peer);
        }
    }
}
