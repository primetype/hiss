//! Elliptic curve traits, types, and implementations.
//!
//! # Curve trait
//!
//! The [`Curve`] trait defines an elliptic curve at the type level —
//! its name, key sizes, and the concrete types for public keys,
//! signatures, and shared secrets. Marker types (e.g. [`p256::P256`])
//! implement it so that generic code can be parameterised over curves
//! without runtime dispatch.
//!
//! # CryptoProviderAsync trait
//!
//! [`CryptoProviderAsync<C>`] abstracts over *how* a curve's operations
//! are performed. The same curve may be backed by a pure-software
//! implementation or by hardware (Secure Enclave, StrongBox). The
//! trait is async because hardware-backed operations may require
//! user presence (biometric).
//!
//! # P-256 backends
//!
//! Two implementations of the P-256 private key exist:
//!
//! * **Software** ([`p256::P256r1PrivateKey`], always available) —
//!   pure-Rust implementation using `eccoxide`. Suitable for tests,
//!   WASM, and any platform without hardware key storage.
//!
//! * **macOS Secure Enclave** ([`p256::apple::P256r1PrivateKey`],
//!   `cfg(target_os = "macos")`) — delegates to Apple's Security
//!   framework. Private keys never leave the Secure Enclave; signing
//!   and ECDH are performed in hardware.
//!
//! Both backends share the same [`p256::P256r1PublicKey`] and
//! [`p256::P256Signature`] types, and their DH results are
//! compatible (X9.63 KDF with SHA-256).


pub mod ed25519;
pub mod p256;

// ── Curve trait ─────────────────────────────────────────────────

/// An elliptic curve with its associated key and output types.
///
/// Implemented by zero-sized marker types (e.g. [`p256::P256`]).
/// The associated constants provide sizes needed by the Noise
/// protocol and serialisation layers; the associated types tie
/// the curve to its concrete public key, signature, and shared
/// secret representations.
pub trait Curve {
    /// Noise name component (e.g. `"P256"`).
    const NAME: &'static str;

    /// DH output length in bytes (`DHLEN` in the Noise spec).
    const DHLEN: usize;

    /// Serialised public key size in bytes.
    const PUBLIC_KEY_SIZE: usize;

    /// Private key / scalar size in bytes.
    const PRIVATE_KEY_SIZE: usize;

    /// Error type for curve operations (e.g. invalid key encoding).
    type Error: std::error::Error + Send + Sync;

    /// The public key type for this curve.
    type PublicKey: Clone;

    /// The signature type produced by signing with this curve.
    type Signature;

    /// The shared secret type produced by ECDH on this curve.
    type SharedSecret;

    /// Deserialise a public key from its canonical byte representation.
    fn public_key_from_bytes(bytes: &[u8]) -> Result<Self::PublicKey, Self::Error>;
}

/// Shared secret derived from an ECDH key exchange.
///
/// The raw 32-byte x-coordinate of the shared ECDH point, as
/// required by the Noise protocol specification.
#[derive(Clone, PartialEq, Eq)]
pub struct SharedSecret([u8; 32]);

impl SharedSecret {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl AsRef<[u8]> for SharedSecret {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes().as_slice()
    }
}

impl Drop for SharedSecret {
    fn drop(&mut self) {
        crate::zeroize::zeroize_array(&mut self.0);
    }
}

#[cfg(not(test))]
impl std::fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("SharedSecret").finish_non_exhaustive()
    }
}

#[cfg(test)]
impl std::fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("SharedSecret")
            .field(&hex::encode(self.0))
            .finish()
    }
}
