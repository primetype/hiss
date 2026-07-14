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
//! # Providers
//!
//! *How* a curve's operations are performed lives in [`crate::provider`]:
//! the [`DhProvider`](crate::provider::DhProvider) /
//! [`DhProviderAsync`](crate::provider::DhProviderAsync) trait
//! family, and the backends that implement it — pure software, or
//! hardware such as the Apple Secure Enclave.
//!
//! # P-256 backends
//!
//! Two implementations of the P-256 private key exist:
//!
//! * **Software** ([`p256::P256r1PrivateKey`], always available) —
//!   pure-Rust implementation using `eccoxide`. Suitable for tests,
//!   WASM, and any platform without hardware key storage.
//!
//! * **Apple Secure Enclave**
//!   (`AppleSecureEnclave`,
//!   `cfg(any(target_os = "macos", target_os = "ios"))`) — delegates to
//!   Apple's Security framework. Private keys never leave the Secure
//!   Enclave; signing and ECDH are performed in hardware.
//!
//! Both backends share the same [`p256::P256r1PublicKey`] and
//! [`p256::P256Signature`] types, and their DH results are compatible —
//! the raw 32-byte x-coordinate of the shared point, as the Noise spec
//! requires (no KDF).

pub mod ed25519;
pub mod p256;
pub mod x25519;
pub mod x448;

// ── Curve trait ─────────────────────────────────────────────────

/// An elliptic curve identity: its name, key sizes, and public-key type.
///
/// Implemented by zero-sized marker types (e.g. [`p256::P256`]). This is
/// the common denominator every curve provides regardless of which
/// operations it supports; the *capabilities* a curve has — Diffie–Hellman
/// ([`DhCurve`]) and/or digital signatures ([`SigningCurve`]) — are layered
/// on top as separate traits, so a DH-only curve need not pretend to sign.
pub trait Curve {
    /// Noise name component (e.g. `"P256"`).
    const NAME: &'static str;

    /// Serialised public key size in bytes.
    const PUBLIC_KEY_SIZE: usize;

    /// Private key / scalar size in bytes.
    const PRIVATE_KEY_SIZE: usize;

    /// Error type for curve operations (e.g. invalid key encoding).
    ///
    /// `'static` so it can be preserved as a boxed `dyn Error` source
    /// (e.g. [`HandshakeError::Crypto`](crate::noise::HandshakeError::Crypto)).
    type Error: std::error::Error + Send + Sync + 'static;

    /// The public key type for this curve.
    type PublicKey: Clone;

    /// Deserialise a public key from its canonical byte representation.
    fn public_key_from_bytes(bytes: &[u8]) -> Result<Self::PublicKey, Self::Error>;
}

/// A [`Curve`] that supports Diffie–Hellman key agreement.
///
/// Separated from [`Curve`] so a DH-only curve (e.g. X25519) is a full
/// participant in the Noise handshake — which is built entirely on this
/// capability — without having to name a signature type it cannot produce.
pub trait DhCurve: Curve {
    /// DH output length in bytes (`DHLEN` in the Noise spec).
    const DHLEN: usize;

    /// The shared secret type produced by ECDH on this curve.
    type SharedSecret;
}

/// A [`Curve`] that supports digital signatures.
///
/// Independent of [`DhCurve`]: a curve may agree, sign, or both. The Noise
/// handshake never signs — this capability exists for callers who want
/// signatures alongside the channel.
pub trait SigningCurve: Curve {
    /// The signature type produced by signing with this curve.
    type Signature;
}

/// Shared secret derived from an ECDH key exchange.
///
/// Holds the raw `DHLEN`-byte output of the curve's DH function, as
/// required by the Noise protocol specification: `N = 32` for the 32-byte
/// curves (P-256's shared-point x-coordinate, X25519) and `N = 56` for
/// X448. The bytes are zeroed on drop.
pub struct SharedSecret<const N: usize>([u8; N]);

impl<const N: usize> SharedSecret<N> {
    /// Wrap the raw `N`-byte ECDH output.
    ///
    /// Takes ownership of the bytes so the wrapper governs their lifetime;
    /// the backing array is zeroed on drop (see the [`Drop`] impl).
    pub fn new(bytes: [u8; N]) -> Self {
        Self(bytes)
    }

    /// Borrow the raw shared-secret bytes.
    ///
    /// The borrow does not copy the secret out; callers must not retain the
    /// bytes beyond the wrapper, which zeroes them on drop.
    pub fn as_bytes(&self) -> &[u8; N] {
        &self.0
    }
}

impl<const N: usize> AsRef<[u8]> for SharedSecret<N> {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes().as_slice()
    }
}

impl<const N: usize> Drop for SharedSecret<N> {
    fn drop(&mut self) {
        crate::zeroize::zeroize_array(&mut self.0);
    }
}

#[cfg(not(test))]
impl<const N: usize> std::fmt::Debug for SharedSecret<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("SharedSecret").finish_non_exhaustive()
    }
}

#[cfg(test)]
impl<const N: usize> std::fmt::Debug for SharedSecret<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("SharedSecret")
            .field(&hex::encode(self.0))
            .finish()
    }
}
