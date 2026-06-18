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

use std::future::Future;

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

// ── Provider trait family ────────────────────────────────────────

/// The shared identity of a crypto backend: its key/handle types and
/// the (always cheap, always synchronous) public-key extraction.
///
/// Both [`CryptoProvider`] (synchronous) and [`CryptoProviderAsync`]
/// build on this, so a backend declares its `PrivateKey`/`Error` once
/// and may implement either operation surface — or both — independently.
/// Generic code that only needs the key types (e.g. the handshake state
/// holder) is bounded on this base trait alone.
pub trait CryptoKeys<C: Curve> {
    /// Error type for this backend's operations.
    type Error: std::error::Error + Send + Sync;

    /// Opaque private key handle.
    ///
    /// On macOS this wraps a `SecKey`; in software it holds raw
    /// scalar bytes. Callers never inspect the key material
    /// directly — all operations go through these traits.
    ///
    /// Intentionally **not** `Clone`: secret keys should not be silently
    /// duplicated. A backend whose handle is cheap to copy (e.g. an Apple
    /// `SecKey` — a refcounted retain, not a copy of key material) may
    /// still derive `Clone` on its own concrete type; the software
    /// backends, which hold raw secret bytes, do not.
    type PrivateKey: Send;

    /// Extract the public key from a private key.
    fn public_key(&self, key: &Self::PrivateKey) -> Result<C::PublicKey, Self::Error>;
}

/// Synchronous elliptic-curve key operations.
///
/// The canonical provider surface, for backends whose operations run to
/// completion on the calling thread — pure software (`eccoxide`) and the
/// Apple Secure Enclave (whose Security-framework calls are synchronous,
/// blocking C functions). It is what the blocking `std::io` handshake
/// (`hiss::noise::SyncHandshake`) is generic over.
///
/// **Independent of [`CryptoProviderAsync`]** — a backend may implement
/// this, that, or both. As the canonical, always-available surface these
/// take the plain method names (`generate_static_key`, `sign`, `dh`, …);
/// the async trait suffixes its methods `_async`, so a backend that
/// implements both has no name clash.
pub trait CryptoProvider<C: Curve>: CryptoKeys<C> {
    /// Generate a long-term static key pair, synchronously.
    fn generate_static_key(&self) -> Result<Self::PrivateKey, Self::Error>;

    /// Generate an ephemeral key pair for a single handshake, synchronously.
    fn generate_ephemeral_key(&self) -> Result<Self::PrivateKey, Self::Error>;

    /// ECDSA sign a message, synchronously (hash applied internally).
    fn sign(
        &self,
        key: &Self::PrivateKey,
        message: &[u8],
    ) -> Result<C::Signature, Self::Error>;

    /// ECDH key exchange, synchronously, returning the shared secret.
    fn dh(
        &self,
        key: &Self::PrivateKey,
        peer: &C::PublicKey,
    ) -> Result<C::SharedSecret, Self::Error>;
}

/// Asynchronous elliptic-curve key operations.
///
/// For backends that genuinely suspend — hardware that may prompt for
/// user presence, or remote/WASM backends (KMS, WebCrypto). The Apple
/// Secure Enclave implements this by offloading its blocking calls to a
/// worker thread (`spawn_blocking`) so the executor never blocks; pure
/// software resolves immediately.
///
/// **Independent of [`CryptoProvider`]** — a genuinely-async backend need
/// not (and may be unable to) provide synchronous operations. All methods
/// return `Send` futures so callers can use them in multi-threaded
/// runtimes (`tokio::spawn`). They are suffixed `_async` to mark this as
/// the non-default surface and to avoid clashing with the synchronous
/// [`CryptoProvider`] when a backend implements both.
pub trait CryptoProviderAsync<C: Curve>: CryptoKeys<C> {
    /// Generate a long-term static key pair.
    fn generate_static_key_async(
        &self,
    ) -> impl Future<Output = Result<Self::PrivateKey, Self::Error>> + Send;

    /// Generate an ephemeral key pair for a single Noise handshake.
    fn generate_ephemeral_key_async(
        &self,
    ) -> impl Future<Output = Result<Self::PrivateKey, Self::Error>> + Send;

    /// ECDSA sign a message (hash is applied internally).
    fn sign_async(
        &self,
        key: &Self::PrivateKey,
        message: &[u8],
    ) -> impl Future<Output = Result<C::Signature, Self::Error>> + Send;

    /// ECDH key exchange, returning the derived shared secret.
    fn dh_async(
        &self,
        key: &Self::PrivateKey,
        peer: &C::PublicKey,
    ) -> impl Future<Output = Result<C::SharedSecret, Self::Error>> + Send;
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
