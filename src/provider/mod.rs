//! Cryptographic providers — the backends that *perform* a curve's
//! operations, and the trait family that defines them.
//!
//! Where [`crate::curve`] holds the curve math and key/handle types, a
//! **provider** describes *where and how* keys live — an environment, not
//! a curve. A provider is parameterised by a
//! [`Curve`](crate::curve::Curve), and one provider may back several
//! curves (it implements the trait family once per curve it supports).
//!
//! The family is three traits:
//!
//! * [`CryptoKeys`] — the shared base: the `PrivateKey`/`Error` types and
//!   the (cheap, synchronous) public-key extraction.
//! * [`CryptoProvider`] — synchronous key operations (the canonical
//!   surface, used by the blocking `std::io` handshake).
//! * [`CryptoProviderAsync`] — asynchronous key operations, for backends
//!   that genuinely suspend (hardware, remote/WASM).
//!
//! [`CryptoProvider`] and [`CryptoProviderAsync`] are **independent**: a
//! backend may implement either, or both.

use std::future::Future;

use rand_core::{CryptoRng, RngCore};

use crate::curve::Curve;
use crate::curve::SharedSecret;
use crate::curve::ed25519::{
    Ed25519, Ed25519PublicKey, Ed25519Signature, SoftwareEd25519PrivateKey,
};
use crate::curve::p256::{P256, P256Signature, P256r1PrivateKey, P256r1PublicKey};

#[cfg(any(target_os = "macos", target_os = "ios"))]
pub mod apple;
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub use apple::{AppleSecureEnclave, SeedError};

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
    ///
    /// Takes `&mut self`: a backend that owns its CSPRNG advances it
    /// here; hardware/deterministic backends ignore the receiver.
    fn generate_static_key(&mut self) -> Result<Self::PrivateKey, Self::Error>;

    /// Generate an ephemeral key pair for a single handshake, synchronously.
    fn generate_ephemeral_key(&mut self) -> Result<Self::PrivateKey, Self::Error>;

    /// ECDSA sign a message, synchronously (hash applied internally).
    fn sign(&self, key: &Self::PrivateKey, message: &[u8]) -> Result<C::Signature, Self::Error>;

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
        &mut self,
    ) -> impl Future<Output = Result<Self::PrivateKey, Self::Error>> + Send;

    /// Generate an ephemeral key pair for a single Noise handshake.
    fn generate_ephemeral_key_async(
        &mut self,
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

// ── EphemeralOnly ────────────────────────────────────────────────

/// Pure-software provider — keys live in memory only and persist
/// **nothing** (zeroized on drop).
///
/// Implements the trait family for both P-256 (`eccoxide`) and Ed25519
/// (`cryptoxide`); works on every platform (including WASM); all
/// operations resolve immediately — no hardware, no prompts.
///
/// "Ephemeral-only" means *no built-in persistence*, not "no static
/// keys": it still generates long-term keys for a handshake — persisting
/// their bytes, if wanted, is the caller's job. For hardware-backed,
/// persistent keys on Apple platforms use
/// [`AppleSecureEnclave`](apple::AppleSecureEnclave).
///
/// Owns a caller-supplied CSPRNG `R` (`CryptoRng + RngCore`): pass
/// `rand::rng()` in production or a seeded RNG for deterministic tests.
/// The crate pulls in no entropy source of its own — `R` is the only
/// one. `Clone`/`Send`/`Sync` are inherited from `R`.
#[derive(Clone)]
pub struct EphemeralOnly<R> {
    rng: R,
}

// P-256 (eccoxide, software) ----------------------------------------

impl<R> CryptoKeys<P256> for EphemeralOnly<R> {
    type Error = crate::curve::p256::Error;
    type PrivateKey = P256r1PrivateKey;

    fn public_key(&self, key: &Self::PrivateKey) -> Result<P256r1PublicKey, Self::Error> {
        Ok(key.public())
    }
}

impl<R: CryptoRng + RngCore> CryptoProvider<P256> for EphemeralOnly<R> {
    fn generate_static_key(&mut self) -> Result<Self::PrivateKey, Self::Error> {
        P256r1PrivateKey::generate(&mut self.rng)
    }

    fn generate_ephemeral_key(&mut self) -> Result<Self::PrivateKey, Self::Error> {
        P256r1PrivateKey::generate(&mut self.rng)
    }

    fn sign(&self, key: &Self::PrivateKey, message: &[u8]) -> Result<P256Signature, Self::Error> {
        key.sign(message)
    }

    fn dh(
        &self,
        key: &Self::PrivateKey,
        peer: &P256r1PublicKey,
    ) -> Result<SharedSecret, Self::Error> {
        key.dh(peer)
    }
}

impl<R: CryptoRng + RngCore + Send + Sync> CryptoProviderAsync<P256> for EphemeralOnly<R> {
    async fn generate_static_key_async(&mut self) -> Result<Self::PrivateKey, Self::Error> {
        P256r1PrivateKey::generate(&mut self.rng)
    }

    async fn generate_ephemeral_key_async(&mut self) -> Result<Self::PrivateKey, Self::Error> {
        P256r1PrivateKey::generate(&mut self.rng)
    }

    async fn sign_async(
        &self,
        key: &Self::PrivateKey,
        message: &[u8],
    ) -> Result<P256Signature, Self::Error> {
        key.sign(message)
    }

    async fn dh_async(
        &self,
        key: &Self::PrivateKey,
        peer: &P256r1PublicKey,
    ) -> Result<SharedSecret, Self::Error> {
        key.dh(peer)
    }
}

// Ed25519 (cryptoxide, software) ------------------------------------

impl<R> CryptoKeys<Ed25519> for EphemeralOnly<R> {
    type Error = crate::curve::ed25519::Error;
    type PrivateKey = SoftwareEd25519PrivateKey;

    fn public_key(&self, key: &Self::PrivateKey) -> Result<Ed25519PublicKey, Self::Error> {
        Ok(key.public_key())
    }
}

impl<R: CryptoRng + RngCore> CryptoProvider<Ed25519> for EphemeralOnly<R> {
    fn generate_static_key(&mut self) -> Result<Self::PrivateKey, Self::Error> {
        Ok(SoftwareEd25519PrivateKey::generate(&mut self.rng))
    }

    fn generate_ephemeral_key(&mut self) -> Result<Self::PrivateKey, Self::Error> {
        Ok(SoftwareEd25519PrivateKey::generate(&mut self.rng))
    }

    fn sign(
        &self,
        key: &Self::PrivateKey,
        message: &[u8],
    ) -> Result<Ed25519Signature, Self::Error> {
        Ok(key.sign(message))
    }

    fn dh(
        &self,
        key: &Self::PrivateKey,
        peer: &Ed25519PublicKey,
    ) -> Result<SharedSecret, Self::Error> {
        Ok(key.dh(peer))
    }
}

impl<R: CryptoRng + RngCore + Send + Sync> CryptoProviderAsync<Ed25519> for EphemeralOnly<R> {
    async fn generate_static_key_async(&mut self) -> Result<Self::PrivateKey, Self::Error> {
        Ok(SoftwareEd25519PrivateKey::generate(&mut self.rng))
    }

    async fn generate_ephemeral_key_async(&mut self) -> Result<Self::PrivateKey, Self::Error> {
        Ok(SoftwareEd25519PrivateKey::generate(&mut self.rng))
    }

    async fn sign_async(
        &self,
        key: &Self::PrivateKey,
        message: &[u8],
    ) -> Result<Ed25519Signature, Self::Error> {
        Ok(key.sign(message))
    }

    async fn dh_async(
        &self,
        key: &Self::PrivateKey,
        peer: &Ed25519PublicKey,
    ) -> Result<SharedSecret, Self::Error> {
        Ok(key.dh(peer))
    }
}

impl<R> EphemeralOnly<R> {
    /// Construct the software provider around a caller-supplied CSPRNG.
    pub fn new(rng: R) -> Self {
        Self { rng }
    }
}

// ── Key → curve association ──────────────────────────────────────

/// A private-key handle that knows which [`Curve`] it belongs to.
///
/// This lets provider methods that take a key (e.g. [`ProviderExt::public`])
/// infer the curve **forward** from the key's type, so a single multi-curve
/// provider can be used without naming the curve at the call site.
pub trait SecretKey {
    /// The curve this key operates on.
    type Curve: Curve;
}

impl SecretKey for P256r1PrivateKey {
    type Curve = P256;
}

impl SecretKey for SoftwareEd25519PrivateKey {
    type Curve = Ed25519;
}

// ── Ergonomic, curve-selecting entry points ──────────────────────

/// Convenience methods over the [`CryptoProvider`] / [`CryptoKeys`] family
/// so a single multi-curve provider value resolves without fully-qualified
/// trait syntax:
///
/// * [`generate`](ProviderExt::generate) /
///   [`generate_ephemeral`](ProviderExt::generate_ephemeral) name the
///   curve with a turbofish — `provider.generate::<P256>()`.
/// * [`public`](ProviderExt::public) infers the curve from the key argument,
///   which carries it via [`SecretKey`] — `provider.public(&sk)`.
///
/// Provided for every provider by a blanket impl; each method is callable
/// exactly when the provider implements the relevant trait for that curve.
pub trait ProviderExt {
    /// Generate a long-term static key for curve `C`.
    fn generate<C: Curve>(
        &mut self,
    ) -> Result<<Self as CryptoKeys<C>>::PrivateKey, <Self as CryptoKeys<C>>::Error>
    where
        Self: CryptoProvider<C>;

    /// Generate an ephemeral key for curve `C`.
    fn generate_ephemeral<C: Curve>(
        &mut self,
    ) -> Result<<Self as CryptoKeys<C>>::PrivateKey, <Self as CryptoKeys<C>>::Error>
    where
        Self: CryptoProvider<C>;

    /// Extract the public key, inferring the curve from `key`.
    fn public<K: SecretKey>(
        &self,
        key: &K,
    ) -> Result<<K::Curve as Curve>::PublicKey, <Self as CryptoKeys<K::Curve>>::Error>
    where
        Self: CryptoKeys<K::Curve, PrivateKey = K>;
}

impl<P> ProviderExt for P {
    fn generate<C: Curve>(
        &mut self,
    ) -> Result<<Self as CryptoKeys<C>>::PrivateKey, <Self as CryptoKeys<C>>::Error>
    where
        Self: CryptoProvider<C>,
    {
        <Self as CryptoProvider<C>>::generate_static_key(self)
    }

    fn generate_ephemeral<C: Curve>(
        &mut self,
    ) -> Result<<Self as CryptoKeys<C>>::PrivateKey, <Self as CryptoKeys<C>>::Error>
    where
        Self: CryptoProvider<C>,
    {
        <Self as CryptoProvider<C>>::generate_ephemeral_key(self)
    }

    fn public<K: SecretKey>(
        &self,
        key: &K,
    ) -> Result<<K::Curve as Curve>::PublicKey, <Self as CryptoKeys<K::Curve>>::Error>
    where
        Self: CryptoKeys<K::Curve, PrivateKey = K>,
    {
        <Self as CryptoKeys<K::Curve>>::public_key(self, key)
    }
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
impl SecretKey for crate::provider::apple::P256r1PrivateKey {
    type Curve = P256;
}
