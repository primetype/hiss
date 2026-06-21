//! Cryptographic providers — the backends that *perform* a curve's
//! operations, and the trait family that defines them.
//!
//! Where [`crate::curve`] holds the curve math and key/handle types, a
//! **provider** describes *where and how* keys live — an environment, not
//! a curve. A provider is parameterised by a
//! [`Curve`], and one provider may back several
//! curves (it implements the trait family once per curve it supports).
//!
//! The family mirrors the curve capability split
//! ([`DhCurve`] /
//! [`SigningCurve`]):
//!
//! * [`CryptoKeyProvider`] — the shared base: the `PrivateKey`/`Error` types,
//!   the (cheap, synchronous) public-key extraction, and synchronous key
//!   generation (so a sign-only curve can still mint keys).
//! * [`CryptoKeyProviderAsync`] — the asynchronous mirror of key generation.
//! * [`DhProvider`] / [`DhProviderAsync`] — synchronous / asynchronous
//!   Diffie–Hellman over a [`DhCurve`] (the sync surface backs the blocking
//!   `std::io` handshake).
//! * [`SigningProvider`] / [`SigningProviderAsync`] — digital signatures over
//!   a [`SigningCurve`]. The Noise handshake never
//!   signs, so these are independent of the DH surface.
//!
//! All operation traits are **independent**: a backend implements exactly the
//! ones its curve and environment support — a DH-only curve has no signing
//! impl at all.

use std::future::Future;

use rand_core::{CryptoRng, RngCore};

use crate::curve::SharedSecret;
use crate::curve::ed25519::{
    Ed25519, Ed25519PublicKey, Ed25519Signature, SoftwareEd25519PrivateKey,
};
use crate::curve::p256::{P256, P256Signature, P256r1PrivateKey, P256r1PublicKey};
use crate::curve::x448::{SoftwareX448PrivateKey, X448, X448PublicKey};
use crate::curve::x25519::{SoftwareX25519PrivateKey, X25519, X25519PublicKey};
use crate::curve::{Curve, DhCurve, SigningCurve};

#[cfg(any(target_os = "macos", target_os = "ios"))]
#[cfg_attr(docsrs, doc(cfg(any(target_os = "macos", target_os = "ios"))))]
pub mod apple;
#[cfg(any(target_os = "macos", target_os = "ios"))]
#[cfg_attr(docsrs, doc(cfg(any(target_os = "macos", target_os = "ios"))))]
pub use apple::{AppleSecureEnclave, SeedError};

// ── Provider trait family ────────────────────────────────────────

/// The shared identity and key lifecycle of a crypto backend: its
/// key/handle types, the (cheap, synchronous) public-key extraction, and
/// synchronous key generation.
///
/// Every operation surface — [`DhProvider`] (DH), [`SigningProvider`]
/// (signing), and their async mirrors — builds on this, so a backend
/// declares its `PrivateKey`/`Error` once and may implement any subset of
/// operations independently. Key generation lives here, **not** on the DH
/// surface, so a sign-only curve can still mint keys. Generic code that only
/// needs the key types or generation (e.g. the handshake state holder) is
/// bounded on this base trait alone.
pub trait CryptoKeyProvider<C: Curve> {
    /// Error type for this backend's operations.
    ///
    /// `'static` so it can be preserved as a boxed `dyn Error` source
    /// (e.g. [`HandshakeError::Crypto`](crate::noise::HandshakeError::Crypto)).
    type Error: std::error::Error + Send + Sync + 'static;

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

    /// Generate a long-term static key pair, synchronously.
    ///
    /// Takes `&mut self`: a backend that owns its CSPRNG advances it
    /// here; hardware/deterministic backends ignore the receiver.
    fn generate_static_key(&mut self) -> Result<Self::PrivateKey, Self::Error>;

    /// Generate an ephemeral key pair for a single handshake, synchronously.
    ///
    /// Mints a fresh per-handshake keypair that is used once and then
    /// discarded with the handshake — it is never persisted. This is
    /// distinct from a long-term static identity key
    /// ([`generate_static_key`](Self::generate_static_key)): a backend may
    /// keep static keys in hardware or on disk, but the ephemeral key is
    /// expected to be cheap and transient. Takes `&mut self` for the same
    /// reason: a backend that owns its CSPRNG advances it here.
    fn generate_ephemeral_key(&mut self) -> Result<Self::PrivateKey, Self::Error>;
}

/// Asynchronous key generation — the async mirror of
/// [`CryptoKeyProvider`]'s generation methods.
///
/// For backends whose key generation genuinely suspends (the Apple Secure
/// Enclave offloads its blocking call to a worker thread; remote/WASM
/// backends await I/O). Independent of the DH and signing surfaces, so a
/// sign-only curve can still be generated asynchronously. Both methods
/// return `Send` futures and are suffixed `_async` to avoid clashing with
/// the synchronous methods when a backend implements both.
pub trait CryptoKeyProviderAsync<C: Curve>: CryptoKeyProvider<C> {
    /// Generate a long-term static key pair.
    fn generate_static_key_async(
        &mut self,
    ) -> impl Future<Output = Result<Self::PrivateKey, Self::Error>> + Send;

    /// Generate an ephemeral key pair for a single Noise handshake.
    fn generate_ephemeral_key_async(
        &mut self,
    ) -> impl Future<Output = Result<Self::PrivateKey, Self::Error>> + Send;
}

/// Synchronous Diffie–Hellman over a [`DhCurve`].
///
/// The canonical DH surface, for backends whose operations run to
/// completion on the calling thread — pure software (`eccoxide` /
/// `cryptoxide`) and the Apple Secure Enclave (whose Security-framework
/// calls are synchronous, blocking C functions). It is what the blocking
/// `std::io` handshake (`hiss::noise::SyncHandshake`) is generic over.
///
/// Key generation lives on the [`CryptoKeyProvider`] base, not here, so DH
/// and generation are independent capabilities. Signing is a separate
/// capability ([`SigningProvider`]).
///
/// **Independent of [`DhProviderAsync`]** — a backend may implement this,
/// that, or both. As the canonical surface this takes the plain method
/// name (`dh`); the async trait suffixes its method `_async`, so a backend
/// that implements both has no name clash.
pub trait DhProvider<C: DhCurve>: CryptoKeyProvider<C> {
    /// ECDH key exchange, synchronously, returning the shared secret.
    fn dh(
        &self,
        key: &Self::PrivateKey,
        peer: &C::PublicKey,
    ) -> Result<C::SharedSecret, Self::Error>;
}

/// Asynchronous Diffie–Hellman over a [`DhCurve`].
///
/// For backends that genuinely suspend — hardware that may prompt for
/// user presence, or remote/WASM backends (KMS, WebCrypto). The Apple
/// Secure Enclave implements this by offloading its blocking call to a
/// worker thread (`spawn_blocking`) so the executor never blocks; pure
/// software resolves immediately.
///
/// **Independent of [`DhProvider`]** — a genuinely-async backend need not
/// (and may be unable to) provide synchronous operations. The future is
/// `Send` so callers can use it in multi-threaded runtimes (`tokio::spawn`).
/// Suffixed `_async` to avoid clashing with [`DhProvider`] when a backend
/// implements both.
pub trait DhProviderAsync<C: DhCurve>: CryptoKeyProviderAsync<C> {
    /// ECDH key exchange, returning the derived shared secret.
    fn dh_async(
        &self,
        key: &Self::PrivateKey,
        peer: &C::PublicKey,
    ) -> impl Future<Output = Result<C::SharedSecret, Self::Error>> + Send;
}

/// Synchronous digital signatures over a [`SigningCurve`].
///
/// A capability independent of the DH surface — the Noise handshake never
/// signs, so a DH-only curve omits this entirely. Implemented by backends
/// that can sign with the curves they support (software P-256 / Ed25519,
/// the Apple Secure Enclave). Key generation lives on
/// [`CryptoKeyProvider`]; this trait only signs with an existing key.
pub trait SigningProvider<C: SigningCurve>: CryptoKeyProvider<C> {
    /// Sign a message, synchronously (hash applied internally).
    fn sign(&self, key: &Self::PrivateKey, message: &[u8]) -> Result<C::Signature, Self::Error>;
}

/// Asynchronous digital signatures over a [`SigningCurve`].
///
/// The async mirror of [`SigningProvider`], for backends that genuinely
/// suspend (the Apple Secure Enclave offloads its blocking signing call).
/// `_async`-suffixed so a backend implementing both surfaces has no clash.
pub trait SigningProviderAsync<C: SigningCurve>: CryptoKeyProvider<C> {
    /// Sign a message (hash applied internally).
    fn sign_async(
        &self,
        key: &Self::PrivateKey,
        message: &[u8],
    ) -> impl Future<Output = Result<C::Signature, Self::Error>> + Send;
}

// ── EphemeralOnly ────────────────────────────────────────────────

/// Pure-software provider — keys live in memory only and persist
/// **nothing** (zeroized on drop).
///
/// Implements the trait family for P-256 (`eccoxide`), X25519, and
/// Ed25519 (`cryptoxide`); works on every platform (including WASM); all
/// operations resolve immediately — no hardware, no prompts.
///
/// "Ephemeral-only" means *no built-in persistence*, not "no static
/// keys": it still generates long-term keys for a handshake — persisting
/// their bytes, if wanted, is the caller's job. For hardware-backed,
/// persistent keys on Apple platforms use
/// [`AppleSecureEnclave`].
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

impl<R: CryptoRng + RngCore> CryptoKeyProvider<P256> for EphemeralOnly<R> {
    type Error = crate::curve::p256::Error;
    type PrivateKey = P256r1PrivateKey;

    fn public_key(&self, key: &Self::PrivateKey) -> Result<P256r1PublicKey, Self::Error> {
        Ok(key.public())
    }

    fn generate_static_key(&mut self) -> Result<Self::PrivateKey, Self::Error> {
        P256r1PrivateKey::generate(&mut self.rng)
    }

    fn generate_ephemeral_key(&mut self) -> Result<Self::PrivateKey, Self::Error> {
        P256r1PrivateKey::generate(&mut self.rng)
    }
}

impl<R: CryptoRng + RngCore + Send + Sync> CryptoKeyProviderAsync<P256> for EphemeralOnly<R> {
    async fn generate_static_key_async(&mut self) -> Result<Self::PrivateKey, Self::Error> {
        P256r1PrivateKey::generate(&mut self.rng)
    }

    async fn generate_ephemeral_key_async(&mut self) -> Result<Self::PrivateKey, Self::Error> {
        P256r1PrivateKey::generate(&mut self.rng)
    }
}

impl<R: CryptoRng + RngCore> DhProvider<P256> for EphemeralOnly<R> {
    fn dh(
        &self,
        key: &Self::PrivateKey,
        peer: &P256r1PublicKey,
    ) -> Result<SharedSecret<32>, Self::Error> {
        key.dh(peer)
    }
}

impl<R: CryptoRng + RngCore + Send + Sync> DhProviderAsync<P256> for EphemeralOnly<R> {
    async fn dh_async(
        &self,
        key: &Self::PrivateKey,
        peer: &P256r1PublicKey,
    ) -> Result<SharedSecret<32>, Self::Error> {
        key.dh(peer)
    }
}

impl<R: CryptoRng + RngCore> SigningProvider<P256> for EphemeralOnly<R> {
    fn sign(&self, key: &Self::PrivateKey, message: &[u8]) -> Result<P256Signature, Self::Error> {
        key.sign(message)
    }
}

impl<R: CryptoRng + RngCore + Send + Sync> SigningProviderAsync<P256> for EphemeralOnly<R> {
    async fn sign_async(
        &self,
        key: &Self::PrivateKey,
        message: &[u8],
    ) -> Result<P256Signature, Self::Error> {
        key.sign(message)
    }
}

// Ed25519 (cryptoxide, software) ------------------------------------

impl<R: CryptoRng + RngCore> CryptoKeyProvider<Ed25519> for EphemeralOnly<R> {
    type Error = crate::curve::ed25519::Error;
    type PrivateKey = SoftwareEd25519PrivateKey;

    fn public_key(&self, key: &Self::PrivateKey) -> Result<Ed25519PublicKey, Self::Error> {
        Ok(key.public_key())
    }

    fn generate_static_key(&mut self) -> Result<Self::PrivateKey, Self::Error> {
        Ok(SoftwareEd25519PrivateKey::generate(&mut self.rng))
    }

    fn generate_ephemeral_key(&mut self) -> Result<Self::PrivateKey, Self::Error> {
        Ok(SoftwareEd25519PrivateKey::generate(&mut self.rng))
    }
}

impl<R: CryptoRng + RngCore + Send + Sync> CryptoKeyProviderAsync<Ed25519> for EphemeralOnly<R> {
    async fn generate_static_key_async(&mut self) -> Result<Self::PrivateKey, Self::Error> {
        Ok(SoftwareEd25519PrivateKey::generate(&mut self.rng))
    }

    async fn generate_ephemeral_key_async(&mut self) -> Result<Self::PrivateKey, Self::Error> {
        Ok(SoftwareEd25519PrivateKey::generate(&mut self.rng))
    }
}

impl<R: CryptoRng + RngCore> DhProvider<Ed25519> for EphemeralOnly<R> {
    fn dh(
        &self,
        key: &Self::PrivateKey,
        peer: &Ed25519PublicKey,
    ) -> Result<SharedSecret<32>, Self::Error> {
        Ok(key.dh(peer))
    }
}

impl<R: CryptoRng + RngCore + Send + Sync> DhProviderAsync<Ed25519> for EphemeralOnly<R> {
    async fn dh_async(
        &self,
        key: &Self::PrivateKey,
        peer: &Ed25519PublicKey,
    ) -> Result<SharedSecret<32>, Self::Error> {
        Ok(key.dh(peer))
    }
}

impl<R: CryptoRng + RngCore> SigningProvider<Ed25519> for EphemeralOnly<R> {
    fn sign(
        &self,
        key: &Self::PrivateKey,
        message: &[u8],
    ) -> Result<Ed25519Signature, Self::Error> {
        Ok(key.sign(message))
    }
}

impl<R: CryptoRng + RngCore + Send + Sync> SigningProviderAsync<Ed25519> for EphemeralOnly<R> {
    async fn sign_async(
        &self,
        key: &Self::PrivateKey,
        message: &[u8],
    ) -> Result<Ed25519Signature, Self::Error> {
        Ok(key.sign(message))
    }
}

// X25519 (eccoxide, software) — DH-only, no signing ----------------

impl<R: CryptoRng + RngCore> CryptoKeyProvider<X25519> for EphemeralOnly<R> {
    type Error = crate::curve::x25519::Error;
    type PrivateKey = SoftwareX25519PrivateKey;

    fn public_key(&self, key: &Self::PrivateKey) -> Result<X25519PublicKey, Self::Error> {
        Ok(key.public_key())
    }

    fn generate_static_key(&mut self) -> Result<Self::PrivateKey, Self::Error> {
        Ok(SoftwareX25519PrivateKey::generate(&mut self.rng))
    }

    fn generate_ephemeral_key(&mut self) -> Result<Self::PrivateKey, Self::Error> {
        Ok(SoftwareX25519PrivateKey::generate(&mut self.rng))
    }
}

impl<R: CryptoRng + RngCore + Send + Sync> CryptoKeyProviderAsync<X25519> for EphemeralOnly<R> {
    async fn generate_static_key_async(&mut self) -> Result<Self::PrivateKey, Self::Error> {
        Ok(SoftwareX25519PrivateKey::generate(&mut self.rng))
    }

    async fn generate_ephemeral_key_async(&mut self) -> Result<Self::PrivateKey, Self::Error> {
        Ok(SoftwareX25519PrivateKey::generate(&mut self.rng))
    }
}

impl<R: CryptoRng + RngCore> DhProvider<X25519> for EphemeralOnly<R> {
    fn dh(
        &self,
        key: &Self::PrivateKey,
        peer: &X25519PublicKey,
    ) -> Result<SharedSecret<32>, Self::Error> {
        Ok(key.dh(peer))
    }
}

impl<R: CryptoRng + RngCore + Send + Sync> DhProviderAsync<X25519> for EphemeralOnly<R> {
    async fn dh_async(
        &self,
        key: &Self::PrivateKey,
        peer: &X25519PublicKey,
    ) -> Result<SharedSecret<32>, Self::Error> {
        Ok(key.dh(peer))
    }
}

// X448 (eccoxide, software) — DH-only, no signing -------------------

impl<R: CryptoRng + RngCore> CryptoKeyProvider<X448> for EphemeralOnly<R> {
    type Error = crate::curve::x448::Error;
    type PrivateKey = SoftwareX448PrivateKey;

    fn public_key(&self, key: &Self::PrivateKey) -> Result<X448PublicKey, Self::Error> {
        Ok(key.public_key())
    }

    fn generate_static_key(&mut self) -> Result<Self::PrivateKey, Self::Error> {
        Ok(SoftwareX448PrivateKey::generate(&mut self.rng))
    }

    fn generate_ephemeral_key(&mut self) -> Result<Self::PrivateKey, Self::Error> {
        Ok(SoftwareX448PrivateKey::generate(&mut self.rng))
    }
}

impl<R: CryptoRng + RngCore + Send + Sync> CryptoKeyProviderAsync<X448> for EphemeralOnly<R> {
    async fn generate_static_key_async(&mut self) -> Result<Self::PrivateKey, Self::Error> {
        Ok(SoftwareX448PrivateKey::generate(&mut self.rng))
    }

    async fn generate_ephemeral_key_async(&mut self) -> Result<Self::PrivateKey, Self::Error> {
        Ok(SoftwareX448PrivateKey::generate(&mut self.rng))
    }
}

impl<R: CryptoRng + RngCore> DhProvider<X448> for EphemeralOnly<R> {
    fn dh(
        &self,
        key: &Self::PrivateKey,
        peer: &X448PublicKey,
    ) -> Result<SharedSecret<56>, Self::Error> {
        Ok(key.dh(peer))
    }
}

impl<R: CryptoRng + RngCore + Send + Sync> DhProviderAsync<X448> for EphemeralOnly<R> {
    async fn dh_async(
        &self,
        key: &Self::PrivateKey,
        peer: &X448PublicKey,
    ) -> Result<SharedSecret<56>, Self::Error> {
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

impl SecretKey for SoftwareX25519PrivateKey {
    type Curve = X25519;
}

impl SecretKey for SoftwareX448PrivateKey {
    type Curve = X448;
}

// ── Ergonomic, curve-selecting entry points ──────────────────────

/// Convenience methods over the [`CryptoKeyProvider`] family
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
    ) -> Result<<Self as CryptoKeyProvider<C>>::PrivateKey, <Self as CryptoKeyProvider<C>>::Error>
    where
        Self: CryptoKeyProvider<C>;

    /// Generate an ephemeral key for curve `C`.
    fn generate_ephemeral<C: Curve>(
        &mut self,
    ) -> Result<<Self as CryptoKeyProvider<C>>::PrivateKey, <Self as CryptoKeyProvider<C>>::Error>
    where
        Self: CryptoKeyProvider<C>;

    /// Extract the public key, inferring the curve from `key`.
    fn public<K: SecretKey>(
        &self,
        key: &K,
    ) -> Result<<K::Curve as Curve>::PublicKey, <Self as CryptoKeyProvider<K::Curve>>::Error>
    where
        Self: CryptoKeyProvider<K::Curve, PrivateKey = K>;
}

impl<P> ProviderExt for P {
    fn generate<C: Curve>(
        &mut self,
    ) -> Result<<Self as CryptoKeyProvider<C>>::PrivateKey, <Self as CryptoKeyProvider<C>>::Error>
    where
        Self: CryptoKeyProvider<C>,
    {
        <Self as CryptoKeyProvider<C>>::generate_static_key(self)
    }

    fn generate_ephemeral<C: Curve>(
        &mut self,
    ) -> Result<<Self as CryptoKeyProvider<C>>::PrivateKey, <Self as CryptoKeyProvider<C>>::Error>
    where
        Self: CryptoKeyProvider<C>,
    {
        <Self as CryptoKeyProvider<C>>::generate_ephemeral_key(self)
    }

    fn public<K: SecretKey>(
        &self,
        key: &K,
    ) -> Result<<K::Curve as Curve>::PublicKey, <Self as CryptoKeyProvider<K::Curve>>::Error>
    where
        Self: CryptoKeyProvider<K::Curve, PrivateKey = K>,
    {
        <Self as CryptoKeyProvider<K::Curve>>::public_key(self, key)
    }
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
impl SecretKey for crate::provider::apple::P256r1PrivateKey {
    type Curve = P256;
}
