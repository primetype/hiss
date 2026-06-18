//! Ed25519 signing and key exchange.
//!
//! Ed25519 is used for signing message headers — where the signature
//! can double as a `message_id` — and, via the birational equivalence
//! between Edwards and Montgomery forms, for Diffie–Hellman key
//! exchange.
//!
//! This module implements the [`Curve`] and [`CryptoProviderAsync`] traits,
//! following the same pattern as the [`p256`](super::p256) module.
//!
//! # Backends
//!
//! * **Software** ([`SoftwareEd25519PrivateKey`], always available) —
//!   pure-Rust implementation using `cryptoxide`. Suitable for tests,
//!   WASM, and any platform without native Ed25519 support.
//!
//! * **Apple CryptoKit** (future, iOS/macOS) — delegates to
//!   `Curve25519.Signing` via FFI. Key stored in the Data Protection
//!   Keychain with `ThisDeviceOnly` access.
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

use std::fmt;

use cryptoxide::ed25519 as ed;
use packtool::Packed;
use rand_core::{CryptoRng, RngCore};

use super::{CryptoKeys, CryptoProviderAsync, Curve, SharedSecret};

// ── Errors ─────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid public key length: expected 32 bytes, got {0}")]
    InvalidPublicKeyLength(usize),
    #[error("invalid signature length: expected 64 bytes, got {0}")]
    InvalidSignatureLength(usize),
    #[error("RNG failure: {0}")]
    Rng(String),
}

// ── Curve marker ───────────────────────────────────────────────

/// Ed25519 curve marker.
///
/// Zero-sized type implementing [`Curve`] that ties together the
/// concrete [`Ed25519PublicKey`], [`Ed25519Signature`], and
/// [`SharedSecret`] types. Used as a type parameter for
/// [`CryptoProviderAsync`].
pub struct Ed25519;

impl Curve for Ed25519 {
    const NAME: &'static str = "Ed25519";
    const DHLEN: usize = 32;
    const PUBLIC_KEY_SIZE: usize = 32;
    const PRIVATE_KEY_SIZE: usize = 32;

    type Error = Error;
    type PublicKey = Ed25519PublicKey;
    type Signature = Ed25519Signature;
    type SharedSecret = SharedSecret;

    fn public_key_from_bytes(bytes: &[u8]) -> Result<Self::PublicKey, Self::Error> {
        Ed25519PublicKey::from_bytes(bytes)
    }
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
/// This is the software backend — always available. On Apple
/// platforms, the CryptoKit backend is preferred for production
/// use (key lifecycle managed by the OS).
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
    pub fn generate<R: RngCore + CryptoRng>(mut rng: R) -> Result<Self, Error> {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        Ok(Self::from_seed(seed))
    }

    /// Generate a new random key pair using the operating system's CSPRNG.
    ///
    /// Convenience wrapper over [`generate`](Self::generate) for callers
    /// that do not need to supply their own RNG.
    pub fn generate_os() -> Result<Self, Error> {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).map_err(|e| Error::Rng(e.to_string()))?;
        Ok(Self::from_seed(seed))
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

// ── Software CryptoProviderAsync ────────────────────────────────────

/// Pure-software [`CryptoProviderAsync`] for Ed25519.
///
/// Uses `cryptoxide` for all operations. Works on every platform
/// (including WASM). All operations resolve immediately — no
/// hardware interaction, no biometric prompts.
#[derive(Clone, Copy)]
pub struct SoftwareCryptoProvider;

impl CryptoKeys<Ed25519> for SoftwareCryptoProvider {
    type Error = Error;
    type PrivateKey = SoftwareEd25519PrivateKey;

    fn public_key(&self, key: &Self::PrivateKey) -> Result<Ed25519PublicKey, Self::Error> {
        Ok(key.public_key())
    }
}

impl CryptoProviderAsync<Ed25519> for SoftwareCryptoProvider {
    async fn generate_static_key(&self) -> Result<Self::PrivateKey, Self::Error> {
        // TODO: maybe this should error since this key is not
        // going to be static at all at this point.
        SoftwareEd25519PrivateKey::generate_os()
    }

    async fn generate_ephemeral_key(&self) -> Result<Self::PrivateKey, Self::Error> {
        SoftwareEd25519PrivateKey::generate_os()
    }

    async fn sign(
        &self,
        key: &Self::PrivateKey,
        message: &[u8],
    ) -> Result<Ed25519Signature, Self::Error> {
        Ok(key.sign(message))
    }

    async fn dh(
        &self,
        key: &Self::PrivateKey,
        peer: &Ed25519PublicKey,
    ) -> Result<SharedSecret, Self::Error> {
        Ok(key.dh(peer))
    }
}

// ── Apple Ed25519 seed at-rest storage ─────────────────────────

/// Module-level data-directory plumbing for the macOS Ed25519 seed
/// at-rest path.
///
/// The `OnceLock<PathBuf>` is initialised exactly once per process
/// start by the host application's FFI bootstrap BEFORE any
/// `DeviceIdentity::create` / `::load` call. The macOS arm of
/// [`apple`] consults it via [`get_data_dir`] to resolve
/// `{data_dir}/identity/ed25519_seed.bin`.
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub mod data_dir {
    use std::path::{Path, PathBuf};
    use std::sync::OnceLock;

    static DATA_DIR: OnceLock<PathBuf> = OnceLock::new();

    /// Errors that can occur initialising or reading the data-dir.
    #[derive(Debug, thiserror::Error)]
    pub enum DataDirError {
        /// `set_data_dir` has not yet been called for this process.
        #[error(
            "Ed25519 data_dir not initialised — FFI bootstrap MUST call `set_data_dir` before runtime start"
        )]
        NotInit,
        /// A second `set_data_dir` call attempted with a path that
        /// does not match the path already stored.
        #[error(
            "Ed25519 data_dir was previously initialised to {existing:?} but reinit attempted with {attempted:?}"
        )]
        Mismatch {
            existing: PathBuf,
            attempted: PathBuf,
        },
    }

    /// Initialise the process-wide data-directory used by the macOS
    /// Ed25519 seed at-rest path.
    ///
    /// Single-writer invariant. Called exactly once per process start
    /// by the FFI bootstrap. Re-initialising with the same path is
    /// idempotent; re-initialising with a different path returns
    /// [`DataDirError::Mismatch`].
    pub fn set_data_dir(path: PathBuf) -> Result<(), DataDirError> {
        match DATA_DIR.set(path.clone()) {
            Ok(()) => Ok(()),
            Err(_attempted) => match DATA_DIR.get() {
                Some(existing) if existing == &path => Ok(()),
                Some(existing) => Err(DataDirError::Mismatch {
                    existing: existing.clone(),
                    attempted: path,
                }),
                None => unreachable!("OnceLock::set returned Err but get is None"),
            },
        }
    }

    /// Resolve the process-wide data-directory.
    pub fn get_data_dir() -> Result<&'static Path, DataDirError> {
        DATA_DIR
            .get()
            .map(|p| p.as_path())
            .ok_or(DataDirError::NotInit)
    }

    /// Test-only override that bypasses [`set_data_dir`]'s
    /// `OnceLock` for per-test isolation.
    ///
    /// Production code MUST NOT call into [`test_only`] — it is
    /// gated by `#[cfg(test)]` and visible only inside the crate.
    #[cfg(test)]
    pub(crate) mod test_only {
        use std::cell::RefCell;
        use std::path::{Path, PathBuf};

        thread_local! {
            static TEST_OVERRIDE: RefCell<Option<PathBuf>> = const { RefCell::new(None) };
        }

        /// Install a per-thread data-dir override. The macOS arm of
        /// [`apple`] checks this before consulting [`DATA_DIR`].
        pub fn set_data_dir_for_test(path: &Path) {
            TEST_OVERRIDE.with(|cell| *cell.borrow_mut() = Some(path.to_path_buf()));
        }

        /// Return the per-thread override, if any.
        pub fn get_data_dir_test() -> Option<PathBuf> {
            TEST_OVERRIDE.with(|cell| cell.borrow().clone())
        }
    }
}

/// Apple-platform Ed25519 seed at-rest persistence.
///
/// **macOS (`target_os = "macos"`):** the 32-byte seed is sealed via
/// `Noise_N_P256_ChaChaPoly_BLAKE2b`
/// ([`crate::noise::seal::seal_32`]) to the device's Secure Enclave
/// P-256 public key and written as the 129-byte sealed envelope to
/// `{data_dir}/identity/ed25519_seed.bin`, where `data_dir` is
/// supplied via the module-level [`data_dir`] sub-module's
/// `OnceLock<PathBuf>` initialised once at the host application's
/// FFI bootstrap. The
/// keychain is NOT used on macOS: a team-codesigned binary with no
/// `keychain-access-groups` entitlement has zero access groups
/// available, so `SecItemAdd` fails with `errSecMissingEntitlement`
/// regardless of which keychain is targeted and regardless of
/// hardened-runtime state (F-4 root cause, verified `2026/05/09`).
/// The cleartext seed never leaves the runtime — what hits disk is
/// the sealed envelope. The macOS arm of `store_seed` / `load_seed` /
/// `delete_seed` is `async fn` to match the existing
/// `CryptoProviderAsync<P256>` async-trait pattern; the cleartext API
/// surface (`&[u8; 32]` in / `Option<[u8; 32]>` out / unit out) is
/// preserved per
/// `.planning/phases/18.1-secure-enclave-codesigning/18.1-CONTEXT.md`
/// § Amendment 2026/05/10 D-25. A parallel sync helper
/// [`apple::delete_seed_blocking`] is provided for callers that must
/// invoke from a non-async context (the host application's wipe path
/// is a sync fn by design — non-`Send` CF types must not cross
/// `.await` — and so consumes `delete_seed_blocking` to preserve the
/// locked `crypto/mod.rs` + `runtime.rs` signatures).
///
/// **iOS (`target_os = "ios"`):** the seed is stored in the
/// data-protection Keychain as a generic password item with
/// `kSecAttrAccessible = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`
/// and `kSecAttrSynchronizable = false`. iOS does not have the macOS
/// access-group + provisioning-profile coupling — the keychain path
/// is the natural home there. The iOS arm's `store_seed` /
/// `load_seed` / `delete_seed` are `async fn` for API parity with
/// the macOS arm; the inner body is the existing synchronous
/// keychain code, preserved verbatim.
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub mod apple {
    // ── macOS arm: file-based + Noise N seal ─────────────────────

    #[cfg(target_os = "macos")]
    mod macos_impl {
        use std::fs::{File, OpenOptions, create_dir_all, remove_file, rename};
        use std::io::{Read, Write};
        #[cfg(unix)]
        use std::os::unix::fs::OpenOptionsExt;
        use std::path::{Path, PathBuf};

        use crate::curve::p256::SecureEnclaveCryptoProvider;
        use crate::curve::p256::apple::P256r1PrivateKey;
        use crate::noise::seal::{SEALED_SIZE, open_32, seal_32};

        const SEED_REL_PATH_PARENT: &str = "identity";
        const SEED_FILE_NAME: &str = "ed25519_seed.bin";
        const SEED_TMP_SUFFIX: &str = ".tmp";

        fn resolve_data_dir() -> Result<PathBuf, String> {
            #[cfg(test)]
            if let Some(p) = super::super::data_dir::test_only::get_data_dir_test() {
                return Ok(p);
            }
            super::super::data_dir::get_data_dir()
                .map(|p| p.to_path_buf())
                .map_err(|e| e.to_string())
        }

        fn seed_path(data_dir: &Path) -> PathBuf {
            data_dir.join(SEED_REL_PATH_PARENT).join(SEED_FILE_NAME)
        }

        fn ensure_parent(data_dir: &Path) -> Result<PathBuf, String> {
            let parent = data_dir.join(SEED_REL_PATH_PARENT);
            create_dir_all(&parent)
                .map_err(|e| format!("failed to create Ed25519 seed parent dir {parent:?}: {e}"))?;
            Ok(parent)
        }

        pub async fn store_seed(seed: &[u8; 32]) -> Result<(), String> {
            let data_dir = resolve_data_dir()?;
            let parent = ensure_parent(&data_dir)?;
            let final_path = parent.join(SEED_FILE_NAME);

            // Load the SE P-256 public key (recipient of the Noise N
            // seal) BEFORE moving the private key into the seal —
            // `SecureEnclaveCryptoProvider::public_key` is sync, so
            // we extract the public, drop the private key handle, and
            // pass only the public into the seal.
            let se_private = P256r1PrivateKey::load_from_keychain()
                .map_err(|e| format!("failed to load SE P-256 key for seal recipient: {e}"))?
                .ok_or_else(|| "SE P-256 key missing at Ed25519 seed-seal time".to_string())?;
            let se_public = se_private
                .public()
                .map_err(|e| format!("failed to extract SE P-256 public key: {e}"))?;
            drop(se_private);

            // Seal via async Noise N. NO `block_on` /
            // `Handle::try_current` — those would panic inside a
            // Tokio worker. The caller is `async fn`.
            let sealed = seal_32(SecureEnclaveCryptoProvider, &se_public, seed)
                .await
                .map_err(|e| format!("Noise N seal of Ed25519 seed failed: {e}"))?;

            // Atomic write: tempfile in the same directory + POSIX
            // `rename(2)`. On Unix the final-path mode is `0o600`.
            let tmp_path = final_path.with_extension(format!("bin{SEED_TMP_SUFFIX}"));
            {
                let mut opts = OpenOptions::new();
                opts.write(true).create(true).truncate(true);
                #[cfg(unix)]
                {
                    opts.mode(0o600);
                }
                let mut f = opts.open(&tmp_path).map_err(|e| {
                    format!("failed to open Ed25519 seed tempfile {tmp_path:?}: {e}")
                })?;
                f.write_all(&sealed)
                    .map_err(|e| format!("failed to write Ed25519 seed tempfile: {e}"))?;
                f.sync_all()
                    .map_err(|e| format!("failed to fsync Ed25519 seed tempfile: {e}"))?;
            }
            rename(&tmp_path, &final_path).map_err(|e| {
                format!("failed to rename Ed25519 seed tempfile to final path: {e}")
            })?;
            Ok(())
        }

        pub async fn load_seed() -> Result<Option<[u8; 32]>, String> {
            let data_dir = resolve_data_dir()?;
            let final_path = seed_path(&data_dir);
            let mut buf = Vec::with_capacity(SEALED_SIZE);
            match File::open(&final_path) {
                Ok(mut f) => {
                    f.read_to_end(&mut buf)
                        .map_err(|e| format!("failed to read Ed25519 seed file: {e}"))?;
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(e) => {
                    return Err(format!(
                        "failed to open Ed25519 seed file {final_path:?}: {e}"
                    ));
                }
            }
            if buf.len() != SEALED_SIZE {
                return Err(format!(
                    "Ed25519 seed file has wrong size: expected {SEALED_SIZE}, got {}",
                    buf.len()
                ));
            }
            let mut sealed = [0u8; SEALED_SIZE];
            sealed.copy_from_slice(&buf);

            let se_private = P256r1PrivateKey::load_from_keychain()
                .map_err(|e| format!("failed to load SE P-256 key for seal recipient: {e}"))?
                .ok_or_else(|| "SE P-256 key missing at Ed25519 seed-open time".to_string())?;

            let opened = open_32(SecureEnclaveCryptoProvider, se_private, &sealed)
                .await
                .map_err(|e| format!("Noise N open of Ed25519 seed failed: {e}"))?;

            Ok(Some(opened))
        }

        /// Async wrapper around the sync filesystem delete.
        ///
        /// Body is purely sync — no `.await` points. The `async fn`
        /// signature exists for API parity with `store_seed` /
        /// `load_seed`. Callers in a sync context use
        /// [`delete_seed_blocking`] instead.
        pub async fn delete_seed() -> Result<(), String> {
            delete_seed_blocking()
        }

        /// Synchronous Ed25519 seed-file delete.
        ///
        /// Exposed for the host application's wipe path,
        /// which is a sync `fn` by design — non-`Send` CF types must
        /// not cross `.await`. Calling this preserves the locked
        /// `crypto/mod.rs` + `runtime.rs` signatures
        /// (CONTEXT.md Amendment 2026/05/10 D-25).
        pub fn delete_seed_blocking() -> Result<(), String> {
            let data_dir = resolve_data_dir()?;
            let final_path = seed_path(&data_dir);
            match remove_file(&final_path) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(format!(
                    "failed to delete Ed25519 seed file {final_path:?}: {e}"
                )),
            }
        }
    }

    // ── iOS arm: keychain (verbatim from Plan 18.1-05) ───────────

    #[cfg(target_os = "ios")]
    mod ios_impl {
        use security_framework::{
            access_control::{ProtectionMode, SecAccessControl},
            passwords::{
                PasswordOptions, delete_generic_password_options, generic_password,
                set_generic_password_options,
            },
        };

        const ED25519_SEED_SERVICE: &str = "uk.co.primetype.hiss.ed25519";
        const ED25519_SEED_ACCOUNT: &str = "device-identity";

        fn seed_options() -> Result<PasswordOptions, String> {
            let mut options =
                PasswordOptions::new_generic_password(ED25519_SEED_SERVICE, ED25519_SEED_ACCOUNT);
            let access_control = SecAccessControl::create_with_protection(
                Some(ProtectionMode::AccessibleAfterFirstUnlockThisDeviceOnly),
                0,
            )
            .map_err(|e| format!("failed to build Ed25519 seed access control: {e}"))?;
            options.set_access_control(access_control);
            options.set_access_synchronized(Some(false));
            options.use_protected_keychain();
            Ok(options)
        }

        pub async fn store_seed(seed: &[u8; 32]) -> Result<(), String> {
            store_seed_sync(seed)
        }

        pub async fn load_seed() -> Result<Option<[u8; 32]>, String> {
            load_seed_sync()
        }

        pub async fn delete_seed() -> Result<(), String> {
            delete_seed_blocking()
        }

        pub fn delete_seed_blocking() -> Result<(), String> {
            let options = seed_options()?;
            match delete_generic_password_options(options) {
                Ok(()) => Ok(()),
                Err(e) if e.code() == security_framework_sys::base::errSecItemNotFound => Ok(()),
                Err(e) => Err(format!("failed to delete Ed25519 seed Keychain item: {e}")),
            }
        }

        fn store_seed_sync(seed: &[u8; 32]) -> Result<(), String> {
            let _ = delete_generic_password_options(seed_options()?);
            let options = seed_options()?;
            set_generic_password_options(seed, options)
                .map_err(|e| format!("failed to store Ed25519 seed in Keychain: {e}"))
        }

        fn load_seed_sync() -> Result<Option<[u8; 32]>, String> {
            let options = seed_options()?;
            match generic_password(options) {
                Ok(bytes) => {
                    let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
                        format!(
                            "Ed25519 seed has wrong length: expected 32, got {}",
                            bytes.len()
                        )
                    })?;
                    Ok(Some(arr))
                }
                Err(e) if e.code() == security_framework_sys::base::errSecItemNotFound => Ok(None),
                Err(e) => Err(format!("Keychain query for Ed25519 seed failed: {e}")),
            }
        }
    }

    // ── Per-OS re-exports ───────────────────────────────────────

    #[cfg(target_os = "macos")]
    pub use macos_impl::{delete_seed, delete_seed_blocking, load_seed, store_seed};

    #[cfg(target_os = "ios")]
    pub use ios_impl::{delete_seed, delete_seed_blocking, load_seed, store_seed};
}

// ── macOS round-trip test for the file + Noise-N seal path ────

#[cfg(all(test, target_os = "macos"))]
mod apple_macos_tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires codesigned test binary on macOS (SE-backed CryptoProviderAsync for the seal recipient)"]
    async fn store_load_delete_round_trip() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let data_dir = tmp.path();
        data_dir::test_only::set_data_dir_for_test(data_dir);

        let seed_in: [u8; 32] = *SoftwareEd25519PrivateKey::generate(rand::rng())
            .expect("generate Ed25519 seed")
            .seed();

        assert!(apple::load_seed().await.unwrap().is_none());

        apple::store_seed(&seed_in).await.unwrap();
        let loaded = apple::load_seed()
            .await
            .unwrap()
            .expect("seed present after store");
        assert_eq!(
            loaded, seed_in,
            "loaded seed must byte-equal the stored seed"
        );

        let on_disk = std::fs::read(data_dir.join("identity").join("ed25519_seed.bin"))
            .expect("seed file exists");
        assert!(
            on_disk.windows(32).all(|w| w != seed_in),
            "on-disk sealed file must not contain cleartext seed"
        );
        assert_eq!(on_disk.len(), 129, "ed25519_seed.bin is exactly 129 bytes");

        apple::delete_seed().await.unwrap();
        assert!(apple::load_seed().await.unwrap().is_none());

        // idempotent on non-existent
        apple::delete_seed().await.unwrap();
        apple::delete_seed_blocking().unwrap();
    }
}

// ── Tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Direct API tests ─────────────────────────────────────────

    #[test]
    fn generate_and_sign_verify() {
        let sk = SoftwareEd25519PrivateKey::generate(rand::rng()).unwrap();
        let pk = sk.public_key();
        let msg = b"Hello hiss";

        let sig = sk.sign(msg);
        assert!(pk.verify(sig, msg));
    }

    #[test]
    fn deterministic_signatures() {
        let sk = SoftwareEd25519PrivateKey::generate(rand::rng()).unwrap();
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
        let sk = SoftwareEd25519PrivateKey::generate(rand::rng()).unwrap();
        let pk = sk.public_key();

        let sig = sk.sign(b"correct message");
        assert!(!pk.verify(sig, b"wrong message"));
    }

    #[test]
    fn wrong_key_fails_verification() {
        let sk1 = SoftwareEd25519PrivateKey::generate(rand::rng()).unwrap();
        let sk2 = SoftwareEd25519PrivateKey::generate(rand::rng()).unwrap();
        let pk2 = sk2.public_key();

        let sig = sk1.sign(b"signed by sk1");
        assert!(!pk2.verify(sig, b"signed by sk1"));
    }

    #[test]
    fn corrupted_signature_fails() {
        let sk = SoftwareEd25519PrivateKey::generate(rand::rng()).unwrap();
        let pk = sk.public_key();
        let sig = sk.sign(b"test");

        let mut raw = *sig.as_bytes();
        raw[16] ^= 0xFF;
        let corrupted = Ed25519Signature::try_from_bytes(&raw).unwrap();

        assert!(!pk.verify(corrupted, b"test"));
    }

    #[test]
    fn zero_signature_fails() {
        let sk = SoftwareEd25519PrivateKey::generate(rand::rng()).unwrap();
        let pk = sk.public_key();

        let zero_sig = Ed25519Signature::try_from_bytes(&[0u8; 64]).unwrap();
        assert!(!pk.verify(zero_sig, b"anything"));
    }

    #[test]
    fn public_key_round_trip() {
        let sk = SoftwareEd25519PrivateKey::generate(rand::rng()).unwrap();
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
        let sk1 = SoftwareEd25519PrivateKey::generate(rand::rng()).unwrap();
        let pk1 = sk1.public_key();
        let sk2 = SoftwareEd25519PrivateKey::generate(rand::rng()).unwrap();
        let pk2 = sk2.public_key();

        let ss1 = sk1.dh(&pk2);
        let ss2 = sk2.dh(&pk1);
        assert_eq!(ss1, ss2);
    }

    #[test]
    fn dh_different_peers_produce_different_secrets() {
        let sk = SoftwareEd25519PrivateKey::generate(rand::rng()).unwrap();
        let peer1 = SoftwareEd25519PrivateKey::generate(rand::rng())
            .unwrap()
            .public_key();
        let peer2 = SoftwareEd25519PrivateKey::generate(rand::rng())
            .unwrap()
            .public_key();

        let ss1 = sk.dh(&peer1);
        let ss2 = sk.dh(&peer2);
        assert_ne!(ss1, ss2);
    }

    // ── CryptoProviderAsync trait tests ───────────────────────────────

    #[tokio::test]
    async fn provider_sign_and_dh() {
        let provider = SoftwareCryptoProvider;

        let sk1 = provider.generate_static_key().await.unwrap();
        let pk1 = provider.public_key(&sk1).unwrap();

        let sk2 = provider.generate_ephemeral_key().await.unwrap();
        let pk2 = provider.public_key(&sk2).unwrap();

        // Sign and verify
        const MSG: &[u8] = b"hello hiss";
        let sig = provider.sign(&sk1, MSG).await.unwrap();
        assert!(pk1.verify(sig, MSG));
        assert!(!pk2.verify(sig, MSG));

        // DH symmetry
        let ss1 = provider.dh(&sk1, &pk2).await.unwrap();
        let ss2 = provider.dh(&sk2, &pk1).await.unwrap();
        assert_eq!(ss1, ss2);
    }
}
