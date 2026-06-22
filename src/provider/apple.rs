//! macOS Secure Enclave P-256 private key implementation.
//!
//! Delegates key generation, ECDSA signing, and ECDH to Apple's
//! Security framework. Private keys live in the Secure Enclave (or
//! in a software-backed `SecKey` for ephemeral use) and never leave
//! hardware. ECDH uses `kSecKeyAlgorithmECDHKeyExchangeStandard`
//! which returns the raw x-coordinate — Noise-spec compliant.
//!
//! Three key generation modes are available:
//!
//! * [`P256r1PrivateKey::generate_ephemeral`] — software-backed
//!   `SecKey`, not persisted in the Keychain. Suitable for Noise
//!   handshake ephemeral keys.
//!
//! * [`P256r1PrivateKey::generate_secure_enclave_ephemeral`] —
//!   hardware-backed, no per-use biometric prompt, not persisted.
//!
//! * [`P256r1PrivateKey::generate_secure_enclave`] — hardware-backed,
//!   persisted to the Data Protection Keychain (Phase 18.1 Option B,
//!   `2026/05/12`, D-20-restored). Authorisation for the team-prefixed
//!   `keychain-access-groups` entitlement comes from the embedded macOS
//!   Development provisioning profile placed alongside the binary by
//!   the host application's build script (D-27.c). The Secure
//!   Enclave binding is preserved via `Token::SecureEnclave` and
//!   `kSecAttrTokenIDSecureEnclave` — D-23 invariant. iOS continues to
//!   use its single (data-protection) keychain as before.

use crate::curve::SharedSecret;
use crate::curve::ed25519::{
    Ed25519, Ed25519PublicKey, Ed25519Signature, SoftwareEd25519PrivateKey,
};
use crate::curve::p256::{Error, P256, P256Signature, P256r1PublicKey};
use crate::noise::seal::{SEALED_SIZE, open_32, seal_32};
use crate::provider::{
    CryptoKeyProvider, CryptoKeyProviderAsync, DhProvider, DhProviderAsync, SigningProvider,
    SigningProviderAsync,
};
use core_foundation::{base::TCFType as _, data::CFData, dictionary::CFDictionary};
use security_framework::{
    access_control::{ProtectionMode, SecAccessControl},
    item::Location,
    key::{Algorithm, GenerateKeyOptions, KeyType, SecKey, Token},
    passwords::{
        PasswordOptions, delete_generic_password_options, generic_password,
        set_generic_password_options,
    },
    passwords_options::AccessControlOptions,
};

/// Keychain label for ephemeral P-256 keys.
///
/// Ephemeral keys are never persisted or looked up by label, so this is
/// a fixed, namespace-independent descriptor.
const EPHEMERAL_LABEL: &str = "hiss.ephemeral.p256";

/// Keychain account for the sealed Ed25519 seed item. A neutral
/// descriptor — the per-caller namespace lives in the service name.
const ED25519_SEED_ACCOUNT: &str = "device-identity";

/// Handle to a P-256 private key managed by Apple's Security framework.
///
/// The handle wraps a `SecKey`; the private scalar itself is never held
/// in process memory. For Secure-Enclave-backed keys the scalar is
/// non-extractable and every operation ([`dh`](Self::dh),
/// [`sign`](Self::sign)) runs inside the enclave; for the software-backed
/// ephemeral variant ([`generate_ephemeral`](Self::generate_ephemeral))
/// the scalar lives in a software `SecKey` and never crosses the FFI
/// boundary either. `deletable` records whether the key was persisted to
/// the Keychain and so is removable by [`delete`](Self::delete);
/// non-persisted (ephemeral) keys are not.
//
// `Clone` here is a CoreFoundation retain of the `SecKey` handle — no
// secret material is copied (the key stays in the keychain / Secure
// Enclave). It is required so the async impl can move the handle into a
// `spawn_blocking` closure; the trait deliberately does not mandate it.
#[derive(Clone)]
pub struct P256r1PrivateKey {
    key: SecKey,
    deletable: bool,
}

impl P256r1PublicKey {
    fn as_sec_key(&self, attributes: &CFDictionary) -> Result<SecKey, Error> {
        let key_data = CFData::from_buffer(self.to_bytes());
        // SAFETY: `key_data` and `attributes` are live `CFData`/`CFDictionary`
        // values owned by this scope, so the `CFTypeRef`s passed by
        // `as_concrete_TypeRef` stay valid for the whole call. `error` is a
        // null-initialised out-param whose address is a valid `*mut CFErrorRef`.
        // `SecKeyCreateWithData` follows Core Foundation's Create rule: the
        // returned `SecKeyRef` is owned by us (not borrowed/Get), so it is taken
        // with `wrap_under_create_rule` whose `Drop` releases it exactly once. On
        // a null return the written-back `CFError` is likewise Create-owned and
        // wrapped under the create rule, balancing its retain count.
        unsafe {
            let mut error = std::ptr::null_mut();

            let sec_key = security_framework_sys::key::SecKeyCreateWithData(
                key_data.as_concrete_TypeRef(),
                attributes.as_concrete_TypeRef(),
                &mut error,
            );

            if sec_key.is_null() {
                let cf_error = core_foundation::error::CFError::wrap_under_create_rule(error);
                Err(Error::Platform(format!("{cf_error:?}")))
            } else {
                Ok(SecKey::wrap_under_create_rule(sec_key))
            }
        }
    }
}

impl P256r1PrivateKey {
    fn new(key: SecKey, deletable: bool) -> Self {
        Self { key, deletable }
    }

    /// Generate a software-backed ephemeral P-256 key.
    ///
    /// The key is created with `Token::Software` and is never persisted
    /// to the Keychain — it lives only for the lifetime of this handle and
    /// is dropped with it. There is no Secure Enclave involvement and no
    /// authentication prompt. Suitable for Noise handshake ephemeral keys,
    /// which are used once and discarded; for a hardware-backed key see
    /// [`generate_secure_enclave_ephemeral`](Self::generate_secure_enclave_ephemeral).
    pub fn generate_ephemeral() -> Result<Self, Error> {
        let mut attributes = GenerateKeyOptions::default();
        attributes
            .set_key_type(KeyType::ec())
            .set_size_in_bits(256)
            .set_token(Token::Software)
            .set_label(EPHEMERAL_LABEL);

        let key = SecKey::new(&attributes)
            .map_err(|e| Error::Platform(format!("failed to generate SecKey: {e:?}")))?;
        Ok(Self::new(key, false))
    }

    /// Generate an ephemeral Secure Enclave key.
    ///
    /// No per-use biometric prompt — same access control as persistent keys.
    pub fn generate_secure_enclave_ephemeral() -> Result<Self, Error> {
        let mut attributes = GenerateKeyOptions::default();
        attributes
            .set_key_type(KeyType::ec())
            .set_size_in_bits(256)
            .set_token(Token::SecureEnclave)
            .set_label(EPHEMERAL_LABEL)
            .set_access_control(
                SecAccessControl::create_with_protection(
                    Some(ProtectionMode::AccessibleAfterFirstUnlockThisDeviceOnly),
                    AccessControlOptions::PRIVATE_KEY_USAGE.bits(),
                )
                .map_err(|e| Error::Platform(format!("access control: {e}")))?,
            );

        let key = SecKey::new(&attributes)
            .map_err(|e| Error::Platform(format!("failed to generate SecKey: {e:?}")))?;
        Ok(Self::new(key, false))
    }

    /// Generate a persistent Secure Enclave key stored in the Keychain.
    ///
    /// Access control: `PRIVATE_KEY_USAGE` only — no per-use biometric
    /// prompt. The app-level lock screen provides the authentication gate.
    /// `AccessibleAfterFirstUnlockThisDeviceOnly` ensures the key is
    /// available once the device has been unlocked after boot.
    pub fn generate_secure_enclave(label: &str) -> Result<Self, Error> {
        let mut attributes = GenerateKeyOptions::default();
        attributes
            .set_key_type(KeyType::ec())
            .set_size_in_bits(256)
            .set_label(label)
            .set_token(Token::SecureEnclave)
            // Phase 18.1 (`2026/05/12`): the data-protection Keychain
            // selector is RESTORED (D-20-restored) per Apple TN3137
            // ("Keys stored in the Secure Enclave _must_ use this
            // keychain"). Authorisation for the team-prefixed
            // `keychain-access-groups` entitlement is provided by the
            // embedded macOS Development provisioning profile bundled
            // alongside the binary by the host application's build
            // script (D-27.c). The prior 2026/05/08 drop-the-selector
            // experiment and the 2026/05/10 file-based-seed direction
            // both failed empirically (see VERIFICATION.md F-2, F-4, F-5,
            // F-5.A); CONTEXT.md Amendment 2026/05/12 restores the
            // canonical D-04 path.
            .set_location(Location::DataProtectionKeychain)
            .set_access_control(
                SecAccessControl::create_with_protection(
                    Some(ProtectionMode::AccessibleAfterFirstUnlockThisDeviceOnly),
                    AccessControlOptions::PRIVATE_KEY_USAGE.bits(),
                )
                .map_err(|e| Error::Platform(format!("access control: {e}")))?,
            );

        let key = SecKey::new(&attributes)
            .map_err(|e| Error::Platform(format!("failed to generate SecKey: {e:?}")))?;
        Ok(Self::new(key, true))
    }

    /// Load a previously persisted Secure Enclave key from the Keychain.
    ///
    /// Queries the Keychain for a key matching `label` (stored under
    /// `kSecAttrLabel` by
    /// [`generate_secure_enclave`](Self::generate_secure_enclave)). Returns `None`
    /// if no key is found.
    ///
    /// Phase 18.1 (`2026/05/12`): the data-protection Keychain selector
    /// is RESTORED (D-20-restored) per Apple TN3137 ("Keys stored in the
    /// Secure Enclave _must_ use this keychain"). The lookup targets DPK;
    /// authorisation lives in the embedded provisioning profile bundled
    /// by the host application's build script (Option B, CONTEXT.md
    /// Amendment 2026/05/12).
    pub fn load_from_keychain(label: &str) -> Result<Option<Self>, Error> {
        use core_foundation::base::TCFType as _;
        use core_foundation::boolean::CFBoolean;
        use core_foundation::string::CFString;
        use security_framework_sys::item::{
            kSecAttrKeyClass, kSecAttrKeyClassPrivate, kSecAttrKeyType,
            kSecAttrKeyTypeECSECPrimeRandom, kSecAttrLabel, kSecAttrTokenID,
            kSecAttrTokenIDSecureEnclave, kSecClass, kSecClassKey, kSecReturnRef,
        };
        use security_framework_sys::keychain_item::SecItemCopyMatching;

        let label = CFString::new(label);

        // SAFETY: every key/value in `query` is wrapped under the Get rule from
        // a static `kSec*` constant (or an owned `CFString`/`CFBoolean`), so the
        // dictionary holds only valid, live `CFType`s for the duration of the
        // call. `result` is a null-initialised `CFTypeRef` out-param whose
        // address is a valid `*mut CFTypeRef`. `SecItemCopyMatching` reads
        // `query` and, only on `errSecSuccess`, writes back a Create-rule-owned
        // object (we requested `kSecReturnRef`); that object is taken exactly
        // once with `wrap_under_create_rule`, so its `Drop` releases it. The
        // not-found and error status paths return before touching `result`,
        // which is left null.
        unsafe {
            let query = CFDictionary::from_CFType_pairs(&[
                (
                    CFString::wrap_under_get_rule(kSecClass),
                    CFString::wrap_under_get_rule(kSecClassKey).as_CFType(),
                ),
                (
                    CFString::wrap_under_get_rule(kSecAttrKeyType),
                    CFString::wrap_under_get_rule(kSecAttrKeyTypeECSECPrimeRandom).as_CFType(),
                ),
                (
                    CFString::wrap_under_get_rule(kSecAttrKeyClass),
                    CFString::wrap_under_get_rule(kSecAttrKeyClassPrivate).as_CFType(),
                ),
                (
                    CFString::wrap_under_get_rule(kSecAttrLabel),
                    label.as_CFType(),
                ),
                (
                    CFString::wrap_under_get_rule(kSecAttrTokenID),
                    CFString::wrap_under_get_rule(kSecAttrTokenIDSecureEnclave).as_CFType(),
                ),
                (
                    CFString::wrap_under_get_rule(kSecReturnRef),
                    CFBoolean::true_value().as_CFType(),
                ),
            ]);

            let mut result: core_foundation::base::CFTypeRef = std::ptr::null();
            let status = SecItemCopyMatching(query.as_concrete_TypeRef(), &mut result);

            if status == security_framework_sys::base::errSecItemNotFound {
                return Ok(None);
            }
            if status != security_framework_sys::base::errSecSuccess {
                return Err(Error::Platform(format!(
                    "Keychain query failed with status {status}"
                )));
            }

            let key = SecKey::wrap_under_create_rule(result as *mut _);
            Ok(Some(Self::new(key, true)))
        }
    }

    /// Derive the P-256 public key for this private key.
    ///
    /// Reads the public key from the `SecKey` and returns its uncompressed
    /// external representation. This is a local accessor — the public
    /// point is always available to the framework, so it incurs no Secure
    /// Enclave round-trip and no authentication prompt.
    pub fn public(&self) -> Result<P256r1PublicKey, Error> {
        let data = self
            .key
            .public_key()
            .ok_or_else(|| Error::Platform("failed to extract public key".into()))?;
        let data = data.external_representation().ok_or_else(|| {
            Error::Platform("failed to extract public key external representation".into())
        })?;
        P256r1PublicKey::from_bytes(data.bytes())
    }

    /// Perform ECDH against `public_key`, returning the raw shared secret.
    ///
    /// Uses `kSecKeyAlgorithmECDHKeyExchangeStandard`, whose output is the
    /// 32-byte x-coordinate of the shared point with no KDF applied — the
    /// representation Noise requires. For a Secure-Enclave-backed key the
    /// scalar multiplication is carried out in-enclave and the private
    /// scalar never leaves hardware; only the resulting secret is returned.
    /// The peer's public bytes are rebuilt into a `SecKey` using this key's
    /// own public-key attributes as the template (both are P-256 public
    /// keys). Fails if the key does not advertise support for the exchange
    /// algorithm or if the agreed secret is not exactly 32 bytes.
    pub fn dh(&self, public_key: &P256r1PublicKey) -> Result<SharedSecret<32>, Error> {
        let algorithm = Algorithm::ECDHKeyExchangeStandard;

        // SAFETY: `self.key` is a live `SecKey`, so its `as_concrete_TypeRef`
        // yields a valid `SecKeyRef` for the call. The operation type and
        // algorithm are valid static CF constants from `security_framework_sys`.
        // `SecKeyIsAlgorithmSupported` only inspects the key and returns a
        // `Boolean` — it transfers no ownership and returns no Get/Create
        // object, so there is nothing to retain or release.
        let supported = unsafe {
            security_framework_sys::key::SecKeyIsAlgorithmSupported(
                self.key.as_concrete_TypeRef(),
                security_framework_sys::key::kSecKeyOperationTypeKeyExchange,
                security_framework_sys::key::kSecKeyAlgorithmECDHKeyExchangeStandard,
            )
        };
        if supported != 1 {
            return Err(Error::Platform(
                "secret key does not support key exchange".into(),
            ));
        }

        // Build a SecKey from the peer's public bytes, using this key's
        // own public-key attributes as the template (both are P-256
        // public keys, so the EC type/size/class match).
        let self_public = self
            .key
            .public_key()
            .ok_or_else(|| Error::Platform("failed to derive public key for DH".into()))?;
        let public_key: SecKey = public_key.as_sec_key(&self_public.attributes())?;

        let shared_secret = self
            .key
            .key_exchange(algorithm, &public_key, 32, None)
            .map_err(|e| Error::Platform(format!("key exchange failed: {e:?}")))?;

        let bytes: [u8; 32] = shared_secret
            .try_into()
            .map_err(|_| Error::Platform("shared secret is not 32 bytes".into()))?;
        Ok(SharedSecret::new(bytes))
    }

    /// Sign `message` with ECDSA over P-256, SHA-256 digesting the message.
    ///
    /// Uses `kSecKeyAlgorithmECDSASignatureMessageX962SHA256`: the
    /// framework hashes `message` and produces an ASN.1/X9.62 DER
    /// signature, which is decoded into the fixed-width
    /// [`P256Signature`]. For a
    /// Secure-Enclave-backed key the signing scalar multiplication runs
    /// in-enclave and the private scalar never leaves hardware.
    pub fn sign(&self, message: &[u8]) -> Result<P256Signature, Error> {
        let signature = self
            .key
            .create_signature(Algorithm::ECDSASignatureMessageX962SHA256, message)
            .map_err(|e| Error::Platform(format!("signing failed: {e}")))?;
        P256Signature::try_from_asn1(&signature).map_err(|e| {
            Error::Platform(format!(
                "failed to decode ASN.1 signature {}: {e}",
                hex::encode(&signature)
            ))
        })
    }

    /// Delete the key from the Keychain.
    ///
    /// Only deletes keys that were persisted (created via
    /// [`generate_secure_enclave`](Self::generate_secure_enclave)).
    /// Ephemeral keys are silently ignored.
    pub fn delete(self) -> Result<(), Error> {
        if self.deletable {
            self.key
                .delete()
                .map_err(|e| Error::Platform(format!("failed to delete key: {e}")))
        } else {
            Ok(())
        }
    }
}

// ── AppleSecureEnclave ───────────────────────────────────────────────

/// Apple Secure Enclave provider — P-256 in the enclave, software Ed25519
/// with a sealed seed.
///
/// P-256 static keys are generated in the Secure Enclave and persisted to
/// the data-protection Keychain under the label `{namespace}.p256`;
/// ephemeral keys use a software-backed `SecKey` (no persistence). Ed25519
/// is software-signed — the enclave has no Ed25519 support — and its
/// 32-byte seed is sealed to this device's SE P-256 public key (a
/// 129-byte Noise-N envelope; the internal `noise::seal` helper) and stored in
/// the same data-protection Keychain under the service
/// `{namespace}.ed25519` ([`store_seed`](Self::store_seed) /
/// [`load_seed`](Self::load_seed)). Both platforms (macOS and iOS) use
/// the Keychain — there is no on-disk seed file.
///
/// `namespace` is a required, caller-supplied reverse-DNS base (no
/// default): it names the persisted slots so independent identities on a
/// device never collide.
#[derive(Clone)]
pub struct AppleSecureEnclave {
    namespace: String,
}

/// Errors from the [`AppleSecureEnclave`] Ed25519 seed lifecycle
/// ([`store_seed`](AppleSecureEnclave::store_seed) /
/// [`load_seed`](AppleSecureEnclave::load_seed)).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SeedError {
    /// The Secure Enclave P-256 identity key (the seal recipient) is
    /// absent. Establish it first via
    /// [`generate_static_key`](CryptoKeyProvider::generate_static_key).
    #[error(
        "Secure Enclave P-256 identity key {label:?} not found (establish it before sealing the Ed25519 seed)"
    )]
    IdentityKeyMissing {
        /// Keychain label of the absent SE P-256 identity key.
        label: String,
    },

    /// A Secure Enclave P-256 key operation failed.
    #[error(transparent)]
    P256(#[from] Error),

    /// Sealing or opening the seed via the Noise-N envelope failed.
    ///
    /// The internal `SealError` is rendered to a message at this
    /// boundary because the seal primitive is crate-private.
    #[error("Noise-N seed envelope operation failed: {0}")]
    Seal(String),

    /// A Keychain item operation (store / query / delete) failed.
    #[error("Ed25519 seed Keychain operation failed: {0}")]
    Keychain(String),

    /// The stored seed envelope was not the expected sealed length.
    #[error(
        "stored Ed25519 seed envelope has wrong length: expected {expected} bytes, got {got}",
        expected = SEALED_SIZE
    )]
    WrongSize {
        /// Actual length of the stored envelope, in bytes (the expected
        /// length is the internal `SEALED_SIZE`).
        got: usize,
    },
}

/// Build the data-protection-Keychain generic-password query for the
/// sealed Ed25519 seed under `service`.
fn seed_password_options(service: &str) -> Result<PasswordOptions, SeedError> {
    let mut options = PasswordOptions::new_generic_password(service, ED25519_SEED_ACCOUNT);
    let access_control = SecAccessControl::create_with_protection(
        Some(ProtectionMode::AccessibleAfterFirstUnlockThisDeviceOnly),
        0,
    )
    .map_err(|e| SeedError::Keychain(format!("failed to build seed access control: {e}")))?;
    options.set_access_control(access_control);
    options.set_access_synchronized(Some(false));
    options.use_protected_keychain();
    Ok(options)
}

impl AppleSecureEnclave {
    /// Construct a provider for the given keychain `namespace` (a
    /// reverse-DNS base such as `"uk.co.example.app"`). The namespace
    /// names every persisted slot: the SE key (`{namespace}.p256`) and
    /// the sealed Ed25519 seed (`{namespace}.ed25519`).
    pub fn new(namespace: impl Into<String>) -> Self {
        Self {
            namespace: namespace.into(),
        }
    }

    /// Keychain label of the persisted SE P-256 identity key.
    fn p256_label(&self) -> String {
        format!("{}.p256", self.namespace)
    }

    /// Keychain generic-password service of the sealed Ed25519 seed.
    fn ed25519_service(&self) -> String {
        format!("{}.ed25519", self.namespace)
    }

    /// Load the persisted SE P-256 identity key, if one exists.
    pub fn load_identity(&self) -> Result<Option<P256r1PrivateKey>, Error> {
        P256r1PrivateKey::load_from_keychain(&self.p256_label())
    }

    /// Delete the persisted SE P-256 identity key (idempotent — `Ok` if
    /// none is present).
    pub fn delete_identity(&self) -> Result<(), Error> {
        match self.load_identity()? {
            Some(key) => key.delete(),
            None => Ok(()),
        }
    }

    /// Seal the 32-byte Ed25519 `seed` to this device's SE P-256 public
    /// key and store the resulting 129-byte envelope in the
    /// data-protection Keychain under `{namespace}.ed25519`.
    ///
    /// Requires the SE P-256 identity key (the seal recipient) to already
    /// exist — establish it via
    /// [`generate_static_key`](CryptoKeyProvider::generate_static_key).
    pub async fn store_seed(&self, seed: &[u8; 32]) -> Result<(), SeedError> {
        // Look up the SE identity key and extract its public key (the
        // seal recipient) on the blocking pool — the lookup is a blocking
        // Security-framework call. Only the public key is needed past
        // here, so the private `SecKey` handle never leaves the closure.
        let label = self.p256_label();
        let se_public = offload_seed(move || {
            let se_private = match P256r1PrivateKey::load_from_keychain(&label)? {
                Some(key) => key,
                None => return Err(SeedError::IdentityKeyMissing { label }),
            };
            Ok(se_private.public()?)
        })
        .await?;

        // Seal the seed to the SE public key (the DH is itself offloaded
        // by the provider inside `seal_32`).
        let sealed = seal_32(self.clone(), &se_public, seed)
            .await
            .map_err(|e| SeedError::Seal(e.to_string()))?;

        // Overwrite any prior item, then store the sealed envelope — both
        // are blocking Keychain writes, so run them on the blocking pool.
        let service = self.ed25519_service();
        offload_seed(move || {
            let _ = delete_generic_password_options(seed_password_options(&service)?);
            set_generic_password_options(&sealed, seed_password_options(&service)?).map_err(|e| {
                SeedError::Keychain(format!("failed to store sealed Ed25519 seed: {e}"))
            })
        })
        .await
    }

    /// Load and unseal the Ed25519 seed, or `None` if none is stored.
    pub async fn load_seed(&self) -> Result<Option<[u8; 32]>, SeedError> {
        // Blocking Keychain query for the sealed envelope.
        let service = self.ed25519_service();
        let sealed_bytes =
            offload_seed(
                move || match generic_password(seed_password_options(&service)?) {
                    Ok(bytes) => Ok(Some(bytes)),
                    Err(e) if e.code() == security_framework_sys::base::errSecItemNotFound => {
                        Ok(None)
                    }
                    Err(e) => Err(SeedError::Keychain(format!(
                        "failed to query sealed Ed25519 seed: {e}"
                    ))),
                },
            )
            .await?;
        let Some(sealed_bytes) = sealed_bytes else {
            return Ok(None);
        };
        if sealed_bytes.len() != SEALED_SIZE {
            return Err(SeedError::WrongSize {
                got: sealed_bytes.len(),
            });
        }
        let mut sealed = [0u8; SEALED_SIZE];
        sealed.copy_from_slice(&sealed_bytes);

        // Blocking SE-key lookup; the returned key (a `Send` `SecKey`
        // handle) then moves into `open_32`, whose DH the provider
        // offloads.
        let label = self.p256_label();
        let se_private =
            offload_seed(
                move || match P256r1PrivateKey::load_from_keychain(&label)? {
                    Some(key) => Ok(key),
                    None => Err(SeedError::IdentityKeyMissing { label }),
                },
            )
            .await?;

        let opened = open_32(self.clone(), se_private, &sealed)
            .await
            .map_err(|e| SeedError::Seal(e.to_string()))?;
        Ok(Some(opened))
    }

    /// Delete the stored sealed Ed25519 seed (idempotent). Synchronous —
    /// removing the Keychain item needs no enclave round-trip.
    pub fn delete_seed(&self) -> Result<(), SeedError> {
        let service = self.ed25519_service();
        match delete_generic_password_options(seed_password_options(&service)?) {
            Ok(()) => Ok(()),
            Err(e) if e.code() == security_framework_sys::base::errSecItemNotFound => Ok(()),
            Err(e) => Err(SeedError::Keychain(format!(
                "failed to delete sealed Ed25519 seed: {e}"
            ))),
        }
    }
}

/// Run a blocking Security-framework operation on Tokio's blocking
/// thread pool.
///
/// Apple's `SecKey*` crypto calls are synchronous, blocking C functions
/// with no async variant — and a Secure Enclave operation can stall for
/// a meaningful time (including any keychain/biometric wait). Running
/// them inline inside an `async fn` would block the async executor;
/// [`spawn_blocking`](tokio::task::spawn_blocking) moves them to a
/// dedicated blocking thread so the executor keeps making progress and
/// the future genuinely suspends until the work completes.
///
/// Because this offloads, the [`DhProviderAsync`] futures here resolve
/// on a worker thread rather than the first poll. The synchronous
/// [`DhProvider`] surface runs the
/// same blocking calls directly on the caller's thread, so
/// `AppleSecureEnclave` is usable with the blocking `std::io` handshake
/// too.
async fn offload<T, F>(op: F) -> Result<T, Error>
where
    F: FnOnce() -> Result<T, Error> + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(op)
        .await
        .map_err(|e| Error::Platform(format!("Secure Enclave task failed to join: {e}")))?
}

/// Like [`offload`], but for the Ed25519 seed lifecycle's [`SeedError`].
///
/// The Keychain item calls and the SE-key lookup are synchronous,
/// blocking Security-framework operations (a keychain wait can stall) —
/// run them on the blocking pool so the async seed methods never block
/// the executor.
async fn offload_seed<T, F>(op: F) -> Result<T, SeedError>
where
    F: FnOnce() -> Result<T, SeedError> + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(op)
        .await
        .map_err(|e| SeedError::Keychain(format!("seed Keychain task failed to join: {e}")))?
}

// Apple's Security-framework operations are synchronous, blocking C
// calls — so the *synchronous* surface is simply those inherent ops,
// run directly on the calling thread. (This is the right behaviour in a
// blocking context; the async impls below offload the same calls.) This
// is what makes Secure Enclave keys usable with the blocking `std::io`
// handshake, exactly as Apple's libraries expose them.
impl CryptoKeyProvider<P256> for AppleSecureEnclave {
    type Error = Error;
    type PrivateKey = P256r1PrivateKey;

    fn public_key(&self, key: &Self::PrivateKey) -> Result<P256r1PublicKey, Self::Error> {
        // Cheap, local SecKey accessor — no Secure Enclave round-trip and
        // no prompt — so it stays inline (the trait declares it sync).
        key.public()
    }

    fn generate_static_key(&mut self) -> Result<Self::PrivateKey, Self::Error> {
        P256r1PrivateKey::generate_secure_enclave(&self.p256_label())
    }

    fn generate_ephemeral_key(&mut self) -> Result<Self::PrivateKey, Self::Error> {
        P256r1PrivateKey::generate_ephemeral()
    }
}

impl CryptoKeyProviderAsync<P256> for AppleSecureEnclave {
    async fn generate_static_key_async(&mut self) -> Result<Self::PrivateKey, Self::Error> {
        let label = self.p256_label();
        offload(move || P256r1PrivateKey::generate_secure_enclave(&label)).await
    }

    async fn generate_ephemeral_key_async(&mut self) -> Result<Self::PrivateKey, Self::Error> {
        offload(P256r1PrivateKey::generate_ephemeral).await
    }
}

impl DhProvider<P256> for AppleSecureEnclave {
    fn dh(
        &self,
        key: &Self::PrivateKey,
        peer: &P256r1PublicKey,
    ) -> Result<SharedSecret<32>, Self::Error> {
        key.dh(peer)
    }
}

impl DhProviderAsync<P256> for AppleSecureEnclave {
    async fn dh_async(
        &self,
        key: &Self::PrivateKey,
        peer: &P256r1PublicKey,
    ) -> Result<SharedSecret<32>, Self::Error> {
        let key = key.clone();
        let peer = *peer;
        offload(move || key.dh(&peer)).await
    }
}

impl SigningProvider<P256> for AppleSecureEnclave {
    fn sign(&self, key: &Self::PrivateKey, message: &[u8]) -> Result<P256Signature, Self::Error> {
        key.sign(message)
    }
}

impl SigningProviderAsync<P256> for AppleSecureEnclave {
    async fn sign_async(
        &self,
        key: &Self::PrivateKey,
        message: &[u8],
    ) -> Result<P256Signature, Self::Error> {
        let key = key.clone();
        let message = message.to_vec();
        offload(move || key.sign(&message)).await
    }
}

// ── Ed25519 (software — the enclave has no Ed25519 support) ───────────
//
// The Secure Enclave never touches Ed25519: these are software
// (`cryptoxide`) operations. Unlike `EphemeralOnly`, the seed's entropy
// comes from Apple's `SecRandomCopyBytes` (hardware-grade) rather than a
// caller-supplied RNG — so `AppleSecureEnclave` needs no `R` parameter.
// Persistence of the seed at rest is handled separately by the
// sealed-seed lifecycle above (`store_seed` / `load_seed`).

/// Generate a software Ed25519 key seeded from Apple's `SecRandomCopyBytes`.
fn apple_ed25519_generate() -> Result<SoftwareEd25519PrivateKey, crate::curve::ed25519::Error> {
    let mut seed = [0u8; 32];
    // SAFETY: `seed.as_mut_ptr()` is a valid, properly-aligned pointer to the
    // exclusively-borrowed `[u8; 32]` (the `&mut seed` borrow guarantees no
    // aliasing for the call). We pass `seed.len()` (== 32), so exactly that many
    // bytes are written within the array's bounds and no further.
    // `kSecRandomDefault` is the framework's valid default RNG reference. The
    // returned status is checked by the caller below before `seed` is used.
    let status = unsafe {
        security_framework_sys::random::SecRandomCopyBytes(
            security_framework_sys::random::kSecRandomDefault,
            seed.len(),
            seed.as_mut_ptr().cast(),
        )
    };
    if status != 0 {
        return Err(crate::curve::ed25519::Error::Platform(format!(
            "SecRandomCopyBytes failed with status {status}"
        )));
    }
    if seed.iter().all(|&b| b == 0) {
        return Err(crate::curve::ed25519::Error::Platform(
            "SecRandomCopyBytes returned an all-zero seed".into(),
        ));
    }
    Ok(SoftwareEd25519PrivateKey::from_seed(seed))
}

impl CryptoKeyProvider<Ed25519> for AppleSecureEnclave {
    type Error = crate::curve::ed25519::Error;
    type PrivateKey = SoftwareEd25519PrivateKey;

    fn public_key(&self, key: &Self::PrivateKey) -> Result<Ed25519PublicKey, Self::Error> {
        Ok(key.public_key())
    }

    fn generate_static_key(&mut self) -> Result<Self::PrivateKey, Self::Error> {
        apple_ed25519_generate()
    }

    fn generate_ephemeral_key(&mut self) -> Result<Self::PrivateKey, Self::Error> {
        apple_ed25519_generate()
    }
}

impl CryptoKeyProviderAsync<Ed25519> for AppleSecureEnclave {
    async fn generate_static_key_async(&mut self) -> Result<Self::PrivateKey, Self::Error> {
        apple_ed25519_generate()
    }

    async fn generate_ephemeral_key_async(&mut self) -> Result<Self::PrivateKey, Self::Error> {
        apple_ed25519_generate()
    }
}

impl DhProvider<Ed25519> for AppleSecureEnclave {
    fn dh(
        &self,
        key: &Self::PrivateKey,
        peer: &Ed25519PublicKey,
    ) -> Result<SharedSecret<32>, Self::Error> {
        Ok(key.dh(peer))
    }
}

impl DhProviderAsync<Ed25519> for AppleSecureEnclave {
    async fn dh_async(
        &self,
        key: &Self::PrivateKey,
        peer: &Ed25519PublicKey,
    ) -> Result<SharedSecret<32>, Self::Error> {
        Ok(key.dh(peer))
    }
}

impl SigningProvider<Ed25519> for AppleSecureEnclave {
    fn sign(
        &self,
        key: &Self::PrivateKey,
        message: &[u8],
    ) -> Result<Ed25519Signature, Self::Error> {
        Ok(key.sign(message))
    }
}

impl SigningProviderAsync<Ed25519> for AppleSecureEnclave {
    async fn sign_async(
        &self,
        key: &Self::PrivateKey,
        message: &[u8],
    ) -> Result<Ed25519Signature, Self::Error> {
        Ok(key.sign(message))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curve::p256::P256r1PrivateKey as SoftwareP256r1PrivateKey;
    use crate::provider::ProviderExt;

    #[test]
    fn generate_signature_ephemeral() {
        let sk1 = P256r1PrivateKey::generate_ephemeral().unwrap();
        let pk1 = sk1.public().unwrap();
        const MSG: &[u8] = b"Hello World";
        let signature = sk1.sign(MSG).unwrap();
        assert!(pk1.verify(signature, MSG));

        let sk2 = P256r1PrivateKey::generate_ephemeral().unwrap();
        let pk2 = sk2.public().unwrap();
        assert!(!pk2.verify(signature, MSG));

        sk1.delete().unwrap();
        sk2.delete().unwrap();
    }

    #[test]
    fn generate_dh_ephemerals() {
        let sk1 = P256r1PrivateKey::generate_ephemeral().unwrap();
        let pk1 = sk1.public().unwrap();

        let sk2 = P256r1PrivateKey::generate_ephemeral().unwrap();
        let pk2 = sk2.public().unwrap();

        let ss1 = sk1.dh(&pk2).unwrap();
        let ss2 = sk2.dh(&pk1).unwrap();

        assert_eq!(ss1, ss2);
    }

    #[test]
    fn macos_x_software() {
        let sk1 = P256r1PrivateKey::generate_ephemeral().unwrap();
        let pk1 = sk1.public().unwrap();

        let sk2 = SoftwareP256r1PrivateKey::generate(rand::rng()).unwrap();
        let pk2 = sk2.public();

        let apple_dh = sk1.dh(&pk2).unwrap();
        let our_dh = sk2.dh(&pk1).unwrap();

        assert_eq!(apple_dh, our_dh);
    }

    /// Drive the async provider trait methods (which offload to
    /// the Tokio blocking pool) end-to-end under a real runtime: generate
    /// two ephemeral keys, agree, and confirm the DH matches both ways.
    #[tokio::test]
    async fn crypto_provider_offloaded_dh_roundtrip() {
        let mut provider = AppleSecureEnclave::new("uk.co.example.hiss-test");

        // Fully-qualified P-256: the provider also implements the trait
        // for Ed25519, so the curve can't be inferred from the call alone.
        let a = CryptoKeyProviderAsync::<P256>::generate_ephemeral_key_async(&mut provider)
            .await
            .unwrap();
        let b = CryptoKeyProviderAsync::<P256>::generate_ephemeral_key_async(&mut provider)
            .await
            .unwrap();
        let a_pub = provider.public(&a).unwrap();
        let b_pub = provider.public(&b).unwrap();

        let ab = DhProviderAsync::<P256>::dh_async(&provider, &a, &b_pub)
            .await
            .unwrap();
        let ba = DhProviderAsync::<P256>::dh_async(&provider, &b, &a_pub)
            .await
            .unwrap();
        assert_eq!(ab, ba);

        // The offloaded signing path round-trips too.
        let sig = SigningProviderAsync::<P256>::sign_async(&provider, &a, b"hello")
            .await
            .unwrap();
        assert!(a_pub.verify(sig, b"hello"));
    }

    #[test]
    #[ignore = "requires Secure Enclave hardware"]
    fn generate_signature_secure_enclave() {
        let sk1 = P256r1PrivateKey::generate_secure_enclave_ephemeral().unwrap();
        let pk1 = sk1.public().unwrap();
        const MSG: &[u8] = b"Hello World";
        let signature = sk1.sign(MSG).unwrap();
        assert!(pk1.verify(signature, MSG));

        let sk2 = P256r1PrivateKey::generate_secure_enclave_ephemeral().unwrap();
        let pk2 = sk2.public().unwrap();
        assert!(!pk2.verify(signature, MSG));

        sk1.delete().unwrap();
        sk2.delete().unwrap();
    }

    /// Establish an SE identity, seal + store the Ed25519 seed to the
    /// Keychain, load it back, and delete — the full keychain-backed
    /// seed lifecycle. Ignored: needs a codesigned binary with the
    /// keychain-access-groups entitlement and Secure Enclave hardware.
    #[tokio::test]
    #[ignore = "requires codesigned test binary + Secure Enclave hardware"]
    async fn ed25519_seed_keychain_round_trip() {
        let mut provider = AppleSecureEnclave::new("uk.co.example.hiss-test");

        // Establish the SE P-256 identity (the seal recipient).
        let _identity = provider.generate::<P256>().unwrap();

        let seed: [u8; 32] = *SoftwareEd25519PrivateKey::generate(rand::rng()).seed();

        assert!(provider.load_seed().await.unwrap().is_none());

        provider.store_seed(&seed).await.unwrap();
        let loaded = provider
            .load_seed()
            .await
            .unwrap()
            .expect("seed present after store");
        assert_eq!(loaded, seed, "loaded seed must byte-equal the stored seed");

        provider.delete_seed().unwrap();
        assert!(provider.load_seed().await.unwrap().is_none());
        // idempotent
        provider.delete_seed().unwrap();

        provider.delete_identity().unwrap();
    }
}
