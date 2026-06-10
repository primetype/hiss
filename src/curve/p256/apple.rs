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
//!   `bin/bubble-desktop/scripts/dev.sh` Step 3 (D-27.c). The Secure
//!   Enclave binding is preserved via `Token::SecureEnclave` and
//!   `kSecAttrTokenIDSecureEnclave` — D-23 invariant. iOS continues to
//!   use its single (data-protection) keychain as before.

use super::{Error, P256, P256Signature, P256r1PublicKey};
use crate::curve::{CryptoProvider, SharedSecret};
use core_foundation::{base::TCFType as _, data::CFData, dictionary::CFDictionary};
use security_framework::{
    access_control::{ProtectionMode, SecAccessControl},
    item::Location,
    key::{Algorithm, GenerateKeyOptions, KeyType, SecKey, Token},
    passwords_options::AccessControlOptions,
};

const TAG: &str = "uk.co.primetype.bubble.key";

#[derive(Clone)]
pub struct P256r1PrivateKey {
    key: SecKey,
    deletable: bool,
}

impl P256r1PublicKey {
    fn as_sec_key(&self, attributes: &CFDictionary) -> Result<SecKey, Error> {
        let key_data = CFData::from_buffer(&self.0);
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

    pub fn generate_ephemeral() -> Result<Self, Error> {
        let mut attributes = GenerateKeyOptions::default();
        attributes
            .set_key_type(KeyType::ec())
            .set_size_in_bits(256)
            .set_token(Token::Software)
            .set_label(format!("{TAG}.ephemeral"));

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
            .set_label(TAG)
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
    pub fn generate_secure_enclave() -> Result<Self, Error> {
        let mut attributes = GenerateKeyOptions::default();
        attributes
            .set_key_type(KeyType::ec())
            .set_size_in_bits(256)
            .set_label(TAG)
            .set_token(Token::SecureEnclave)
            // Phase 18.1 (`2026/05/12`): the data-protection Keychain
            // selector is RESTORED (D-20-restored) per Apple TN3137
            // ("Keys stored in the Secure Enclave _must_ use this
            // keychain"). Authorisation for the team-prefixed
            // `keychain-access-groups` entitlement is provided by the
            // embedded macOS Development provisioning profile bundled
            // alongside the binary by `bin/bubble-desktop/scripts/dev.sh`
            // Step 3 (D-27.c). The prior 2026/05/08 drop-the-selector
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
    /// Queries the Keychain for a key matching [`TAG`] (stored via
    /// `kSecAttrLabel` by [`generate_secure_enclave`]). Returns `None`
    /// if no key is found.
    ///
    /// Phase 18.1 (`2026/05/12`): the data-protection Keychain selector
    /// is RESTORED (D-20-restored) per Apple TN3137 ("Keys stored in the
    /// Secure Enclave _must_ use this keychain"). The lookup targets DPK;
    /// authorisation lives in the embedded provisioning profile bundled
    /// by `bin/bubble-desktop/scripts/dev.sh` Step 3 (Option B, CONTEXT.md
    /// Amendment 2026/05/12).
    pub fn load_from_keychain() -> Result<Option<Self>, Error> {
        use core_foundation::base::TCFType as _;
        use core_foundation::boolean::CFBoolean;
        use core_foundation::string::CFString;
        use security_framework_sys::item::{
            kSecAttrKeyClass, kSecAttrKeyClassPrivate, kSecAttrKeyType,
            kSecAttrKeyTypeECSECPrimeRandom, kSecAttrLabel, kSecAttrTokenID,
            kSecAttrTokenIDSecureEnclave, kSecClass, kSecClassKey, kSecReturnRef,
        };
        use security_framework_sys::keychain_item::SecItemCopyMatching;

        let label = CFString::new(TAG);

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

    pub fn dh(&self, public_key: &P256r1PublicKey) -> Result<SharedSecret, Error> {
        let algorithm = Algorithm::ECDHKeyExchangeStandard;

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

// ── CryptoProvider ──────────────────────────────────────────────

/// macOS Secure Enclave [`CryptoProvider`] for P-256.
///
/// Static keys are generated in the Secure Enclave and persisted
/// to the Data Protection Keychain. Ephemeral keys use a
/// software-backed `SecKey` (no persistence, no biometric).
#[derive(Clone, Copy)]
pub struct SecureEnclaveCryptoProvider;

impl CryptoProvider<P256> for SecureEnclaveCryptoProvider {
    type Error = Error;
    type PrivateKey = P256r1PrivateKey;

    async fn generate_static_key(&self) -> Result<Self::PrivateKey, Self::Error> {
        P256r1PrivateKey::generate_secure_enclave()
    }

    async fn generate_ephemeral_key(&self) -> Result<Self::PrivateKey, Self::Error> {
        P256r1PrivateKey::generate_ephemeral()
    }

    fn public_key(&self, key: &Self::PrivateKey) -> Result<P256r1PublicKey, Self::Error> {
        key.public()
    }

    async fn sign(
        &self,
        key: &Self::PrivateKey,
        message: &[u8],
    ) -> Result<P256Signature, Self::Error> {
        key.sign(message)
    }

    async fn dh(
        &self,
        key: &Self::PrivateKey,
        peer: &P256r1PublicKey,
    ) -> Result<SharedSecret, Self::Error> {
        key.dh(peer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curve::p256::P256r1PrivateKey as SoftwareP256r1PrivateKey;

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

        let sk2 = SoftwareP256r1PrivateKey::generate_ephemeral().unwrap();
        let pk2 = sk2.public();

        let apple_dh = sk1.dh(&pk2).unwrap();
        let our_dh = sk2.dh(&pk1);

        assert_eq!(apple_dh, our_dh);
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
}
