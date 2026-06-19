//! Noise-N one-way seal helpers for fixed-size 32-byte payloads.
//!
//! These helpers wrap the `Noise_N_P256_ChaChaPoly_BLAKE2b` pattern
//! (one-way sealing of a secret to a recipient's public key) and
//! expose two ergonomic async functions for sealing and opening a
//! 32-byte payload to a recipient's P-256 public key.
//!
//! Async by construction: matches the existing `CryptoProviderAsync<P256>`
//! async-trait pattern in [`crate::curve::p256`]. Callers `.await`
//! directly. NO `block_on` / `Handle::try_current` is used — those
//! would panic when invoked from inside a Tokio worker.
//!
//! # Wire format
//!
//! The sealed envelope is exactly 129 bytes:
//!
//! ```text
//! [Noise N msg1 — 81 bytes: ephemeral public key (65) + empty payload tag (16)]
//! [Transport ciphertext — 48 bytes: encrypted payload (32) + AEAD tag (16)]
//! ```
//!
//! The layout is stable and self-describing. Each seal operation uses
//! a fresh ephemeral key, providing forward secrecy per write.
//!
//! # Cryptographic invariant
//!
//! The sealed envelope is opaque to anyone without the recipient's
//! P-256 private key. On Apple platforms the recipient private key
//! lives in the Secure Enclave (non-exportable hardware-resident
//! material).

use crate::provider::CryptoProviderAsync;
use crate::curve::p256::{P256, P256r1PublicKey};
use crate::noise::{Blake2b, ChaChaPoly, N, Noise, Transport};

/// Size of the cleartext payload sealed by [`seal_32`] / [`open_32`].
pub const SEAL_PAYLOAD_SIZE: usize = 32;

/// Size of the Noise N msg1 (ephemeral key + empty payload tag).
pub const NOISE_N_MSG1_SIZE: usize = 81;

/// The Noise N protocol pinned for sealing.
///
/// `Noise_N_P256_ChaChaPoly_BLAKE2b` — the one-way sealing descriptor
/// used by [`seal_32`] / [`open_32`].
pub type NoiseSeal = Noise<N, P256, ChaChaPoly, Blake2b>;

/// Size of the transport ciphertext (payload + AEAD tag).
const SEALED_TRANSPORT_SIZE: usize = SEAL_PAYLOAD_SIZE + Transport::<NoiseSeal>::OVERHEAD;

/// Total size of the sealed envelope: 129 bytes
/// (81-byte Noise N msg1 ‖ 48-byte transport ciphertext).
pub const SEALED_SIZE: usize = NOISE_N_MSG1_SIZE + SEALED_TRANSPORT_SIZE;

/// Errors that can occur while sealing or opening a 32-byte payload.
#[derive(Debug, thiserror::Error)]
pub enum SealError {
    /// The Noise N seal sequence failed.
    #[error("Noise N seal failed: {0}")]
    Seal(String),
    /// The Noise N open sequence failed.
    #[error("Noise N open failed: {0}")]
    Open(String),
}

/// Seal a 32-byte payload to `recipient_pub` using
/// `Noise_N_P256_ChaChaPoly_BLAKE2b`.
///
/// Each call generates a fresh ephemeral key (forward secrecy per
/// write). The returned 129-byte envelope is opaque to anyone without
/// the recipient's P-256 private key.
pub async fn seal_32<P>(
    provider: P,
    recipient_pub: &P256r1PublicKey,
    payload: &[u8; SEAL_PAYLOAD_SIZE],
) -> Result<[u8; SEALED_SIZE], SealError>
where
    P: CryptoProviderAsync<P256>,
    P::Error: std::fmt::Display,
{
    let sealer = NoiseSeal::initiate(provider, &[]).set_rs(*recipient_pub);

    let mut msg_buf = [0u8; NOISE_N_MSG1_SIZE];
    let (msg, mut transport) = sealer
        .e(&mut msg_buf)
        .await
        .map_err(|e| SealError::Seal(e.to_string()))?
        .es()
        .await
        .map_err(|e| SealError::Seal(e.to_string()))?;

    let mut sealed_transport = [0u8; SEALED_TRANSPORT_SIZE];
    let sealed_len = transport
        .send(payload, &mut sealed_transport)
        .map_err(|e| SealError::Seal(e.to_string()))?;

    let mut blob = [0u8; SEALED_SIZE];
    blob[..NOISE_N_MSG1_SIZE].copy_from_slice(msg);
    blob[NOISE_N_MSG1_SIZE..NOISE_N_MSG1_SIZE + sealed_len]
        .copy_from_slice(&sealed_transport[..sealed_len]);

    Ok(blob)
}

/// Open a 129-byte sealed envelope using the recipient's private key.
///
/// Consumes the private key because the Noise handshake state
/// machine takes ownership (private keys are intentionally
/// non-cloneable). On Apple platforms `recipient_key` is the
/// Secure-Enclave-bound P-256 key (non-exportable).
pub async fn open_32<P>(
    provider: P,
    recipient_key: P::PrivateKey,
    sealed: &[u8; SEALED_SIZE],
) -> Result<[u8; SEAL_PAYLOAD_SIZE], SealError>
where
    P: CryptoProviderAsync<P256>,
    P::Error: std::fmt::Display,
{
    let msg1 = &sealed[..NOISE_N_MSG1_SIZE];
    let ciphertext = &sealed[NOISE_N_MSG1_SIZE..];

    let opener = NoiseSeal::respond(provider, &[])
        .set_s(recipient_key)
        .map_err(|e| SealError::Open(e.to_string()))?;

    let (_, recv) = opener
        .read(msg1)
        .map_err(|e| SealError::Open(e.to_string()))?
        .e()
        .await
        .map_err(|e| SealError::Open(e.to_string()))?;

    let mut transport = recv
        .es()
        .await
        .map_err(|e| SealError::Open(e.to_string()))?;

    let mut payload = [0u8; SEAL_PAYLOAD_SIZE];
    transport
        .receive(ciphertext, &mut payload)
        .map_err(|e| SealError::Open(e.to_string()))?;

    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curve::p256::P256r1PrivateKey;
    use crate::provider::EphemeralOnly;

    #[tokio::test]
    async fn seal_open_round_trip() {
        let device_key = P256r1PrivateKey::generate().unwrap();
        let device_pub = device_key.public();
        let payload: [u8; 32] = [0x42; 32];

        let sealed = seal_32(EphemeralOnly, &device_pub, &payload)
            .await
            .unwrap();
        assert_eq!(sealed.len(), SEALED_SIZE);
        assert_eq!(
            SEALED_SIZE, 129,
            "Noise-N sealed envelope is 129 bytes (81-byte msg1 + 48-byte transport)",
        );
        assert!(
            sealed.windows(32).all(|w| w != payload),
            "sealed envelope must not contain cleartext payload",
        );

        let opened = open_32(EphemeralOnly, device_key, &sealed)
            .await
            .unwrap();
        assert_eq!(opened, payload);
    }

    #[tokio::test]
    async fn open_with_wrong_key_fails() {
        let device_key = P256r1PrivateKey::generate().unwrap();
        let device_pub = device_key.public();
        let payload: [u8; 32] = [0x99; 32];
        let sealed = seal_32(EphemeralOnly, &device_pub, &payload)
            .await
            .unwrap();

        let other_key = P256r1PrivateKey::generate().unwrap();
        let result = open_32(EphemeralOnly, other_key, &sealed).await;
        assert!(
            matches!(result, Err(SealError::Open(_))),
            "opening with wrong key must fail",
        );
    }

    #[tokio::test]
    async fn fresh_ephemeral_per_seal() {
        let device_key = P256r1PrivateKey::generate().unwrap();
        let device_pub = device_key.public();
        let payload: [u8; 32] = [0xAB; 32];

        let sealed_a = seal_32(EphemeralOnly, &device_pub, &payload)
            .await
            .unwrap();
        let sealed_b = seal_32(EphemeralOnly, &device_pub, &payload)
            .await
            .unwrap();

        // Different ephemeral key each time → different blobs even
        // for identical payload + recipient.
        assert_ne!(sealed_a, sealed_b);
    }
}
