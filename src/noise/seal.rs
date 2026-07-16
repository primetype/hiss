//! Noise-N one-way seal helpers for fixed-size 32-byte payloads.
//!
//! A P-256 **key-wrapping primitive**: wrap a 32-byte 25519 secret (an
//! Ed25519 seed today; an X25519/Curve25519 key when Apple X25519
//! lands) to a recipient's P-256 public key — on Apple platforms the
//! recipient key lives in the Secure Enclave. The wrapping uses the
//! `Noise_N_P256_ChaChaPoly_BLAKE2b` one-way pattern.
//!
//! These helpers are **internal** ([`pub(crate)`]) and Apple-scoped:
//! the sole consumer is [`crate::provider::apple`]. They are written
//! directly over the shared per-token crypto free functions in
//! [`super::process`] in fixed Noise-N order (`e, es`) — there is no
//! type-state driver and no I/O stream involved.
//!
//! Async by construction: matches the existing `DhProviderAsync<P256>`
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
//! a fresh ephemeral key, providing forward secrecy per write. The
//! envelope is stored verbatim in the Keychain, so the byte layout is
//! frozen (see the `seal_format_pin` test).
//!
//! # Cryptographic invariant
//!
//! The sealed envelope is opaque to anyone without the recipient's
//! P-256 private key. On Apple platforms the recipient private key
//! lives in the Secure Enclave (non-exportable hardware-resident
//! material).

use crate::curve::p256::{P256, P256r1PublicKey};
use crate::curve::{Curve, DhCurve};
use crate::noise::buffers::{RecvBuffer, SendBuffer};
use crate::noise::handshake::HandshakeInner;
use crate::noise::process::{
    do_es_initiator, do_es_responder, recv_e, recv_payload, recv_to_transport, send_e, send_payload,
};
use crate::noise::role::{Initiator, Responder};
use crate::noise::{Blake2b, ChaChaPoly, HandshakeError, Noise, Transport, pattern};
use crate::provider::DhProviderAsync;

/// Internal alias for the Noise protocol this seal is built on:
/// `Noise_N_P256_ChaChaPoly_BLAKE2b`. Not public API — the seal is internal
/// (an Apple-only key wrapper), so a suite-bound `N` is appropriate here.
type N = Noise<pattern::N, P256, ChaChaPoly, Blake2b>;

/// Size of the cleartext payload sealed by [`seal_32`] / [`open_32`].
pub(crate) const SEAL_PAYLOAD_SIZE: usize = 32;

/// Size of the Noise N msg1 (ephemeral key + empty payload tag).
pub(crate) const NOISE_N_MSG1_SIZE: usize = 81;

/// Size of the transport ciphertext (payload + AEAD tag).
const SEALED_TRANSPORT_SIZE: usize = SEAL_PAYLOAD_SIZE + Transport::<N>::OVERHEAD;

/// Total size of the sealed envelope: 129 bytes
/// (81-byte Noise N msg1 ‖ 48-byte transport ciphertext).
pub(crate) const SEALED_SIZE: usize = NOISE_N_MSG1_SIZE + SEALED_TRANSPORT_SIZE;

/// Errors that can occur while sealing or opening a 32-byte payload.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub(crate) enum SealError {
    /// The Noise N seal sequence failed.
    #[error("Noise N seal failed: {0}")]
    Seal(#[source] Box<HandshakeError>),
    /// The Noise N open sequence failed.
    #[error("Noise N open failed: {0}")]
    Open(#[source] Box<HandshakeError>),
}

/// Seal a 32-byte payload to `recipient_pub` using
/// `Noise_N_P256_ChaChaPoly_BLAKE2b`.
///
/// Each call generates a fresh ephemeral key (forward secrecy per
/// write). The returned 129-byte envelope is opaque to anyone without
/// the recipient's P-256 private key.
///
/// Runs the Noise-N initiator message (`e, es`) directly over the
/// shared crypto free functions — no type-state, no I/O driver.
pub(crate) async fn seal_32<P>(
    provider: P,
    recipient_pub: &P256r1PublicKey,
    payload: &[u8; SEAL_PAYLOAD_SIZE],
) -> Result<[u8; SEALED_SIZE], SealError>
where
    P: DhProviderAsync<P256>,
    <P256 as DhCurve>::SharedSecret: AsRef<[u8]>,
    <P256 as Curve>::PublicKey: AsRef<[u8]>,
{
    let seal = |e: HandshakeError| SealError::Seal(Box::new(e));

    let mut inner = HandshakeInner::new::<N>(provider, &[]);

    // Pre-message `<- s`: the recipient's static is our remote static.
    inner.symmetric.mix_hash(recipient_pub.as_ref());
    inner.rs = Some(*recipient_pub);

    // Noise N msg1: `e, es`, then the empty payload tag.
    let mut msg1 = [0u8; NOISE_N_MSG1_SIZE];
    {
        let mut buffer = SendBuffer::new(&mut msg1);
        send_e(&mut inner, &mut buffer).await.map_err(seal)?;
        do_es_initiator(&mut inner).await.map_err(seal)?;
        send_payload(&mut inner, &mut buffer, &[]).map_err(seal)?;
    }

    let mut transport = recv_to_transport::<N, Initiator, P>(inner);

    let mut sealed_transport = [0u8; SEALED_TRANSPORT_SIZE];
    let sealed_len = transport
        .send(payload, &mut sealed_transport)
        .map_err(seal)?;

    let mut blob = [0u8; SEALED_SIZE];
    blob[..NOISE_N_MSG1_SIZE].copy_from_slice(&msg1);
    blob[NOISE_N_MSG1_SIZE..NOISE_N_MSG1_SIZE + sealed_len]
        .copy_from_slice(&sealed_transport[..sealed_len]);

    Ok(blob)
}

/// Open a 129-byte sealed envelope using the recipient's private key.
///
/// Consumes the private key because the Noise handshake takes ownership
/// (private keys are intentionally non-cloneable). On Apple platforms
/// `recipient_key` is the Secure-Enclave-bound P-256 key
/// (non-exportable).
///
/// Runs the Noise-N responder message (`e, es`) directly over the
/// shared crypto free functions — no type-state, no I/O driver.
pub(crate) async fn open_32<P>(
    provider: P,
    recipient_key: P::PrivateKey,
    sealed: &[u8; SEALED_SIZE],
) -> Result<[u8; SEAL_PAYLOAD_SIZE], SealError>
where
    P: DhProviderAsync<P256>,
    <P256 as DhCurve>::SharedSecret: AsRef<[u8]>,
    <P256 as Curve>::PublicKey: AsRef<[u8]>,
{
    let open = |e: HandshakeError| SealError::Open(Box::new(e));

    let msg1 = &sealed[..NOISE_N_MSG1_SIZE];
    let ciphertext = &sealed[NOISE_N_MSG1_SIZE..];

    let mut inner = HandshakeInner::new::<N>(provider, &[]);

    // Pre-message `<- s`: our own static is known to the initiator, so
    // mix its public key into the hash and stash both halves.
    let s_pub = inner
        .provider
        .public_key(&recipient_key)
        .map_err(|e| SealError::Open(Box::new(HandshakeError::Crypto(Box::new(e)))))?;
    inner.symmetric.mix_hash(s_pub.as_ref());
    inner.s_pub = Some(s_pub);
    inner.s = Some(recipient_key);

    // Noise N msg1: read `e` (65 bytes), `es`, then verify the payload tag.
    let e_bytes = &msg1[..<P256 as Curve>::PUBLIC_KEY_SIZE];
    let tag = &msg1[<P256 as Curve>::PUBLIC_KEY_SIZE..];
    {
        let mut e_buffer = RecvBuffer::new(e_bytes);
        recv_e(&mut inner, &mut e_buffer).map_err(open)?;
    }
    do_es_responder(&mut inner).await.map_err(open)?;
    {
        let mut tag_buffer = RecvBuffer::new(tag);
        recv_payload(&mut inner, &mut tag_buffer, &mut []).map_err(open)?;
    }

    let mut transport = recv_to_transport::<N, Responder, P>(inner);

    let mut payload = [0u8; SEAL_PAYLOAD_SIZE];
    transport.receive(ciphertext, &mut payload).map_err(open)?;

    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curve::p256::P256r1PrivateKey;
    use crate::provider::EphemeralOnly;
    use rand::{SeedableRng, rngs::StdRng};

    #[tokio::test]
    async fn seal_open_round_trip() {
        let device_key = P256r1PrivateKey::generate(rand::rng()).unwrap();
        let device_pub = device_key.public();
        let payload: [u8; 32] = [0x42; 32];

        let sealed = seal_32(
            EphemeralOnly::new(StdRng::from_os_rng()),
            &device_pub,
            &payload,
        )
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

        let opened = open_32(
            EphemeralOnly::new(StdRng::from_os_rng()),
            device_key,
            &sealed,
        )
        .await
        .unwrap();
        assert_eq!(opened, payload);
    }

    #[tokio::test]
    async fn open_with_wrong_key_fails() {
        let device_key = P256r1PrivateKey::generate(rand::rng()).unwrap();
        let device_pub = device_key.public();
        let payload: [u8; 32] = [0x99; 32];
        let sealed = seal_32(
            EphemeralOnly::new(StdRng::from_os_rng()),
            &device_pub,
            &payload,
        )
        .await
        .unwrap();

        let other_key = P256r1PrivateKey::generate(rand::rng()).unwrap();
        let result = open_32(
            EphemeralOnly::new(StdRng::from_os_rng()),
            other_key,
            &sealed,
        )
        .await;
        assert!(
            matches!(result, Err(SealError::Open(_))),
            "opening with wrong key must fail",
        );
    }

    #[tokio::test]
    async fn fresh_ephemeral_per_seal() {
        let device_key = P256r1PrivateKey::generate(rand::rng()).unwrap();
        let device_pub = device_key.public();
        let payload: [u8; 32] = [0xAB; 32];

        let sealed_a = seal_32(
            EphemeralOnly::new(StdRng::from_os_rng()),
            &device_pub,
            &payload,
        )
        .await
        .unwrap();
        let sealed_b = seal_32(
            EphemeralOnly::new(StdRng::from_os_rng()),
            &device_pub,
            &payload,
        )
        .await
        .unwrap();

        // Different ephemeral key each time → different blobs even
        // for identical payload + recipient.
        assert_ne!(sealed_a, sealed_b);
    }

    /// Frozen 129-byte byte-format pin.
    ///
    /// The sealed envelope is stored verbatim in the Keychain, so its
    /// layout must never shift. With a fixed recipient key and a fixed
    /// (deterministic) ephemeral RNG, the whole 129-byte blob is fully
    /// determined and pinned here. A change to the wire layout, the
    /// protocol name, the KDF, or the transport framing would break
    /// this and surface as a hard failure rather than a silent
    /// Keychain-incompatibility in the field.
    #[tokio::test]
    async fn seal_format_pin() {
        // Fixed recipient P-256 key (deterministic scalar).
        let recipient_key = P256r1PrivateKey::from_bytes([0x07; 32]).unwrap();
        let recipient_pub = recipient_key.public();
        let payload: [u8; 32] = [0x11; 32];

        // Fixed-seed RNG → deterministic ephemeral key → deterministic blob.
        let sealed = seal_32(
            EphemeralOnly::new(StdRng::seed_from_u64(0xA5A5_5A5A_DEAD_BEEF)),
            &recipient_pub,
            &payload,
        )
        .await
        .unwrap();

        const EXPECTED: [u8; SEALED_SIZE] = SEAL_FORMAT_PIN;
        assert_eq!(
            sealed, EXPECTED,
            "frozen 129-byte seal envelope changed — Keychain format would break",
        );

        // Round-trips back to the original payload.
        let opened = open_32(
            EphemeralOnly::new(StdRng::from_os_rng()),
            recipient_key,
            &sealed,
        )
        .await
        .unwrap();
        assert_eq!(opened, payload);
    }

    // The frozen reference blob, captured from the deterministic seal
    // above. See `seal_format_pin`.
    #[rustfmt::skip]
    const SEAL_FORMAT_PIN: [u8; SEALED_SIZE] = [
        0x04, 0x8c, 0x0b, 0x89, 0xb3, 0x75, 0x88, 0x5b, 0x4e, 0xc0, 0x9b, 0x36, 0x63, 0x6d, 0xc9, 0x28,
        0x2a, 0x1d, 0x87, 0xe8, 0xa1, 0xea, 0x86, 0x7e, 0x05, 0xa0, 0x99, 0x98, 0x94, 0xd9, 0x2a, 0x48,
        0x01, 0x74, 0x4c, 0xba, 0x76, 0x25, 0x6f, 0x56, 0xb1, 0x97, 0xf3, 0xcf, 0x93, 0x8e, 0xed, 0x44,
        0x55, 0x13, 0x21, 0xee, 0x0c, 0x09, 0xeb, 0x22, 0xff, 0x2a, 0x5e, 0xba, 0x4b, 0x2d, 0xb5, 0x82,
        0x37, 0x22, 0x12, 0xf2, 0x1e, 0xfe, 0xbe, 0x3e, 0xd7, 0xc0, 0xae, 0xa4, 0xac, 0x0c, 0xf4, 0xec,
        0x9d, 0x23, 0x23, 0x5f, 0xc4, 0xc5, 0x7d, 0xd9, 0x81, 0xeb, 0xc6, 0xf0, 0xd5, 0x9d, 0x08, 0xb9,
        0x8b, 0x8d, 0x50, 0xc3, 0x82, 0x86, 0xd1, 0x42, 0x05, 0x01, 0xc0, 0xa8, 0xe6, 0xd1, 0x41, 0xd7,
        0x18, 0x10, 0x0e, 0x8b, 0xa1, 0xe6, 0x11, 0x1c, 0xee, 0xa0, 0xf7, 0x6c, 0x3a, 0x17, 0x44, 0xf0,
        0xeb,
    ];
}
