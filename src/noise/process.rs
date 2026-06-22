//! Shared per-token crypto for the handshake drivers.
//!
//! These provider-driven free functions perform the Noise per-token
//! cryptography on the runtime [`HandshakeInner`] state. The async
//! driver (`AsyncHandshake` (feature `async-io`)) and the
//! internal seal helpers ([`seal`](super::seal)) call them directly; the
//! blocking driver ([`SyncHandshake`](super::io_sync::SyncHandshake))
//! reuses the provider-free helpers here (`recv_e`/`recv_s`/`send_s`/
//! `send_payload`/`recv_payload`/`do_psk`/`recv_to_transport`) and has
//! its own synchronous mirrors of the DH/ephemeral steps that call the
//! provider.
//!
//! Each function reads/writes the borrowed [`SendBuffer`]/[`RecvBuffer`]
//! scratch the driver hands it, and threads the symmetric state forward.
//! Role-dependent DH tokens (`Es`, `Se`) have separate
//! initiator/responder functions.

use super::Protocol;
use super::buffers::{RecvBuffer, SendBuffer};
use super::cipher::Cipher;
use super::error::HandshakeError;
use super::handshake::HandshakeInner;
use super::hash::Hash;
use super::role::Role;
use super::transport::Transport;
use crate::curve::{Curve, DhCurve};
use crate::provider::{CryptoKeyProvider, DhProviderAsync};

// ═══════════════════════════════════════════════════════════════
//  Payload helpers — EncryptAndHash("") / DecryptAndHash("")
// ═══════════════════════════════════════════════════════════════
//
// The Noise spec requires calling EncryptAndHash(payload) after
// processing all tokens in each handshake message. Even with an
// empty payload, a keyed cipher state produces a TAG_SIZE-byte
// authentication tag that is appended to the message and mixed
// into the handshake hash.

/// Encrypt the empty payload at the end of a send message.
///
/// When keyed, reserves `TAG_SIZE` bytes in the buffer for the
/// authentication tag. When unkeyed, this is effectively a no-op
/// (mix_hash of empty).
pub(crate) fn send_payload<Cu, Ci, H, CP>(
    inner: &mut HandshakeInner<Cu, Ci, H, CP>,
    buffer: &mut SendBuffer<'_>,
) -> Result<(), HandshakeError>
where
    Cu: Curve,
    Ci: Cipher,
    H: Hash,
    CP: CryptoKeyProvider<Cu>,
{
    let tag_len = if inner.symmetric.has_key() {
        Ci::TAG_SIZE
    } else {
        0
    };
    let output = buffer.reserve(tag_len);
    inner.symmetric.encrypt_and_hash(&[], output)?;
    Ok(())
}

/// Decrypt the empty payload at the end of a receive message.
///
/// Consumes remaining bytes (TAG_SIZE when keyed, 0 when unkeyed)
/// and verifies the authentication tag.
pub(crate) fn recv_payload<Cu, Ci, H, CP>(
    inner: &mut HandshakeInner<Cu, Ci, H, CP>,
    buffer: &mut RecvBuffer<'_>,
) -> Result<(), HandshakeError>
where
    Cu: Curve,
    Ci: Cipher,
    H: Hash,
    CP: CryptoKeyProvider<Cu>,
{
    let remaining_len = buffer.remaining().len();
    let tag = buffer.read(remaining_len)?;
    inner.symmetric.decrypt_and_hash(tag, &mut [])?;
    Ok(())
}

// ═══════════════════════════════════════════════════════════════
//  Finalization
// ═══════════════════════════════════════════════════════════════

/// Split the symmetric state into the post-handshake [`Transport`].
///
/// Called by both drivers (and the seal helpers) once the final token
/// of the last message has been processed.
pub(crate) fn recv_to_transport<Proto, R, CP>(
    inner: HandshakeInner<Proto::Curve, Proto::Cipher, Proto::Hash, CP>,
) -> Transport<Proto>
where
    Proto: Protocol,
    R: Role,
    CP: CryptoKeyProvider<Proto::Curve>,
{
    let session_id = inner.symmetric.handshake_hash().to_vec().into();
    let local_e = inner.e_pub;
    let remote_e = inner.re;
    let (c1, c2) = inner.symmetric.split();
    if R::IS_INITIATOR {
        Transport::new(c1, c2, session_id, local_e, remote_e)
    } else {
        Transport::new(c2, c1, session_id, local_e, remote_e)
    }
}

// ═══════════════════════════════════════════════════════════════
//  Shared token logic
// ═══════════════════════════════════════════════════════════════

pub(crate) async fn send_e<Cu, Ci, H, CP>(
    inner: &mut HandshakeInner<Cu, Ci, H, CP>,
    buffer: &mut SendBuffer<'_>,
) -> Result<Cu::PublicKey, HandshakeError>
where
    Cu: DhCurve,
    Cu::PublicKey: AsRef<[u8]>,
    Ci: Cipher,
    H: Hash,
    CP: DhProviderAsync<Cu>,
{
    let e = inner
        .provider
        .generate_ephemeral_key_async()
        .await
        .map_err(|e| HandshakeError::Crypto(Box::new(e)))?;
    let e_pub = inner
        .provider
        .public_key(&e)
        .map_err(|e| HandshakeError::Crypto(Box::new(e)))?;
    buffer.write(e_pub.as_ref());
    inner.symmetric.mix_hash(e_pub.as_ref());
    if inner.has_psk {
        inner.symmetric.mix_key(e_pub.as_ref());
    }
    inner.e = Some(e);
    inner.e_pub = Some(e_pub.clone());
    Ok(e_pub)
}

pub(crate) fn recv_e<Cu, Ci, H, CP>(
    inner: &mut HandshakeInner<Cu, Ci, H, CP>,
    buffer: &mut RecvBuffer<'_>,
) -> Result<Cu::PublicKey, HandshakeError>
where
    Cu: Curve,
    Cu::PublicKey: AsRef<[u8]>,
    Ci: Cipher,
    H: Hash,
    CP: CryptoKeyProvider<Cu>,
{
    let bytes = buffer.read(Cu::PUBLIC_KEY_SIZE)?;
    let re = Cu::public_key_from_bytes(bytes)
        .map_err(|e| HandshakeError::InvalidPublicKey(Box::new(e)))?;
    // Reject any non-canonical on-wire encoding: a conformant peer sends
    // exactly the canonical form, so the re-serialized key must equal the
    // wire bytes. For curves with a single encoding this always holds; for
    // P-256 it rejects compressed / trailing-garbage encodings. Also makes
    // the receive transcript symmetric with the send path (which mixes the
    // canonical bytes).
    if re.as_ref() != bytes {
        return Err(HandshakeError::NonCanonicalPublicKey);
    }
    inner.symmetric.mix_hash(re.as_ref());
    if inner.has_psk {
        inner.symmetric.mix_key(re.as_ref());
    }
    let revealed = re.clone();
    inner.re = Some(re);
    Ok(revealed)
}

pub(crate) fn send_s<Cu, Ci, H, CP>(
    inner: &mut HandshakeInner<Cu, Ci, H, CP>,
    buffer: &mut SendBuffer<'_>,
    static_key: CP::PrivateKey,
) -> Result<(), HandshakeError>
where
    Cu: Curve,
    Cu::PublicKey: AsRef<[u8]>,
    Ci: Cipher,
    H: Hash,
    CP: CryptoKeyProvider<Cu>,
{
    let s_pub = inner
        .provider
        .public_key(&static_key)
        .map_err(|e| HandshakeError::Crypto(Box::new(e)))?;
    let out_len = if inner.symmetric.has_key() {
        Cu::PUBLIC_KEY_SIZE + Ci::TAG_SIZE
    } else {
        Cu::PUBLIC_KEY_SIZE
    };
    let output = buffer.reserve(out_len);
    inner.symmetric.encrypt_and_hash(s_pub.as_ref(), output)?;
    inner.s_pub = Some(s_pub);
    inner.s = Some(static_key);
    Ok(())
}

pub(crate) fn recv_s<Cu, Ci, H, CP>(
    inner: &mut HandshakeInner<Cu, Ci, H, CP>,
    buffer: &mut RecvBuffer<'_>,
) -> Result<Cu::PublicKey, HandshakeError>
where
    Cu: Curve,
    Cu::PublicKey: AsRef<[u8]>,
    Ci: Cipher,
    H: Hash,
    CP: CryptoKeyProvider<Cu>,
{
    let wire_len = if inner.symmetric.has_key() {
        Cu::PUBLIC_KEY_SIZE + Ci::TAG_SIZE
    } else {
        Cu::PUBLIC_KEY_SIZE
    };
    let ciphertext = buffer.read(wire_len)?;
    // Public key size is bounded — stack-allocate the output.
    const {
        assert!(
            Cu::PUBLIC_KEY_SIZE + Ci::TAG_SIZE <= 128,
            "curve public key + AEAD tag exceeds the 128-byte scratch buffer"
        )
    };
    let mut pk_buf = [0u8; 128];
    let pt_len = inner.symmetric.decrypt_and_hash(ciphertext, &mut pk_buf)?;
    let rs = Cu::public_key_from_bytes(&pk_buf[..pt_len])
        .map_err(|e| HandshakeError::InvalidPublicKey(Box::new(e)))?;
    // Reject any non-canonical on-wire encoding (see `recv_e`). The static
    // key is bound to the transcript via its ciphertext in
    // `decrypt_and_hash` above, which is unchanged; this only rejects a
    // decrypted key whose re-serialised form differs from the wire bytes.
    if rs.as_ref() != &pk_buf[..pt_len] {
        return Err(HandshakeError::NonCanonicalPublicKey);
    }
    let revealed = rs.clone();
    inner.rs = Some(rs);
    Ok(revealed)
}

// `do_ee` / `do_se_*` / `do_ss` are consumed only by the async driver
// (`io_async`); the seal helpers use `send_e` + `do_es_*` and the sync
// driver mirrors the DH steps itself. Gate them to the async-io feature
// so a default build does not carry dead code.
#[cfg(feature = "async-io")]
pub(crate) async fn do_ee<Cu, Ci, H, CP>(
    inner: &mut HandshakeInner<Cu, Ci, H, CP>,
) -> Result<(), HandshakeError>
where
    Cu: DhCurve,
    Cu::SharedSecret: AsRef<[u8]>,
    Ci: Cipher,
    H: Hash,
    CP: DhProviderAsync<Cu>,
{
    let e = inner
        .e
        .as_ref()
        .ok_or(HandshakeError::MissingEphemeralKey)?;
    let re = inner
        .re
        .as_ref()
        .ok_or(HandshakeError::MissingRemoteEphemeral)?;
    let ss = inner
        .provider
        .dh_async(e, re)
        .await
        .map_err(|e| HandshakeError::Crypto(Box::new(e)))?;
    inner.symmetric.mix_key(ss.as_ref());
    Ok(())
}

pub(crate) async fn do_es_initiator<Cu, Ci, H, CP>(
    inner: &mut HandshakeInner<Cu, Ci, H, CP>,
) -> Result<(), HandshakeError>
where
    Cu: DhCurve,
    Cu::SharedSecret: AsRef<[u8]>,
    Ci: Cipher,
    H: Hash,
    CP: DhProviderAsync<Cu>,
{
    let e = inner
        .e
        .as_ref()
        .ok_or(HandshakeError::MissingEphemeralKey)?;
    let rs = inner
        .rs
        .as_ref()
        .ok_or(HandshakeError::MissingRemoteStatic)?;
    let ss = inner
        .provider
        .dh_async(e, rs)
        .await
        .map_err(|e| HandshakeError::Crypto(Box::new(e)))?;
    inner.symmetric.mix_key(ss.as_ref());
    Ok(())
}

pub(crate) async fn do_es_responder<Cu, Ci, H, CP>(
    inner: &mut HandshakeInner<Cu, Ci, H, CP>,
) -> Result<(), HandshakeError>
where
    Cu: DhCurve,
    Cu::SharedSecret: AsRef<[u8]>,
    Ci: Cipher,
    H: Hash,
    CP: DhProviderAsync<Cu>,
{
    let s = inner.s.as_ref().ok_or(HandshakeError::MissingStaticKey)?;
    let re = inner
        .re
        .as_ref()
        .ok_or(HandshakeError::MissingRemoteEphemeral)?;
    let ss = inner
        .provider
        .dh_async(s, re)
        .await
        .map_err(|e| HandshakeError::Crypto(Box::new(e)))?;
    inner.symmetric.mix_key(ss.as_ref());
    Ok(())
}

#[cfg(feature = "async-io")]
pub(crate) async fn do_se_initiator<Cu, Ci, H, CP>(
    inner: &mut HandshakeInner<Cu, Ci, H, CP>,
) -> Result<(), HandshakeError>
where
    Cu: DhCurve,
    Cu::SharedSecret: AsRef<[u8]>,
    Ci: Cipher,
    H: Hash,
    CP: DhProviderAsync<Cu>,
{
    let s = inner.s.as_ref().ok_or(HandshakeError::MissingStaticKey)?;
    let re = inner
        .re
        .as_ref()
        .ok_or(HandshakeError::MissingRemoteEphemeral)?;
    let ss = inner
        .provider
        .dh_async(s, re)
        .await
        .map_err(|e| HandshakeError::Crypto(Box::new(e)))?;
    inner.symmetric.mix_key(ss.as_ref());
    Ok(())
}

#[cfg(feature = "async-io")]
pub(crate) async fn do_se_responder<Cu, Ci, H, CP>(
    inner: &mut HandshakeInner<Cu, Ci, H, CP>,
) -> Result<(), HandshakeError>
where
    Cu: DhCurve,
    Cu::SharedSecret: AsRef<[u8]>,
    Ci: Cipher,
    H: Hash,
    CP: DhProviderAsync<Cu>,
{
    let e = inner
        .e
        .as_ref()
        .ok_or(HandshakeError::MissingEphemeralKey)?;
    let rs = inner
        .rs
        .as_ref()
        .ok_or(HandshakeError::MissingRemoteStatic)?;
    let ss = inner
        .provider
        .dh_async(e, rs)
        .await
        .map_err(|e| HandshakeError::Crypto(Box::new(e)))?;
    inner.symmetric.mix_key(ss.as_ref());
    Ok(())
}

#[cfg(feature = "async-io")]
pub(crate) async fn do_ss<Cu, Ci, H, CP>(
    inner: &mut HandshakeInner<Cu, Ci, H, CP>,
) -> Result<(), HandshakeError>
where
    Cu: DhCurve,
    Cu::SharedSecret: AsRef<[u8]>,
    Ci: Cipher,
    H: Hash,
    CP: DhProviderAsync<Cu>,
{
    let s = inner.s.as_ref().ok_or(HandshakeError::MissingStaticKey)?;
    let rs = inner
        .rs
        .as_ref()
        .ok_or(HandshakeError::MissingRemoteStatic)?;
    let ss = inner
        .provider
        .dh_async(s, rs)
        .await
        .map_err(|e| HandshakeError::Crypto(Box::new(e)))?;
    inner.symmetric.mix_key(ss.as_ref());
    Ok(())
}

pub(crate) fn do_psk<Cu, Ci, H, CP>(
    inner: &mut HandshakeInner<Cu, Ci, H, CP>,
    psk: &crate::psk::Psk,
) -> Result<(), HandshakeError>
where
    Cu: Curve,
    Ci: Cipher,
    H: Hash,
    CP: CryptoKeyProvider<Cu>,
{
    inner.symmetric.mix_key_and_hash(psk.as_bytes());
    Ok(())
}
