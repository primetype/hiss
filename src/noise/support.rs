//! Support surface for `hiss-macros`-generated handshake code.
//!
//! **Not public API.** Everything in this module is `#[doc(hidden)]` and
//! exists only so that the code emitted by the `noise!` macro — which
//! expands *inside the caller's crate* — can reach the crate-private
//! handshake engine ([`HandshakeInner`], the per-token crypto in the
//! private `process` module). Semver does not cover this module; it
//! moves in lockstep with `hiss-macros`.
//!
//! # Shape
//!
//! The macro generates *sans-io* state machines: every handshake message
//! is a caller-visible `[u8; N]` whose size the macro derives from the
//! [`WireSize`](super::tokens::WireSize) consts. The helpers here
//! therefore speak plain byte slices — the send-side helpers write into
//! `&mut [u8]` and return the byte count written, the receive-side
//! helpers parse from `&[u8]` and return the byte count consumed —
//! rather than owning any I/O.
//!
//! The synchronous DH helpers (`ee`/`es_*`/`se_*`/`ss`) live here; the
//! provider-free token crypto is delegated to the private `process`
//! module.
//!
//! # An error is terminal
//!
//! These helpers mutate the symmetric state in place; the contract is the
//! same as in the private `process` module: a step that returns `Err`
//! leaves the handshake half-advanced and it **must be dropped**. The
//! macro-generated states enforce this by ownership — every token method
//! consumes `self`.

use super::Protocol;
use super::buffers::{RecvBuffer, SendBuffer};
use super::cipher::Cipher;
use super::error::HandshakeError;
use super::hash::Hash;
use super::process;
use super::role::Role;
use super::transport::Transport;
use crate::curve::{Curve, DhCurve};
use crate::provider::{CryptoKeyProvider, DhProvider};

#[doc(hidden)]
pub use super::handshake::HandshakeInner;

// ═══════════════════════════════════════════════════════════════
//  Construction and pre-messages
// ═══════════════════════════════════════════════════════════════

/// Build the runtime handshake state for `Proto`, mixing the prologue.
#[doc(hidden)]
pub fn new_handshake<Proto, CP>(
    provider: CP,
    prologue: &[u8],
) -> HandshakeInner<Proto::Curve, Proto::Cipher, Proto::Hash, CP>
where
    Proto: Protocol,
    CP: CryptoKeyProvider<Proto::Curve>,
{
    HandshakeInner::new::<Proto>(provider, prologue)
}

/// Pre-message: record the remote party's static public key.
#[doc(hidden)]
pub fn set_rs<Cu, Ci, H, CP>(
    inner: &mut HandshakeInner<Cu, Ci, H, CP>,
    remote_static: Cu::PublicKey,
) where
    Cu: Curve,
    Cu::PublicKey: AsRef<[u8]>,
    Ci: Cipher,
    H: Hash,
    CP: CryptoKeyProvider<Cu>,
{
    inner.symmetric.mix_hash(remote_static.as_ref());
    inner.rs = Some(remote_static);
}

/// Pre-message: record our local static key (deriving its public half).
#[doc(hidden)]
pub fn set_s<Cu, Ci, H, CP>(
    inner: &mut HandshakeInner<Cu, Ci, H, CP>,
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
    inner.symmetric.mix_hash(s_pub.as_ref());
    inner.s_pub = Some(s_pub);
    inner.s = Some(static_key);
    Ok(())
}

// ═══════════════════════════════════════════════════════════════
//  Mid-handshake observers
// ═══════════════════════════════════════════════════════════════

/// Our ephemeral public key, once an `e` token has generated it.
#[doc(hidden)]
pub fn local_ephemeral<Cu, Ci, H, CP>(
    inner: &HandshakeInner<Cu, Ci, H, CP>,
) -> Option<&Cu::PublicKey>
where
    Cu: Curve,
    Ci: Cipher,
    H: Hash,
    CP: CryptoKeyProvider<Cu>,
{
    inner.e_pub.as_ref()
}

/// The peer's ephemeral public key, once an `e` token has read it.
#[doc(hidden)]
pub fn remote_ephemeral<Cu, Ci, H, CP>(
    inner: &HandshakeInner<Cu, Ci, H, CP>,
) -> Option<&Cu::PublicKey>
where
    Cu: Curve,
    Ci: Cipher,
    H: Hash,
    CP: CryptoKeyProvider<Cu>,
{
    inner.re.as_ref()
}

/// The peer's static public key, once a pre-message or an `s` token has
/// established it.
#[doc(hidden)]
pub fn remote_static<Cu, Ci, H, CP>(inner: &HandshakeInner<Cu, Ci, H, CP>) -> Option<&Cu::PublicKey>
where
    Cu: Curve,
    Ci: Cipher,
    H: Hash,
    CP: CryptoKeyProvider<Cu>,
{
    inner.rs.as_ref()
}

// ═══════════════════════════════════════════════════════════════
//  Wire tokens — write into / read from caller-provided slices
// ═══════════════════════════════════════════════════════════════

/// `e` (send): generate our ephemeral, mix it, write its public key into
/// `out`. Returns the byte count written.
#[doc(hidden)]
pub fn send_e<Cu, Ci, H, CP>(
    inner: &mut HandshakeInner<Cu, Ci, H, CP>,
    out: &mut [u8],
) -> Result<usize, HandshakeError>
where
    Cu: DhCurve,
    Cu::PublicKey: AsRef<[u8]>,
    Ci: Cipher,
    H: Hash,
    CP: CryptoKeyProvider<Cu>,
{
    let e = inner
        .provider
        .generate_ephemeral_key()
        .map_err(|e| HandshakeError::Crypto(Box::new(e)))?;
    let e_pub = inner
        .provider
        .public_key(&e)
        .map_err(|e| HandshakeError::Crypto(Box::new(e)))?;
    let mut buffer = SendBuffer::new(out);
    buffer.write(e_pub.as_ref());
    inner.symmetric.mix_hash(e_pub.as_ref());
    if inner.has_psk {
        inner.symmetric.mix_key(e_pub.as_ref());
    }
    inner.e = Some(e);
    inner.e_pub = Some(e_pub);
    Ok(buffer.finish().len())
}

/// `s` (send): encrypt-and-hash our static public key into `out`.
/// Returns the byte count written.
#[doc(hidden)]
pub fn send_s<Cu, Ci, H, CP>(
    inner: &mut HandshakeInner<Cu, Ci, H, CP>,
    out: &mut [u8],
    static_key: CP::PrivateKey,
) -> Result<usize, HandshakeError>
where
    Cu: Curve,
    Cu::PublicKey: AsRef<[u8]>,
    Ci: Cipher,
    H: Hash,
    CP: CryptoKeyProvider<Cu>,
{
    let mut buffer = SendBuffer::new(out);
    process::send_s(inner, &mut buffer, static_key)?;
    Ok(buffer.finish().len())
}

/// `e` (recv): parse and mix the remote ephemeral from `input`.
/// Returns the revealed key and the byte count consumed.
#[doc(hidden)]
pub fn recv_e<Cu, Ci, H, CP>(
    inner: &mut HandshakeInner<Cu, Ci, H, CP>,
    input: &[u8],
) -> Result<(Cu::PublicKey, usize), HandshakeError>
where
    Cu: Curve,
    Cu::PublicKey: AsRef<[u8]>,
    Ci: Cipher,
    H: Hash,
    CP: CryptoKeyProvider<Cu>,
{
    let mut buffer = RecvBuffer::new(input);
    let re = process::recv_e(inner, &mut buffer)?;
    let consumed = input.len() - buffer.remaining().len();
    Ok((re, consumed))
}

/// `s` (recv): parse, decrypt, and mix the remote static from `input`.
/// Returns the revealed key and the byte count consumed.
#[doc(hidden)]
pub fn recv_s<Cu, Ci, H, CP>(
    inner: &mut HandshakeInner<Cu, Ci, H, CP>,
    input: &[u8],
) -> Result<(Cu::PublicKey, usize), HandshakeError>
where
    Cu: Curve,
    Cu::PublicKey: AsRef<[u8]>,
    Ci: Cipher,
    H: Hash,
    CP: CryptoKeyProvider<Cu>,
{
    let mut buffer = RecvBuffer::new(input);
    let rs = process::recv_s(inner, &mut buffer)?;
    let consumed = input.len() - buffer.remaining().len();
    Ok((rs, consumed))
}

// ═══════════════════════════════════════════════════════════════
//  DH tokens — synchronous provider calls, no wire bytes
// ═══════════════════════════════════════════════════════════════

/// Initiator `es`: mix `DH(e, rs)`.
#[doc(hidden)]
pub fn es_initiator<Cu, Ci, H, CP>(
    inner: &mut HandshakeInner<Cu, Ci, H, CP>,
) -> Result<(), HandshakeError>
where
    Cu: DhCurve,
    Cu::SharedSecret: AsRef<[u8]>,
    Ci: Cipher,
    H: Hash,
    CP: DhProvider<Cu>,
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
        .dh(e, rs)
        .map_err(|e| HandshakeError::Crypto(Box::new(e)))?;
    inner.symmetric.mix_key(ss.as_ref());
    Ok(())
}

/// Responder `es`: mix `DH(s, re)`.
#[doc(hidden)]
pub fn es_responder<Cu, Ci, H, CP>(
    inner: &mut HandshakeInner<Cu, Ci, H, CP>,
) -> Result<(), HandshakeError>
where
    Cu: DhCurve,
    Cu::SharedSecret: AsRef<[u8]>,
    Ci: Cipher,
    H: Hash,
    CP: DhProvider<Cu>,
{
    let s = inner.s.as_ref().ok_or(HandshakeError::MissingStaticKey)?;
    let re = inner
        .re
        .as_ref()
        .ok_or(HandshakeError::MissingRemoteEphemeral)?;
    let ss = inner
        .provider
        .dh(s, re)
        .map_err(|e| HandshakeError::Crypto(Box::new(e)))?;
    inner.symmetric.mix_key(ss.as_ref());
    Ok(())
}

/// `ee`: mix `DH(e, re)` (role-independent).
#[doc(hidden)]
pub fn ee<Cu, Ci, H, CP>(inner: &mut HandshakeInner<Cu, Ci, H, CP>) -> Result<(), HandshakeError>
where
    Cu: DhCurve,
    Cu::SharedSecret: AsRef<[u8]>,
    Ci: Cipher,
    H: Hash,
    CP: DhProvider<Cu>,
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
        .dh(e, re)
        .map_err(|e| HandshakeError::Crypto(Box::new(e)))?;
    inner.symmetric.mix_key(ss.as_ref());
    Ok(())
}

/// Initiator `se`: mix `DH(s, re)`.
#[doc(hidden)]
pub fn se_initiator<Cu, Ci, H, CP>(
    inner: &mut HandshakeInner<Cu, Ci, H, CP>,
) -> Result<(), HandshakeError>
where
    Cu: DhCurve,
    Cu::SharedSecret: AsRef<[u8]>,
    Ci: Cipher,
    H: Hash,
    CP: DhProvider<Cu>,
{
    let s = inner.s.as_ref().ok_or(HandshakeError::MissingStaticKey)?;
    let re = inner
        .re
        .as_ref()
        .ok_or(HandshakeError::MissingRemoteEphemeral)?;
    let ss = inner
        .provider
        .dh(s, re)
        .map_err(|e| HandshakeError::Crypto(Box::new(e)))?;
    inner.symmetric.mix_key(ss.as_ref());
    Ok(())
}

/// Responder `se`: mix `DH(e, rs)`.
#[doc(hidden)]
pub fn se_responder<Cu, Ci, H, CP>(
    inner: &mut HandshakeInner<Cu, Ci, H, CP>,
) -> Result<(), HandshakeError>
where
    Cu: DhCurve,
    Cu::SharedSecret: AsRef<[u8]>,
    Ci: Cipher,
    H: Hash,
    CP: DhProvider<Cu>,
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
        .dh(e, rs)
        .map_err(|e| HandshakeError::Crypto(Box::new(e)))?;
    inner.symmetric.mix_key(ss.as_ref());
    Ok(())
}

/// `ss`: mix `DH(s, rs)` (role-independent).
#[doc(hidden)]
pub fn ss<Cu, Ci, H, CP>(inner: &mut HandshakeInner<Cu, Ci, H, CP>) -> Result<(), HandshakeError>
where
    Cu: DhCurve,
    Cu::SharedSecret: AsRef<[u8]>,
    Ci: Cipher,
    H: Hash,
    CP: DhProvider<Cu>,
{
    let s = inner.s.as_ref().ok_or(HandshakeError::MissingStaticKey)?;
    let rs = inner
        .rs
        .as_ref()
        .ok_or(HandshakeError::MissingRemoteStatic)?;
    let ss = inner
        .provider
        .dh(s, rs)
        .map_err(|e| HandshakeError::Crypto(Box::new(e)))?;
    inner.symmetric.mix_key(ss.as_ref());
    Ok(())
}

/// `psk`: mix the pre-shared key (no wire bytes).
#[doc(hidden)]
pub fn psk<Cu, Ci, H, CP>(
    inner: &mut HandshakeInner<Cu, Ci, H, CP>,
    psk: &crate::psk::Psk,
) -> Result<(), HandshakeError>
where
    Cu: Curve,
    Ci: Cipher,
    H: Hash,
    CP: CryptoKeyProvider<Cu>,
{
    process::do_psk(inner, psk)
}

// ═══════════════════════════════════════════════════════════════
//  Message tails and finalisation
// ═══════════════════════════════════════════════════════════════

/// Close an outgoing message: encrypt-and-hash `payload` (the message's
/// declared application payload; empty for a payload-free message) into
/// `out` — its ciphertext plus a `TAG_SIZE` tag when keyed, the bare
/// payload bytes otherwise. Returns the byte count written.
#[doc(hidden)]
pub fn send_tail<Cu, Ci, H, CP>(
    inner: &mut HandshakeInner<Cu, Ci, H, CP>,
    out: &mut [u8],
    payload: &[u8],
) -> Result<usize, HandshakeError>
where
    Cu: Curve,
    Ci: Cipher,
    H: Hash,
    CP: CryptoKeyProvider<Cu>,
{
    let mut buffer = SendBuffer::new(out);
    process::send_payload(inner, &mut buffer, payload)?;
    Ok(buffer.finish().len())
}

/// Close an incoming message: decrypt the trailing payload into
/// `payload_out` (empty for a payload-free message, making the tail the
/// bare tag), consuming all of `input` and verifying the tag where one
/// exists. On a failed tag the cipher zeroes `payload_out` before the
/// error returns.
#[doc(hidden)]
pub fn recv_tail<Cu, Ci, H, CP>(
    inner: &mut HandshakeInner<Cu, Ci, H, CP>,
    input: &[u8],
    payload_out: &mut [u8],
) -> Result<(), HandshakeError>
where
    Cu: Curve,
    Ci: Cipher,
    H: Hash,
    CP: CryptoKeyProvider<Cu>,
{
    let mut buffer = RecvBuffer::new(input);
    process::recv_payload(inner, &mut buffer, payload_out)
}

/// Split the completed handshake into the post-handshake [`Transport`].
#[doc(hidden)]
pub fn into_transport<Proto, R, CP>(
    inner: HandshakeInner<Proto::Curve, Proto::Cipher, Proto::Hash, CP>,
) -> Transport<Proto>
where
    Proto: Protocol,
    R: Role,
    CP: CryptoKeyProvider<Proto::Curve>,
{
    process::recv_to_transport::<Proto, R, CP>(inner)
}
