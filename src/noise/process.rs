//! Per-token method implementations on [`Sending`] and [`Receiving`].
//!
//! Each token (`E`, `S`, `Es`, `Ee`, `Se`, `Psk`) gets method
//! implementations with **three non-overlapping return types** per
//! context (send/recv):
//!
//! 1. More tokens remain in this message → return the same wrapper
//!    with the token consumed from the Cons-list.
//! 2. Last token in this message, more messages remain → return
//!    next `HandshakeState` (send also yields `&[u8]`).
//! 3. Last token in the last message → return `Transport`
//!    (send also yields `&[u8]`).
//!
//! On the receiving side no bytes are returned — the caller already
//! provided them via `read(&msg)`. Revealing tokens (`E`, `S`)
//! additionally return the revealed `PublicKey`.
//!
//! Role-dependent DH tokens (`Es`, `Se`) have separate impls for
//! [`Initiator`] and [`Responder`].

use super::Protocol;
use super::buffers::{RecvBuffer, SendBuffer};
use super::cipher::Cipher;
use super::error::HandshakeError;
use super::handshake::{HandshakeInner, HandshakeState, Receiving, Sending};
use super::hash::Hash;
use super::role::{Initiator, Responder, Role};
use super::tokens::*;
use super::transport::Transport;
use crate::curve::Curve;
use crate::provider::{CryptoKeys, CryptoProviderAsync};
use std::marker::PhantomData;

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
    CP: CryptoKeys<Cu>,
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
    CP: CryptoKeys<Cu>,
{
    let remaining_len = buffer.remaining().len();
    let tag = buffer.read(remaining_len)?;
    inner.symmetric.decrypt_and_hash(tag, &mut [])?;
    Ok(())
}

// ═══════════════════════════════════════════════════════════════
//  Finalization helpers
// ═══════════════════════════════════════════════════════════════

fn send_to_handshake_state<'a, N, R, MsgRest, CP>(
    inner: HandshakeInner<N::Curve, N::Cipher, N::Hash, CP>,
    buffer: SendBuffer<'a>,
) -> (&'a [u8], HandshakeState<N, R, Nil, MsgRest, CP>)
where
    N: Protocol,
    CP: CryptoProviderAsync<N::Curve>,
{
    (
        buffer.finish(),
        HandshakeState {
            inner,
            _marker: PhantomData,
        },
    )
}

fn send_to_transport<'a, N, R, CP>(
    inner: HandshakeInner<N::Curve, N::Cipher, N::Hash, CP>,
    buffer: SendBuffer<'a>,
) -> (&'a [u8], Transport<N>)
where
    N: Protocol,
    R: Role,
    CP: CryptoProviderAsync<N::Curve>,
{
    let session_id = inner.symmetric.handshake_hash().to_vec().into();
    let local_e = inner.e_pub;
    let remote_e = inner.re;
    let (c1, c2) = inner.symmetric.split();
    let transport = if R::IS_INITIATOR {
        Transport::new(c1, c2, session_id, local_e, remote_e)
    } else {
        Transport::new(c2, c1, session_id, local_e, remote_e)
    };
    (buffer.finish(), transport)
}

fn recv_to_handshake_state<N, R, MsgRest, CP>(
    inner: HandshakeInner<N::Curve, N::Cipher, N::Hash, CP>,
) -> HandshakeState<N, R, Nil, MsgRest, CP>
where
    N: Protocol,
    CP: CryptoProviderAsync<N::Curve>,
{
    HandshakeState {
        inner,
        _marker: PhantomData,
    }
}

pub(crate) fn recv_to_transport<N, R, CP>(
    inner: HandshakeInner<N::Curve, N::Cipher, N::Hash, CP>,
) -> Transport<N>
where
    N: Protocol,
    R: Role,
    CP: CryptoKeys<N::Curve>,
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
    Cu: Curve,
    Cu::PublicKey: AsRef<[u8]>,
    Ci: Cipher,
    H: Hash,
    CP: CryptoProviderAsync<Cu>,
{
    let e = inner
        .provider
        .generate_ephemeral_key_async()
        .await
        .map_err(|e| HandshakeError::Crypto(e.to_string()))?;
    let e_pub = inner
        .provider
        .public_key(&e)
        .map_err(|e| HandshakeError::Crypto(e.to_string()))?;
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
    CP: CryptoKeys<Cu>,
{
    let bytes = buffer.read(Cu::PUBLIC_KEY_SIZE)?;
    inner.symmetric.mix_hash(bytes);
    if inner.has_psk {
        inner.symmetric.mix_key(bytes);
    }
    let re = Cu::public_key_from_bytes(bytes)
        .map_err(|e| HandshakeError::InvalidPublicKey(e.to_string()))?;
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
    CP: CryptoKeys<Cu>,
{
    let s_pub = inner
        .provider
        .public_key(&static_key)
        .map_err(|e| HandshakeError::Crypto(e.to_string()))?;
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
    CP: CryptoKeys<Cu>,
{
    let wire_len = if inner.symmetric.has_key() {
        Cu::PUBLIC_KEY_SIZE + Ci::TAG_SIZE
    } else {
        Cu::PUBLIC_KEY_SIZE
    };
    let ciphertext = buffer.read(wire_len)?;
    // Public key size is bounded — stack-allocate the output.
    let mut pk_buf = [0u8; 128];
    let pt_len = inner.symmetric.decrypt_and_hash(ciphertext, &mut pk_buf)?;
    let rs = Cu::public_key_from_bytes(&pk_buf[..pt_len])
        .map_err(|e| HandshakeError::InvalidPublicKey(e.to_string()))?;
    let revealed = rs.clone();
    inner.rs = Some(rs);
    Ok(revealed)
}

pub(crate) async fn do_ee<Cu, Ci, H, CP>(
    inner: &mut HandshakeInner<Cu, Ci, H, CP>,
) -> Result<(), HandshakeError>
where
    Cu: Curve,
    Cu::SharedSecret: AsRef<[u8]>,
    Ci: Cipher,
    H: Hash,
    CP: CryptoProviderAsync<Cu>,
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
        .map_err(|e| HandshakeError::Crypto(e.to_string()))?;
    inner.symmetric.mix_key(ss.as_ref());
    Ok(())
}

pub(crate) async fn do_es_initiator<Cu, Ci, H, CP>(
    inner: &mut HandshakeInner<Cu, Ci, H, CP>,
) -> Result<(), HandshakeError>
where
    Cu: Curve,
    Cu::SharedSecret: AsRef<[u8]>,
    Ci: Cipher,
    H: Hash,
    CP: CryptoProviderAsync<Cu>,
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
        .map_err(|e| HandshakeError::Crypto(e.to_string()))?;
    inner.symmetric.mix_key(ss.as_ref());
    Ok(())
}

pub(crate) async fn do_es_responder<Cu, Ci, H, CP>(
    inner: &mut HandshakeInner<Cu, Ci, H, CP>,
) -> Result<(), HandshakeError>
where
    Cu: Curve,
    Cu::SharedSecret: AsRef<[u8]>,
    Ci: Cipher,
    H: Hash,
    CP: CryptoProviderAsync<Cu>,
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
        .map_err(|e| HandshakeError::Crypto(e.to_string()))?;
    inner.symmetric.mix_key(ss.as_ref());
    Ok(())
}

pub(crate) async fn do_se_initiator<Cu, Ci, H, CP>(
    inner: &mut HandshakeInner<Cu, Ci, H, CP>,
) -> Result<(), HandshakeError>
where
    Cu: Curve,
    Cu::SharedSecret: AsRef<[u8]>,
    Ci: Cipher,
    H: Hash,
    CP: CryptoProviderAsync<Cu>,
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
        .map_err(|e| HandshakeError::Crypto(e.to_string()))?;
    inner.symmetric.mix_key(ss.as_ref());
    Ok(())
}

pub(crate) async fn do_se_responder<Cu, Ci, H, CP>(
    inner: &mut HandshakeInner<Cu, Ci, H, CP>,
) -> Result<(), HandshakeError>
where
    Cu: Curve,
    Cu::SharedSecret: AsRef<[u8]>,
    Ci: Cipher,
    H: Hash,
    CP: CryptoProviderAsync<Cu>,
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
        .map_err(|e| HandshakeError::Crypto(e.to_string()))?;
    inner.symmetric.mix_key(ss.as_ref());
    Ok(())
}

pub(crate) async fn do_ss<Cu, Ci, H, CP>(
    inner: &mut HandshakeInner<Cu, Ci, H, CP>,
) -> Result<(), HandshakeError>
where
    Cu: Curve,
    Cu::SharedSecret: AsRef<[u8]>,
    Ci: Cipher,
    H: Hash,
    CP: CryptoProviderAsync<Cu>,
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
        .map_err(|e| HandshakeError::Crypto(e.to_string()))?;
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
    CP: CryptoKeys<Cu>,
{
    inner.symmetric.mix_key_and_hash(psk.as_bytes());
    Ok(())
}

// ═══════════════════════════════════════════════════════════════
//  Macro: three-variant impls for a send token
// ═══════════════════════════════════════════════════════════════

/// Generate three `impl` blocks for a send-side token method.
///
/// The body block has access to `inner: &mut HandshakeInner` and
/// `buffer: &mut SendBuffer<'a>` plus any declared args.
macro_rules! send_token {
    (
        role: $R:ty,
        token: $Token:ty,
        method: $method:ident ($($arg:ident : $arg_ty:ty),*),
        bounds: [$($extra:tt)*],
        body: |$inner:ident, $buf:ident| { $($logic:tt)* }
    ) => {
        // Variant 1: more tokens after this one.
        impl<'a, N, Next, More, MsgRest, CP>
            Sending<'a, N, $R, Cons<$Token, Cons<Next, More>>, MsgRest, CP>
        where
            N: Protocol,
            <N::Curve as Curve>::PublicKey: AsRef<[u8]>,
            CP: CryptoProviderAsync<N::Curve>,
            $($extra)*
        {
            pub async fn $method(
                mut self, $($arg: $arg_ty,)*
            ) -> Result<Sending<'a, N, $R, Cons<Next, More>, MsgRest, CP>, HandshakeError> {
                let $inner = &mut self.inner;
                let $buf = &mut self.buffer;
                $($logic)*
                Ok(Sending { inner: self.inner, buffer: self.buffer, _marker: PhantomData })
            }
        }

        // Variant 2: last token, more messages.
        impl<'a, N, NextMsg, MoreMsgs, CP>
            Sending<'a, N, $R, Cons<$Token, Nil>, Cons<NextMsg, MoreMsgs>, CP>
        where
            N: Protocol,
            <N::Curve as Curve>::PublicKey: AsRef<[u8]>,
            CP: CryptoProviderAsync<N::Curve>,
            $($extra)*
        {
            pub async fn $method(
                mut self, $($arg: $arg_ty,)*
            ) -> Result<(&'a [u8], HandshakeState<N, $R, Nil, Cons<NextMsg, MoreMsgs>, CP>), HandshakeError> {
                let $inner = &mut self.inner;
                let $buf = &mut self.buffer;
                $($logic)*
                send_payload(&mut self.inner, &mut self.buffer)?;
                Ok(send_to_handshake_state::<N, $R, _, CP>(self.inner, self.buffer))
            }
        }

        // Variant 3: last token, last message.
        impl<'a, N, CP>
            Sending<'a, N, $R, Cons<$Token, Nil>, Nil, CP>
        where
            N: Protocol,
            <N::Curve as Curve>::PublicKey: AsRef<[u8]>,
            CP: CryptoProviderAsync<N::Curve>,
            $($extra)*
        {
            pub async fn $method(
                mut self, $($arg: $arg_ty,)*
            ) -> Result<(&'a [u8], Transport<N>), HandshakeError> {
                let $inner = &mut self.inner;
                let $buf = &mut self.buffer;
                $($logic)*
                send_payload(&mut self.inner, &mut self.buffer)?;
                Ok(send_to_transport::<N, $R, CP>(self.inner, self.buffer))
            }
        }
    };
}

/// Same for recv-side — but does **not** return bytes.
///
/// On the receiving side the caller already provided the bytes via
/// `read(&msg)`, so there is nothing useful to hand back. The return
/// type is just the next state.
macro_rules! recv_token {
    (
        role: $R:ty,
        token: $Token:ty,
        method: $method:ident ($($arg:ident : $arg_ty:ty),*),
        bounds: [$($extra:tt)*],
        body: |$inner:ident, $buf:ident| { $($logic:tt)* }
    ) => {
        // Variant 1: more tokens.
        impl<'a, N, Next, More, MsgRest, CP>
            Receiving<'a, N, $R, Cons<$Token, Cons<Next, More>>, MsgRest, CP>
        where
            N: Protocol,
            <N::Curve as Curve>::PublicKey: AsRef<[u8]>,
            CP: CryptoProviderAsync<N::Curve>,
            $($extra)*
        {
            pub async fn $method(
                mut self, $($arg: $arg_ty,)*
            ) -> Result<Receiving<'a, N, $R, Cons<Next, More>, MsgRest, CP>, HandshakeError> {
                let $inner = &mut self.inner;
                let $buf = &mut self.buffer;
                $($logic)*
                Ok(Receiving { inner: self.inner, buffer: self.buffer, _marker: PhantomData })
            }
        }

        // Variant 2: last token, more messages.
        impl<'a, N, NextMsg, MoreMsgs, CP>
            Receiving<'a, N, $R, Cons<$Token, Nil>, Cons<NextMsg, MoreMsgs>, CP>
        where
            N: Protocol,
            <N::Curve as Curve>::PublicKey: AsRef<[u8]>,
            CP: CryptoProviderAsync<N::Curve>,
            $($extra)*
        {
            pub async fn $method(
                mut self, $($arg: $arg_ty,)*
            ) -> Result<HandshakeState<N, $R, Nil, Cons<NextMsg, MoreMsgs>, CP>, HandshakeError> {
                let $inner = &mut self.inner;
                let $buf = &mut self.buffer;
                $($logic)*
                recv_payload(&mut self.inner, &mut self.buffer)?;
                Ok(recv_to_handshake_state::<N, $R, _, CP>(self.inner))
            }
        }

        // Variant 3: last token, last message.
        impl<'a, N, CP>
            Receiving<'a, N, $R, Cons<$Token, Nil>, Nil, CP>
        where
            N: Protocol,
            <N::Curve as Curve>::PublicKey: AsRef<[u8]>,
            CP: CryptoProviderAsync<N::Curve>,
            $($extra)*
        {
            pub async fn $method(
                mut self, $($arg: $arg_ty,)*
            ) -> Result<Transport<N>, HandshakeError> {
                let $inner = &mut self.inner;
                let $buf = &mut self.buffer;
                $($logic)*
                recv_payload(&mut self.inner, &mut self.buffer)?;
                Ok(recv_to_transport::<N, $R, CP>(self.inner))
            }
        }
    };
}

// ═══════════════════════════════════════════════════════════════
//  Macro: recv token that reveals a public key
// ═══════════════════════════════════════════════════════════════

/// Generate three `impl` blocks for a recv-side token that reveals
/// a public key (E or S).
///
/// The return type pairs the revealed `Cu::PublicKey` with the next
/// state — the caller sees the key at the point it is revealed.
macro_rules! recv_reveal_token {
    (
        role: $R:ty,
        token: $Token:ty,
        method: $method:ident ($($arg:ident : $arg_ty:ty),*),
        bounds: [$($extra:tt)*],
        body: |$inner:ident, $buf:ident| { $($logic:tt)* }
    ) => {
        // Variant 1: more tokens after this one.
        impl<'a, N, Next, More, MsgRest, CP>
            Receiving<'a, N, $R, Cons<$Token, Cons<Next, More>>, MsgRest, CP>
        where
            N: Protocol,
            <N::Curve as Curve>::PublicKey: AsRef<[u8]>,
            CP: CryptoProviderAsync<N::Curve>,
            $($extra)*
        {
            pub async fn $method(
                mut self, $($arg: $arg_ty,)*
            ) -> Result<(<N::Curve as Curve>::PublicKey, Receiving<'a, N, $R, Cons<Next, More>, MsgRest, CP>), HandshakeError> {
                let $inner = &mut self.inner;
                let $buf = &mut self.buffer;
                let revealed = { $($logic)* };
                Ok((revealed, Receiving { inner: self.inner, buffer: self.buffer, _marker: PhantomData }))
            }
        }

        // Variant 2: last token, more messages.
        impl<'a, N, NextMsg, MoreMsgs, CP>
            Receiving<'a, N, $R, Cons<$Token, Nil>, Cons<NextMsg, MoreMsgs>, CP>
        where
            N: Protocol,
            <N::Curve as Curve>::PublicKey: AsRef<[u8]>,
            CP: CryptoProviderAsync<N::Curve>,
            $($extra)*
        {
            pub async fn $method(
                mut self, $($arg: $arg_ty,)*
            ) -> Result<(<N::Curve as Curve>::PublicKey, HandshakeState<N, $R, Nil, Cons<NextMsg, MoreMsgs>, CP>), HandshakeError> {
                let $inner = &mut self.inner;
                let $buf = &mut self.buffer;
                let revealed = { $($logic)* };
                recv_payload(&mut self.inner, &mut self.buffer)?;
                let hs = recv_to_handshake_state::<N, $R, _, CP>(self.inner);
                Ok((revealed, hs))
            }
        }

        // Variant 3: last token, last message.
        impl<'a, N, CP>
            Receiving<'a, N, $R, Cons<$Token, Nil>, Nil, CP>
        where
            N: Protocol,
            <N::Curve as Curve>::PublicKey: AsRef<[u8]>,
            CP: CryptoProviderAsync<N::Curve>,
            $($extra)*
        {
            pub async fn $method(
                mut self, $($arg: $arg_ty,)*
            ) -> Result<(<N::Curve as Curve>::PublicKey, Transport<N>), HandshakeError> {
                let $inner = &mut self.inner;
                let $buf = &mut self.buffer;
                let revealed = { $($logic)* };
                recv_payload(&mut self.inner, &mut self.buffer)?;
                let transport = recv_to_transport::<N, $R, CP>(self.inner);
                Ok((revealed, transport))
            }
        }
    };
}

// ═══════════════════════════════════════════════════════════════
//  Token: E (role-independent)
// ═══════════════════════════════════════════════════════════════

send_token! {
    role: Initiator, token: E, method: e(), bounds: [],
    body: |inner, buf| { send_e(inner, buf).await?; }
}
send_token! {
    role: Responder, token: E, method: e(), bounds: [],
    body: |inner, buf| { send_e(inner, buf).await?; }
}
recv_reveal_token! {
    role: Initiator, token: E, method: e(), bounds: [],
    body: |inner, buf| { recv_e(inner, buf)? }
}
recv_reveal_token! {
    role: Responder, token: E, method: e(), bounds: [],
    body: |inner, buf| { recv_e(inner, buf)? }
}

// ═══════════════════════════════════════════════════════════════
//  Token: S
// ═══════════════════════════════════════════════════════════════

send_token! {
    role: Initiator, token: S, method: s(static_key: CP::PrivateKey), bounds: [],
    body: |inner, buf| { send_s(inner, buf, static_key)?; }
}
send_token! {
    role: Responder, token: S, method: s(static_key: CP::PrivateKey), bounds: [],
    body: |inner, buf| { send_s(inner, buf, static_key)?; }
}
recv_reveal_token! {
    role: Initiator, token: S, method: s(), bounds: [],
    body: |inner, buf| { recv_s(inner, buf)? }
}
recv_reveal_token! {
    role: Responder, token: S, method: s(), bounds: [],
    body: |inner, buf| { recv_s(inner, buf)? }
}

// ═══════════════════════════════════════════════════════════════
//  Token: Ee (role-independent)
// ═══════════════════════════════════════════════════════════════

send_token! {
    role: Initiator, token: Ee, method: ee(), bounds: [<N::Curve as Curve>::SharedSecret: AsRef<[u8]>,],
    body: |inner, _buf| { do_ee(inner).await?; }
}
send_token! {
    role: Responder, token: Ee, method: ee(), bounds: [<N::Curve as Curve>::SharedSecret: AsRef<[u8]>,],
    body: |inner, _buf| { do_ee(inner).await?; }
}
recv_token! {
    role: Initiator, token: Ee, method: ee(), bounds: [<N::Curve as Curve>::SharedSecret: AsRef<[u8]>,],
    body: |inner, _buf| { do_ee(inner).await?; }
}
recv_token! {
    role: Responder, token: Ee, method: ee(), bounds: [<N::Curve as Curve>::SharedSecret: AsRef<[u8]>,],
    body: |inner, _buf| { do_ee(inner).await?; }
}

// ═══════════════════════════════════════════════════════════════
//  Token: Es (role-dependent)
// ═══════════════════════════════════════════════════════════════

// Initiator Es: DH(e, rs). Remote static key read from state (set via set_rs pre-message).
send_token! {
    role: Initiator, token: Es, method: es(), bounds: [<N::Curve as Curve>::SharedSecret: AsRef<[u8]>,],
    body: |inner, _buf| { do_es_initiator(inner).await?; }
}
recv_token! {
    role: Initiator, token: Es, method: es(), bounds: [<N::Curve as Curve>::SharedSecret: AsRef<[u8]>,],
    body: |inner, _buf| { do_es_initiator(inner).await?; }
}

// Responder Es: DH(s, re). Keys already in state.
send_token! {
    role: Responder, token: Es, method: es(), bounds: [<N::Curve as Curve>::SharedSecret: AsRef<[u8]>,],
    body: |inner, _buf| { do_es_responder(inner).await?; }
}
recv_token! {
    role: Responder, token: Es, method: es(), bounds: [<N::Curve as Curve>::SharedSecret: AsRef<[u8]>,],
    body: |inner, _buf| { do_es_responder(inner).await?; }
}

// ═══════════════════════════════════════════════════════════════
//  Token: Se (role-dependent)
// ═══════════════════════════════════════════════════════════════

// Initiator Se: DH(s, re). Keys already in state.
send_token! {
    role: Initiator, token: Se, method: se(), bounds: [<N::Curve as Curve>::SharedSecret: AsRef<[u8]>,],
    body: |inner, _buf| { do_se_initiator(inner).await?; }
}
recv_token! {
    role: Initiator, token: Se, method: se(), bounds: [<N::Curve as Curve>::SharedSecret: AsRef<[u8]>,],
    body: |inner, _buf| { do_se_initiator(inner).await?; }
}

// Responder Se: DH(e, rs). Keys already in state.
send_token! {
    role: Responder, token: Se, method: se(), bounds: [<N::Curve as Curve>::SharedSecret: AsRef<[u8]>,],
    body: |inner, _buf| { do_se_responder(inner).await?; }
}
recv_token! {
    role: Responder, token: Se, method: se(), bounds: [<N::Curve as Curve>::SharedSecret: AsRef<[u8]>,],
    body: |inner, _buf| { do_se_responder(inner).await?; }
}

// ═══════════════════════════════════════════════════════════════
//  Token: Ss (role-independent — both sides DH their own s with rs)
// ═══════════════════════════════════════════════════════════════

send_token! {
    role: Initiator, token: Ss, method: ss(), bounds: [<N::Curve as Curve>::SharedSecret: AsRef<[u8]>,],
    body: |inner, _buf| { do_ss(inner).await?; }
}
send_token! {
    role: Responder, token: Ss, method: ss(), bounds: [<N::Curve as Curve>::SharedSecret: AsRef<[u8]>,],
    body: |inner, _buf| { do_ss(inner).await?; }
}
recv_token! {
    role: Initiator, token: Ss, method: ss(), bounds: [<N::Curve as Curve>::SharedSecret: AsRef<[u8]>,],
    body: |inner, _buf| { do_ss(inner).await?; }
}
recv_token! {
    role: Responder, token: Ss, method: ss(), bounds: [<N::Curve as Curve>::SharedSecret: AsRef<[u8]>,],
    body: |inner, _buf| { do_ss(inner).await?; }
}

// ═══════════════════════════════════════════════════════════════
//  Token: Psk (role-independent)
// ═══════════════════════════════════════════════════════════════

send_token! {
    role: Initiator, token: Psk, method: psk(psk_key: &crate::psk::Psk), bounds: [],
    body: |inner, _buf| { do_psk(inner, psk_key)?; }
}
send_token! {
    role: Responder, token: Psk, method: psk(psk_key: &crate::psk::Psk), bounds: [],
    body: |inner, _buf| { do_psk(inner, psk_key)?; }
}
recv_token! {
    role: Initiator, token: Psk, method: psk(psk_key: &crate::psk::Psk), bounds: [],
    body: |inner, _buf| { do_psk(inner, psk_key)?; }
}
recv_token! {
    role: Responder, token: Psk, method: psk(psk_key: &crate::psk::Psk), bounds: [],
    body: |inner, _buf| { do_psk(inner, psk_key)?; }
}

// ═══════════════════════════════════════════════════════════════
//  Entry points: HandshakeState → Sending
// ═══════════════════════════════════════════════════════════════

// When the first token of a send message is E.
// Only available in the Ready stage.
impl<N, R, Tokens, MsgRest, Dir, CP>
    HandshakeState<N, R, Nil, Cons<Message<Dir, Cons<E, Tokens>>, MsgRest>, CP>
where
    N: Protocol,
    R: Role<SendDir = Dir>,
    <N::Curve as Curve>::PublicKey: AsRef<[u8]>,
    CP: CryptoProviderAsync<N::Curve>,
    Cons<E, Tokens>: WireSize<N::Curve, N::Cipher, true> + WireSize<N::Curve, N::Cipher, false>,
{
    /// Start a send message with the `E` token.
    ///
    /// `output` must be exactly the right size for this message.
    /// Use [`noise_message_size!`](crate::noise_message_size) to compute the size at compile time.
    pub async fn e(
        self,
        output: &mut [u8],
    ) -> Result<Sending<'_, N, R, Tokens, MsgRest, CP>, HandshakeError> {
        let mut sending = self.begin_send(output);
        send_e(&mut sending.inner, &mut sending.buffer).await?;
        Ok(Sending {
            inner: sending.inner,
            buffer: sending.buffer,
            _marker: PhantomData,
        })
    }
}

// When the first token of a send message is Psk.
// Only available in the Ready stage.
impl<N, R, Tokens, MsgRest, Dir, CP>
    HandshakeState<N, R, Nil, Cons<Message<Dir, Cons<Psk, Tokens>>, MsgRest>, CP>
where
    N: Protocol,
    R: Role<SendDir = Dir>,
    <N::Curve as Curve>::PublicKey: AsRef<[u8]>,
    CP: CryptoProviderAsync<N::Curve>,
    Cons<Psk, Tokens>: WireSize<N::Curve, N::Cipher, true> + WireSize<N::Curve, N::Cipher, false>,
{
    /// Start a send message with the `Psk` token.
    ///
    /// `output` must be exactly the right size for this message.
    /// Use [`noise_message_size!`](crate::noise_message_size) to compute the size at compile time.
    pub async fn psk<'a>(
        self,
        output: &'a mut [u8],
        psk_key: &crate::psk::Psk,
    ) -> Result<Sending<'a, N, R, Tokens, MsgRest, CP>, HandshakeError> {
        let mut sending = self.begin_send(output);
        do_psk(&mut sending.inner, psk_key)?;
        Ok(Sending {
            inner: sending.inner,
            buffer: sending.buffer,
            _marker: PhantomData,
        })
    }
}

// When the first token of a send message is S.
// Only available in the Ready stage.
impl<N, R, Tokens, MsgRest, Dir, CP>
    HandshakeState<N, R, Nil, Cons<Message<Dir, Cons<S, Tokens>>, MsgRest>, CP>
where
    N: Protocol,
    R: Role<SendDir = Dir>,
    <N::Curve as Curve>::PublicKey: AsRef<[u8]>,
    CP: CryptoProviderAsync<N::Curve>,
    Cons<S, Tokens>: WireSize<N::Curve, N::Cipher, true> + WireSize<N::Curve, N::Cipher, false>,
{
    /// Start a send message with the `S` token.
    ///
    /// `output` must be exactly the right size for this message.
    /// Use [`noise_message_size!`](crate::noise_message_size) to compute the size at compile time.
    pub async fn s(
        self,
        output: &mut [u8],
        static_key: CP::PrivateKey,
    ) -> Result<Sending<'_, N, R, Tokens, MsgRest, CP>, HandshakeError> {
        let mut sending = self.begin_send(output);
        send_s(&mut sending.inner, &mut sending.buffer, static_key)?;
        Ok(Sending {
            inner: sending.inner,
            buffer: sending.buffer,
            _marker: PhantomData,
        })
    }
}
