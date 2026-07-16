//! Out-of-order transport — a datagram-mode counterpart to [`Transport`].
//!
//! Where [`Transport`] requires a reliable, in-order, exactly-once byte
//! stream, some substrates — UDP, and anything else that may drop,
//! reorder, or duplicate packets — cannot offer one. The Noise
//! specification sanctions this case in §11.4 ("Out-of-order transport
//! messages"): transmit the nonce explicitly with every message and leave
//! the delivery semantics — reordering tolerance, replay rejection,
//! retransmission — to the application.
//!
//! [`Transport::into_datagram`] converts a completed transport into a
//! [`DatagramSend`]/[`DatagramRecv`] pair that does exactly this. The send
//! half owns the monotonic send counter and reports it with every sealed
//! message; the receive half is stateless in the counter, opening whatever
//! counter the caller presents.
//!
//! # What this does and does not provide
//!
//! - **Nonce-reuse safety is preserved.** The send counter lives inside
//!   `hiss` and is strictly monotonic — the caller is told which counter a
//!   message was sealed under but can never choose it, so it can never
//!   drive two messages onto the same nonce.
//! - **Replay protection is the caller's duty.** [`DatagramRecv::decrypt_at`]
//!   will open the same counter as many times as it is asked to. A datagram
//!   protocol that needs replay rejection — most do — must track seen
//!   counters itself, e.g. with a sliding receive window in the style of
//!   WireGuard or IPsec.
//! - **No rekey.** With explicit counters an unsynchronised rekey while
//!   packets are in flight is a correctness trap, so neither half offers
//!   one; a consuming protocol re-handshakes to obtain fresh keys instead.
//!
//! Both halves inherit the stream pair's key hygiene: the underlying
//! [`CipherState`] zeroises its key on drop, and the message-length cap and
//! nonce-exhaustion guard carry over unchanged.

use super::Protocol;
use super::cipher_state::CipherState;
use super::error::HandshakeError;
use super::session_id::SessionId;
use super::transport::Transport;

impl<Proto: Protocol> Transport<Proto> {
    /// Convert this stream-oriented transport into an out-of-order
    /// **datagram** pair.
    ///
    /// Consumes the transport — mirroring [`split`](Self::split) — and
    /// hands back a [`DatagramSend`]/[`DatagramRecv`] pair suited to a
    /// lossy, reordering substrate such as UDP. Each half keeps its
    /// direction's key material and a clone of the [`SessionId`]; the
    /// ephemeral public keys are dropped, because a datagram protocol
    /// re-handshakes rather than inspecting them.
    ///
    /// Use this instead of [`split`](Self::split) when the wire cannot
    /// guarantee in-order, exactly-once delivery. See the
    /// [module documentation](self) for the delivery contract and the
    /// caller's replay-protection duty.
    pub fn into_datagram(self) -> (DatagramSend<Proto>, DatagramRecv<Proto>) {
        let (send, recv, session_id) = self.into_cipher_states();
        let sender = DatagramSend {
            cipher: send,
            session_id: session_id.clone(),
        };
        let receiver = DatagramRecv {
            cipher: recv,
            session_id,
        };
        (sender, receiver)
    }
}

/// The sending half of a datagram-mode [`Transport`].
///
/// Owns the outbound [`CipherState`] and, with it, the monotonic send
/// counter. Every [`encrypt_next`](Self::encrypt_next) seals under the next
/// counter and reports it, so the caller can put that counter in its packet
/// header for the peer to decrypt with.
pub struct DatagramSend<Proto: Protocol> {
    cipher: CipherState<Proto::Cipher>,
    session_id: SessionId,
}

impl<Proto: Protocol> DatagramSend<Proto> {
    /// Seal `plaintext` with associated data `ad` into `output`, using the
    /// next send counter.
    ///
    /// Returns `(counter, bytes_written)`. The `counter` is the explicit
    /// nonce this message was sealed under — transmit it in the packet
    /// header so the peer can open the message with
    /// [`DatagramRecv::decrypt_at`]. The counter is owned by `hiss` and is
    /// strictly monotonic (`0, 1, 2, …`); the caller can never choose it,
    /// so it can never cause nonce reuse.
    ///
    /// `output` must be at least `plaintext.len() + OVERHEAD` bytes.
    ///
    /// Errors on `u64::MAX` (nonce exhaustion) and on a payload whose
    /// on-wire message would exceed the Noise length cap, exactly as the
    /// stream transport does. On any error the counter does **not** advance
    /// and nothing is written.
    pub fn encrypt_next(
        &mut self,
        ad: &[u8],
        plaintext: &[u8],
        output: &mut [u8],
    ) -> Result<(u64, usize), HandshakeError> {
        self.cipher.encrypt_next_with_ad(ad, plaintext, output)
    }

    /// The session identifier — the same value on both halves and on the
    /// peer.
    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    /// Force the send counter to `n` (tests only).
    ///
    /// Mirrors [`CipherState::set_nonce_for_test`]; used to drive the
    /// counter up to its `u64::MAX` boundary so the exhaustion guard can be
    /// exercised without performing 2^64 seals.
    #[cfg(test)]
    pub(crate) fn set_counter_for_test(&mut self, n: u64) {
        self.cipher.set_nonce_for_test(n);
    }
}

/// The receiving half of a datagram-mode [`Transport`].
///
/// Owns the inbound key material. It is stateless in the counter: it holds
/// no receive nonce, so it opens datagrams under whatever counter the
/// caller supplies, in any order, any number of times.
pub struct DatagramRecv<Proto: Protocol> {
    cipher: CipherState<Proto::Cipher>,
    session_id: SessionId,
}

impl<Proto: Protocol> DatagramRecv<Proto> {
    /// Open a datagram that was sealed at `counter`, writing plaintext into
    /// `output`.
    ///
    /// **Stateless in the counter.** The same `counter` can be decrypted
    /// more than once, and counters may arrive in any order or not at all —
    /// this half keeps no receive nonce, so nothing here rejects a replay.
    /// **Replay protection is explicitly the caller's duty**: a datagram
    /// protocol that must reject duplicates has to track the counters it has
    /// already accepted (typically a sliding window). Takes `&self`; on any
    /// error nothing is learnt and no state changes.
    ///
    /// `output` must be at least `ciphertext.len() - OVERHEAD` bytes.
    ///
    /// On a [`DecryptionFailed`](HandshakeError::DecryptionFailed) error —
    /// from a tampered ciphertext, the wrong `ad`, or the wrong `counter` —
    /// `output` holds **unauthenticated** bytes that must not be read, per
    /// the AEAD output contract.
    pub fn decrypt_at(
        &self,
        counter: u64,
        ad: &[u8],
        ciphertext: &[u8],
        output: &mut [u8],
    ) -> Result<usize, HandshakeError> {
        self.cipher.decrypt_at(counter, ad, ciphertext, output)
    }

    /// The session identifier — the same value on both halves and on the
    /// peer.
    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }
}
