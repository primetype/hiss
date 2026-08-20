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
//! message; the receive half opens whatever counter the caller presents.
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
//!
//! # Rekey and key epochs
//!
//! [`into_datagram`](Transport::into_datagram) never ratchets: both halves
//! keep the handshake keys for the life of the session. With explicit
//! counters an *unsynchronised* rekey while packets are in flight would be
//! a correctness trap, so the plain pair offers none — a consuming protocol
//! re-handshakes to obtain fresh keys instead.
//!
//! [`into_datagram_with_epoch`](Transport::into_datagram_with_epoch) instead
//! ratchets the transport keys forward on a **counter-derived schedule**,
//! so an otherwise idle session does not die of key age without a
//! re-handshake. The caller fixes an `epoch_size`; the epoch of a message
//! is `counter / epoch_size`, and each epoch uses the key obtained by
//! chaining the Noise §11.3 `Rekey()` transform that many times from the
//! handshake key. The schedule is a pure function of the counter, so both
//! peers agree on which key opens which packet without any extra wire
//! signalling. Each direction ratchets **independently** on its own
//! counter, exactly as the two Noise `CipherState`s rekey independently.
//!
//! Both halves inherit the stream pair's key hygiene: the underlying key
//! material is zeroised on drop, and the message-length cap and
//! nonce-exhaustion guard carry over unchanged.

use super::Protocol;
use super::cipher::Cipher;
use super::cipher_state::{CipherState, MAX_MESSAGE_LEN, rekey_key};
use super::error::HandshakeError;
use super::session_id::SessionId;
use super::transport::Transport;
use std::marker::PhantomData;
use std::num::NonZeroU64;

/// How far ahead of its committed epoch a [`DatagramRecv`] will chase a
/// future-epoch datagram before refusing it outright.
///
/// A datagram whose counter lands more than `MAX_EPOCH_JUMP` epochs beyond
/// the receiver's current epoch is rejected **without deriving any key**.
/// This bounds the work a single unauthenticated packet can demand: without
/// the cap, a forged counter near `2^64` would ask the receiver to chain
/// `Rekey()` an astronomical number of times — a CPU denial of service.
///
/// A *legitimate* peer more than `MAX_EPOCH_JUMP` epochs ahead means at
/// least one whole epoch elapsed during which we heard nothing at all; that
/// is a dead session, and the upper layer's liveness handling — not a key
/// chase on the receive path — is what deals with it.
pub const MAX_EPOCH_JUMP: u64 = 2;

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
    /// The keys never ratchet: both halves hold the handshake keys for the
    /// life of the session. For an epoch-ratcheting pair — one that renews
    /// its keys on a counter-derived schedule without a re-handshake — use
    /// [`into_datagram_with_epoch`](Self::into_datagram_with_epoch) instead.
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
            epoch: None,
        };
        let receiver = DatagramRecv {
            keys: RecvKeys::Plain(recv),
            session_id,
        };
        (sender, receiver)
    }

    /// Convert this transport into an out-of-order **datagram** pair whose
    /// keys ratchet forward on a counter-derived epoch schedule.
    ///
    /// Identical to [`into_datagram`](Self::into_datagram) — same
    /// explicit-counter, reordering-tolerant contract, same
    /// caller-owned replay duty — except that the keys are renewed as the
    /// counter advances, so a long-lived but sparsely-used session is not
    /// forced to re-handshake merely to retire an ageing key.
    ///
    /// `epoch_size` is the number of counter values per epoch and is the
    /// **caller's** to choose (`hiss` fixes no default): a message sealed at
    /// counter `c` belongs to epoch `c / epoch_size`, and epoch `e` uses the
    /// key reached by applying the Noise §11.3 `Rekey()` transform `e` times
    /// to the handshake key. Both peers must pass the **same** `epoch_size`,
    /// or they will disagree on which key opens which packet. Each direction
    /// ratchets independently on its own counter.
    ///
    /// The send half advances its key eagerly as its monotonic counter
    /// crosses each boundary; the receive half keeps the current and the
    /// immediately-preceding epoch keys, so packets reordered across one
    /// boundary still open. See [`DatagramRecv::decrypt_at`] for the
    /// commit-only-after-verify discipline that keeps a forged counter from
    /// desynchronising the receiver.
    pub fn into_datagram_with_epoch(
        self,
        epoch_size: NonZeroU64,
    ) -> (DatagramSend<Proto>, DatagramRecv<Proto>) {
        let (send, mut recv, session_id) = self.into_cipher_states();
        let sender = DatagramSend {
            cipher: send,
            session_id: session_id.clone(),
            epoch: Some(SendEpoch {
                epoch_size,
                key_epoch: 0,
            }),
        };
        // **Move** the epoch-0 receive key into the ratchet. The source
        // `CipherState` is left unkeyed, so the ratchet holds the only key
        // anything will use from here on — but a move copies rather than
        // erases, so the moved-from slot's bytes survive as dead stack of
        // this function, unscrubbed. That is the same class as every other
        // move of a key-bearing value (see `CipherState::take_key`, and
        // SECURITY.md's "Honest limits"), not something this call site can
        // close. A completed transport is always keyed, but should a
        // plaintext-mode state ever reach here it degrades to the no-ratchet
        // path rather than panicking.
        let keys = match recv.take_key() {
            Some(base) => RecvKeys::Ratchet(RecvRatchet::new(epoch_size, base)),
            None => RecvKeys::Plain(recv),
        };
        let receiver = DatagramRecv { keys, session_id };
        (sender, receiver)
    }
}

/// Per-direction epoch state carried by a ratcheting [`DatagramSend`].
struct SendEpoch {
    /// Counter values per epoch — the caller's choice, shared with the peer.
    epoch_size: NonZeroU64,
    /// The epoch of the key currently held in the [`CipherState`].
    key_epoch: u64,
}

/// The sending half of a datagram-mode [`Transport`].
///
/// Owns the outbound [`CipherState`] and, with it, the monotonic send
/// counter. Every [`encrypt_next`](Self::encrypt_next) seals under the next
/// counter and reports it, so the caller can put that counter in its packet
/// header for the peer to decrypt with. When built with
/// [`into_datagram_with_epoch`](Transport::into_datagram_with_epoch) it also
/// ratchets its key forward as the counter crosses each epoch boundary.
pub struct DatagramSend<Proto: Protocol> {
    cipher: CipherState<Proto::Cipher>,
    session_id: SessionId,
    /// Epoch ratchet state; `None` for the plain (no-ratchet) half.
    epoch: Option<SendEpoch>,
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
    /// For an epoch-ratcheting half, the key is first advanced so that its
    /// epoch matches `counter / epoch_size`. Because the counter is
    /// monotonic the target epoch never decreases, so this ratchets forward
    /// one step at a time and never backwards.
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
        if let Some(epoch) = self.epoch.as_mut() {
            // `u64::MAX` is reserved for `Rekey()` and the seal below refuses
            // it — but guard here too, so the refused call cannot ratchet the
            // key first ("on any error nothing changes" holds for key state as
            // well as for the counter and the output).
            if self.cipher.nonce() == u64::MAX {
                return Err(HandshakeError::NonceOverflow);
            }
            // The counter about to be used decides the key epoch.
            let target = self.cipher.nonce() / epoch.epoch_size.get();
            while epoch.key_epoch < target {
                self.cipher.rekey()?;
                epoch.key_epoch += 1;
            }
        }
        self.cipher.encrypt_next_with_ad(ad, plaintext, output)
    }

    /// The counter the next **successful** [`encrypt_next`](Self::encrypt_next)
    /// will seal under — the current cipher-state `n`. Read-only: the
    /// counter stays owned by `hiss`, and only a successful seal advances
    /// it.
    ///
    /// This is what lets a packet header that carries the counter — and is
    /// then fed back in as the seal's associated data — be constructed
    /// *before* the seal, without mirroring hiss-owned state. The value
    /// returned equals the `counter` the next successful `encrypt_next`
    /// returns. A failed seal leaves it unchanged (on any `encrypt_next`
    /// error the counter does not advance, so the promise stands until a
    /// seal succeeds). At `u64::MAX` the accessor still returns `u64::MAX`
    /// — the counter that will never be used: the next seal fails with
    /// [`NonceOverflow`](HandshakeError::NonceOverflow) rather than reuse
    /// it.
    pub fn next_counter(&self) -> u64 {
        self.cipher.nonce()
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
/// Holds the inbound key material and opens datagrams under the explicit
/// counter the caller supplies, in any order and any number of times. A
/// plain half (from [`into_datagram`](Transport::into_datagram)) keeps a
/// single, stateless key; an epoch-ratcheting half (from
/// [`into_datagram_with_epoch`](Transport::into_datagram_with_epoch)) keeps
/// the current and the immediately-preceding epoch keys and advances them
/// under the strict discipline documented on [`decrypt_at`](Self::decrypt_at).
pub struct DatagramRecv<Proto: Protocol> {
    keys: RecvKeys<Proto::Cipher>,
    session_id: SessionId,
}

/// The receive-side key material: either a single unchanging key or a
/// forward-ratcheting pair of epoch keys.
enum RecvKeys<Ci: Cipher> {
    /// No ratchet: a single stateless [`CipherState`], byte-for-byte the
    /// behaviour of the original datagram receive half.
    Plain(CipherState<Ci>),
    /// A counter-derived epoch ratchet.
    Ratchet(RecvRatchet<Ci>),
}

/// The current and previous epoch keys of a ratcheting receive half.
///
/// Only the two newest epoch keys are retained: the current epoch's, and —
/// once the ratchet has advanced at least once — the one immediately before
/// it, so a datagram reordered across a single boundary still opens. Older
/// keys are ratcheted away and gone.
struct RecvRatchet<Ci: Cipher> {
    /// Counter values per epoch — the caller's choice, shared with the peer.
    epoch_size: NonZeroU64,
    /// The highest epoch whose key has been committed.
    current_epoch: u64,
    /// The key for `current_epoch`.
    current_key: Ci::Key,
    /// The key for `current_epoch − 1`, or `None` while `current_epoch == 0`.
    prev_key: Option<Ci::Key>,
    /// `fn() -> Ci`, not `Ci`, so the marker cannot strip an auto trait the
    /// keys themselves keep — see [`CipherState`].
    _cipher: PhantomData<fn() -> Ci>,
}

impl<Ci: Cipher> RecvRatchet<Ci> {
    /// Seed a fresh ratchet at epoch 0 with the handshake key.
    fn new(epoch_size: NonZeroU64, base_key: Ci::Key) -> Self {
        Self {
            epoch_size,
            current_epoch: 0,
            current_key: base_key,
            prev_key: None,
            _cipher: PhantomData,
        }
    }

    /// Open a datagram sealed at `counter`, ratcheting the committed keys
    /// forward only if the AEAD tag verifies.
    ///
    /// The commit-and-cap discipline is a security property, not a nicety;
    /// see [`DatagramRecv::decrypt_at`] for the full contract.
    fn decrypt_at(
        &mut self,
        counter: u64,
        ad: &[u8],
        ciphertext: &[u8],
        output: &mut [u8],
    ) -> Result<usize, HandshakeError> {
        // Reject an over-cap incoming message (spec §3) before any work, and
        // reserve `u64::MAX` for `Rekey()` — no legitimately sealed message
        // ever carries it.
        if ciphertext.len() > MAX_MESSAGE_LEN {
            return Err(HandshakeError::MessageTooLong {
                len: ciphertext.len(),
            });
        }
        if counter == u64::MAX {
            return Err(HandshakeError::NonceOverflow);
        }

        let msg_epoch = counter / self.epoch_size.get();

        // Current epoch: open under the committed key, no state change.
        if msg_epoch == self.current_epoch {
            return Ci::decrypt(&self.current_key, counter, ad, ciphertext, output);
        }

        // Past epoch: a straggler from the immediately-preceding epoch opens
        // under the retained previous key; anything older was ratcheted away
        // and is refused with the ordinary decrypt error.
        if msg_epoch < self.current_epoch {
            if msg_epoch + 1 == self.current_epoch
                && let Some(prev) = self.prev_key.as_ref()
            {
                return Ci::decrypt(prev, counter, ad, ciphertext, output);
            }
            return Err(HandshakeError::DecryptionFailed);
        }

        // Future epoch. Two rules keep an unauthenticated packet cheap and
        // non-desynchronising:
        //
        //   1. Beyond `MAX_EPOCH_JUMP` we refuse WITHOUT deriving any key, so
        //      a forged far-future counter cannot demand an unbounded REKEY
        //      chain (a CPU denial of service).
        //   2. Within the cap we derive CANDIDATE keys, leaving the committed
        //      keys in place until the AEAD tag verifies, so a single forged
        //      packet cannot advance — and thereby desync — the receiver (a
        //      one-packet denial of service).
        let steps = msg_epoch - self.current_epoch;
        if steps > MAX_EPOCH_JUMP {
            return Err(HandshakeError::DecryptionFailed);
        }

        // Chain `Rekey()` from the committed current key, which is only
        // borrowed. `prev_cand` trails one epoch behind `cur_cand`; `None`
        // means "the committed current key", which is where the chain starts
        // and is therefore key(msg_epoch − 1) exactly when `steps == 1`. On
        // exit `cur_cand` holds key(msg_epoch).
        let mut cur_cand = rekey_key::<Ci>(&self.current_key)?;
        let mut prev_cand: Option<Ci::Key> = None;
        for _ in 1..steps {
            let next = rekey_key::<Ci>(&cur_cand)?;
            // The displaced value drops here, scrubbing itself.
            prev_cand = Some(core::mem::replace(&mut cur_cand, next));
        }

        // Open under the candidate. Committed state advances ONLY on success.
        match Ci::decrypt(&cur_cand, counter, ad, ciphertext, output) {
            Ok(len) => {
                let old_current = core::mem::replace(&mut self.current_key, cur_cand);
                // steps == 1: the old current key IS key(msg_epoch − 1), so it
                // becomes `prev`. steps > 1: `prev_cand` is key(msg_epoch − 1)
                // and the old current key drops here, scrubbing itself. The
                // displaced `prev_key` drops on assignment either way.
                self.prev_key = Some(prev_cand.unwrap_or(old_current));
                self.current_epoch = msg_epoch;
                Ok(len)
            }
            // The candidates drop and scrub themselves; committed state is
            // untouched.
            Err(err) => Err(err),
        }
    }
}

impl<Proto: Protocol> DatagramRecv<Proto> {
    /// Open a datagram that was sealed at `counter`, writing plaintext into
    /// `output`.
    ///
    /// **Out of order, and no replay rejection.** The same `counter` can be
    /// decrypted more than once, and counters may arrive in any order or not
    /// at all — nothing here rejects a replay. **Replay protection is
    /// explicitly the caller's duty**: a datagram protocol that must reject
    /// duplicates has to track the counters it has already accepted
    /// (typically a sliding window).
    ///
    /// `output` must be at least `ciphertext.len() - OVERHEAD` bytes.
    ///
    /// # Epoch ratchet and its commit-and-cap discipline
    ///
    /// For a plain half (from [`into_datagram`](Transport::into_datagram))
    /// this takes no committed state and cannot fail from key age. For an
    /// epoch-ratcheting half (from
    /// [`into_datagram_with_epoch`](Transport::into_datagram_with_epoch)) the
    /// key that opens a datagram is chosen by its epoch,
    /// `counter / epoch_size`, and two rules protect the committed keys from
    /// unauthenticated input:
    ///
    /// - **Commit only after the tag verifies.** A datagram claiming a
    ///   future epoch is opened under a *candidate* key, derived without
    ///   disturbing the committed ones; the receiver's committed keys advance
    ///   only once the AEAD tag authenticates the packet. A forged packet
    ///   bearing a huge counter is therefore rejected without moving the
    ///   receiver forward, so it cannot desynchronise the session (a
    ///   one-packet denial of service).
    /// - **Bounded look-ahead.** A datagram more than [`MAX_EPOCH_JUMP`]
    ///   epochs beyond the committed epoch is refused **without deriving any
    ///   key**, so a forged far-future counter cannot demand an unbounded
    ///   chain of key derivations (a CPU denial of service).
    ///
    /// A straggler from the epoch immediately before the current one still
    /// opens, under the retained previous key; a datagram from any older
    /// epoch fails with the ordinary decrypt error, its key having been
    /// ratcheted away.
    ///
    /// On a [`DecryptionFailed`](HandshakeError::DecryptionFailed) error —
    /// from a tampered ciphertext, the wrong `ad`, the wrong `counter`, or a
    /// refused epoch — `output` holds **unauthenticated** bytes that must not
    /// be read, per the AEAD output contract, and the committed keys are
    /// unchanged.
    pub fn decrypt_at(
        &mut self,
        counter: u64,
        ad: &[u8],
        ciphertext: &[u8],
        output: &mut [u8],
    ) -> Result<usize, HandshakeError> {
        match &mut self.keys {
            RecvKeys::Plain(cipher) => cipher.decrypt_at(counter, ad, ciphertext, output),
            RecvKeys::Ratchet(ratchet) => ratchet.decrypt_at(counter, ad, ciphertext, output),
        }
    }

    /// The session identifier — the same value on both halves and on the
    /// peer.
    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }
}
