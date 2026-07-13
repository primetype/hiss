//! Post-handshake transport — a pair of directional [`CipherState`]s.

use super::Protocol;
use super::cipher::Cipher;
use super::cipher_state::CipherState;
use super::error::HandshakeError;
use super::session_id::SessionId;
use crate::curve::Curve;

/// A completed Noise transport.
///
/// Parameterised over the [`Protocol`] descriptor that produced it —
/// e.g. `Transport<IKpsk1>`. The
/// protocol identity is carried at the type level with zero runtime
/// cost, allowing consumers to name the transport using their protocol
/// type alias:
///
/// ```ignore
/// type MyProtocol = IKpsk1;
/// let transport: Transport<MyProtocol> = /* handshake */;
/// ```
///
/// After the handshake finishes, all further communication uses two
/// [`CipherState`]s — one for each direction. The [`SessionId`]
/// uniquely identifies this session — both peers produce the same
/// value from a completed handshake.
///
/// # Delivery contract
///
/// The transport requires a **reliable, in-order, exactly-once** byte
/// stream. Each direction's nonce counter advances only on AEAD success
/// and is never reset, so the sender's counter for record *k* must meet
/// the receiver's counter for record *k*. A single **lost, reordered, or
/// duplicated** record permanently desynchronises that direction — every
/// subsequent [`receive`](Self::receive) then fails. Run the transport
/// over a reliable, ordered substrate (e.g. TCP, or TLS-style record
/// framing); it does not tolerate datagram loss or reordering on its own.
///
/// A transport-record decrypt failure is therefore **terminal**: tear the
/// session down. Do **not** retry the record, and do **not** attempt to
/// resynchronise from a counter taken off the wire — the counter is
/// implicit and never transmitted, so any "resync" value would be
/// attacker-supplied.
///
/// Ephemeral keys are `Option` because one-way patterns (Proto, K, Kpsk0)
/// produce only one ephemeral: the sender has `local_ephemeral` but no
/// `remote_ephemeral`, and vice versa for the receiver. Interactive
/// patterns (IK, XK) always produce both.
pub struct Transport<Proto: Protocol> {
    send: CipherState<Proto::Cipher>,
    recv: CipherState<Proto::Cipher>,
    session_id: SessionId,
    /// Our ephemeral public key for this session, if we generated one.
    local_ephemeral: Option<<Proto::Curve as Curve>::PublicKey>,
    /// The remote party's ephemeral public key, if they sent one.
    remote_ephemeral: Option<<Proto::Curve as Curve>::PublicKey>,
    /// The remote party's static public key, if the handshake
    /// established one (via a pre-message or an `s` token).
    remote_static: Option<<Proto::Curve as Curve>::PublicKey>,
}

impl<Proto: Protocol> Transport<Proto> {
    pub(crate) fn new(
        send: CipherState<Proto::Cipher>,
        recv: CipherState<Proto::Cipher>,
        session_id: SessionId,
        local_ephemeral: Option<<Proto::Curve as Curve>::PublicKey>,
        remote_ephemeral: Option<<Proto::Curve as Curve>::PublicKey>,
        remote_static: Option<<Proto::Curve as Curve>::PublicKey>,
    ) -> Self {
        Self {
            send,
            recv,
            session_id,
            local_ephemeral,
            remote_ephemeral,
            remote_static,
        }
    }

    /// The number of bytes added to each plaintext by encryption (the
    /// AEAD authentication tag). Use this to size output buffers:
    /// `plaintext.len() + Transport::OVERHEAD`.
    pub const OVERHEAD: usize = <Proto::Cipher as Cipher>::TAG_SIZE;

    /// Encrypt a transport message, writing ciphertext + tag into
    /// `output`.
    ///
    /// `output` must be at least `plaintext.len() + OVERHEAD` bytes.
    /// Returns the number of bytes written.
    pub fn send(&mut self, plaintext: &[u8], output: &mut [u8]) -> Result<usize, HandshakeError> {
        self.send.encrypt_with_ad(&[], plaintext, output)
    }

    /// Decrypt a transport message, writing plaintext into `output`.
    ///
    /// `output` must be at least `ciphertext.len() - OVERHEAD` bytes.
    /// Returns the number of bytes written.
    ///
    /// Records must arrive **in order and exactly once** (see the
    /// [type-level delivery contract](Transport#delivery-contract)). On
    /// any error the receive nonce does **not** advance; treat a failure
    /// as **terminal** and tear the session down rather than retrying the
    /// record. On a [`DecryptionFailed`](HandshakeError::DecryptionFailed)
    /// error the unverified plaintext has already been written into
    /// `output`, so `output` holds **unauthenticated** bytes that must not
    /// be read.
    pub fn receive(
        &mut self,
        ciphertext: &[u8],
        output: &mut [u8],
    ) -> Result<usize, HandshakeError> {
        self.recv.decrypt_with_ad(&[], ciphertext, output)
    }

    /// Re-key both the send and receive CipherStates.
    ///
    /// Noise spec §5.1: derives a new key from the existing key
    /// using `ENCRYPT(k, 2^64−1, "", zeros)`. The nonce counters
    /// are **not** reset — they continue from their current values.
    ///
    /// Rekeying is **application-driven**: there is no automatic rekey,
    /// and `hiss` never calls this for you. It is a forward-secrecy
    /// measure — the caller invokes it on its own schedule to limit the
    /// data encrypted under a single key. It is **not** needed to avoid
    /// nonce exhaustion: each direction has an independent 64-bit counter
    /// (~2⁶⁴ messages before [`NonceOverflow`](HandshakeError::NonceOverflow)),
    /// which is not a practical concern. Both peers must rekey in lockstep
    /// — a rekey on one side that the other does not mirror desynchronises
    /// that direction.
    pub fn rekey(&mut self) -> Result<(), HandshakeError> {
        self.send.rekey()?;
        self.recv.rekey()?;
        Ok(())
    }

    /// The unique identifier for this session.
    ///
    /// Derived from the Noise handshake hash — both peers produce the
    /// same value from a completed handshake.
    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    /// Our ephemeral public key for this session, if we generated one.
    ///
    /// Always `Some` for interactive patterns (IK, XK). `None` for the
    /// receiver side of one-way patterns (Proto, K, Kpsk0).
    pub fn local_ephemeral(&self) -> Option<&<Proto::Curve as Curve>::PublicKey> {
        self.local_ephemeral.as_ref()
    }

    /// The remote party's ephemeral public key, if they sent one.
    ///
    /// Always `Some` for interactive patterns (IK, XK). `None` for the
    /// sender side of one-way patterns (Proto, K, Kpsk0).
    pub fn remote_ephemeral(&self) -> Option<&<Proto::Curve as Curve>::PublicKey> {
        self.remote_ephemeral.as_ref()
    }

    /// The remote party's static public key — the peer's verified-by-DH
    /// identity — if the handshake established one (via a pre-message or
    /// an `s` token).
    ///
    /// `None` only for patterns whose peer is anonymous (e.g. `NN`, or
    /// the responder's view of `N`/`NK`).
    pub fn remote_static(&self) -> Option<&<Proto::Curve as Curve>::PublicKey> {
        self.remote_static.as_ref()
    }

    /// Split the transport into independent send and receive halves.
    ///
    /// Each half owns its own [`CipherState`] and a clone of the peer
    /// keys and the [`SessionId`].
    pub fn split(self) -> (TransportSend<Proto>, TransportRecv<Proto>) {
        let send = TransportSend {
            cipher: self.send,
            session_id: self.session_id.clone(),
            local_ephemeral: self.local_ephemeral.clone(),
            remote_ephemeral: self.remote_ephemeral.clone(),
            remote_static: self.remote_static.clone(),
        };
        let recv = TransportRecv {
            cipher: self.recv,
            session_id: self.session_id,
            local_ephemeral: self.local_ephemeral,
            remote_ephemeral: self.remote_ephemeral,
            remote_static: self.remote_static,
        };
        (send, recv)
    }
}

/// The send half of a split [`Transport`].
///
/// Owns the outbound [`CipherState`] and both ephemeral public keys.
pub struct TransportSend<Proto: Protocol> {
    cipher: CipherState<Proto::Cipher>,
    session_id: SessionId,
    local_ephemeral: Option<<Proto::Curve as Curve>::PublicKey>,
    remote_ephemeral: Option<<Proto::Curve as Curve>::PublicKey>,
    remote_static: Option<<Proto::Curve as Curve>::PublicKey>,
}

impl<Proto: Protocol> TransportSend<Proto> {
    /// The number of bytes added to each plaintext by encryption.
    pub const OVERHEAD: usize = <Proto::Cipher as Cipher>::TAG_SIZE;

    /// Encrypt a transport message, writing ciphertext + tag into `output`.
    ///
    /// `output` must be at least `plaintext.len() + OVERHEAD` bytes.
    /// Returns the number of bytes written.
    pub fn encrypt(
        &mut self,
        plaintext: &[u8],
        output: &mut [u8],
    ) -> Result<usize, HandshakeError> {
        self.cipher.encrypt_with_ad(&[], plaintext, output)
    }

    /// Re-key the send cipher.
    pub fn rekey(&mut self) -> Result<(), HandshakeError> {
        self.cipher.rekey()
    }

    /// The session identifier — same value on both halves.
    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    /// Our ephemeral public key for this session.
    pub fn local_ephemeral(&self) -> Option<&<Proto::Curve as Curve>::PublicKey> {
        self.local_ephemeral.as_ref()
    }

    /// The remote party's ephemeral public key for this session.
    pub fn remote_ephemeral(&self) -> Option<&<Proto::Curve as Curve>::PublicKey> {
        self.remote_ephemeral.as_ref()
    }

    /// The remote party's static public key, if the handshake
    /// established one.
    pub fn remote_static(&self) -> Option<&<Proto::Curve as Curve>::PublicKey> {
        self.remote_static.as_ref()
    }
}

/// The receive half of a split [`Transport`].
///
/// Owns the inbound [`CipherState`] and both ephemeral public keys.
pub struct TransportRecv<Proto: Protocol> {
    cipher: CipherState<Proto::Cipher>,
    session_id: SessionId,
    local_ephemeral: Option<<Proto::Curve as Curve>::PublicKey>,
    remote_ephemeral: Option<<Proto::Curve as Curve>::PublicKey>,
    remote_static: Option<<Proto::Curve as Curve>::PublicKey>,
}

impl<Proto: Protocol> TransportRecv<Proto> {
    /// The number of bytes added to each plaintext by encryption.
    pub const OVERHEAD: usize = <Proto::Cipher as Cipher>::TAG_SIZE;

    /// Decrypt a transport message, writing plaintext into `output`.
    ///
    /// `output` must be at least `ciphertext.len() - OVERHEAD` bytes.
    /// Returns the number of bytes written.
    ///
    /// Records must arrive **in order and exactly once** (see the
    /// [`Transport` delivery contract](Transport#delivery-contract)). On
    /// any error the receive nonce does **not** advance; a failure is
    /// **terminal** — tear the session down rather than retrying or
    /// resynchronising from the wire. On a
    /// [`DecryptionFailed`](HandshakeError::DecryptionFailed) error
    /// `output` holds **unauthenticated** bytes that must not be read.
    pub fn decrypt(
        &mut self,
        ciphertext: &[u8],
        output: &mut [u8],
    ) -> Result<usize, HandshakeError> {
        self.cipher.decrypt_with_ad(&[], ciphertext, output)
    }

    /// Re-key the receive cipher.
    pub fn rekey(&mut self) -> Result<(), HandshakeError> {
        self.cipher.rekey()
    }

    /// The session identifier — same value on both halves.
    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    /// Our ephemeral public key for this session.
    pub fn local_ephemeral(&self) -> Option<&<Proto::Curve as Curve>::PublicKey> {
        self.local_ephemeral.as_ref()
    }

    /// The remote party's ephemeral public key for this session.
    pub fn remote_ephemeral(&self) -> Option<&<Proto::Curve as Curve>::PublicKey> {
        self.remote_ephemeral.as_ref()
    }

    /// The remote party's static public key, if the handshake
    /// established one.
    pub fn remote_static(&self) -> Option<&<Proto::Curve as Curve>::PublicKey> {
        self.remote_static.as_ref()
    }
}
