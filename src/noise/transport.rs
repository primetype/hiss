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
/// e.g. `Transport<Noise<IKpsk1, P256, ChaChaPoly, Blake2b>>`. The
/// protocol identity is carried at the type level with zero runtime
/// cost, allowing consumers to name the transport using their protocol
/// type alias:
///
/// ```ignore
/// type MyProtocol = Noise<IKpsk1, P256, ChaChaPoly, Blake2b>;
/// let transport: Transport<MyProtocol> = /* handshake */;
/// ```
///
/// After the handshake finishes, all further communication uses two
/// [`CipherState`]s — one for each direction. The [`SessionId`]
/// uniquely identifies this session — both peers produce the same
/// value from a completed handshake.
///
/// Ephemeral keys are `Option` because one-way patterns (N, K, Kpsk0)
/// produce only one ephemeral: the sender has `local_ephemeral` but no
/// `remote_ephemeral`, and vice versa for the receiver. Interactive
/// patterns (IK, XK) always produce both.
pub struct Transport<N: Protocol> {
    send: CipherState<N::Cipher>,
    recv: CipherState<N::Cipher>,
    session_id: SessionId,
    /// Our ephemeral public key for this session, if we generated one.
    local_ephemeral: Option<<N::Curve as Curve>::PublicKey>,
    /// The remote party's ephemeral public key, if they sent one.
    remote_ephemeral: Option<<N::Curve as Curve>::PublicKey>,
}

impl<N: Protocol> Transport<N> {
    pub(crate) fn new(
        send: CipherState<N::Cipher>,
        recv: CipherState<N::Cipher>,
        session_id: SessionId,
        local_ephemeral: Option<<N::Curve as Curve>::PublicKey>,
        remote_ephemeral: Option<<N::Curve as Curve>::PublicKey>,
    ) -> Self {
        Self {
            send,
            recv,
            session_id,
            local_ephemeral,
            remote_ephemeral,
        }
    }

    /// The number of bytes added to each plaintext by encryption (the
    /// AEAD authentication tag). Use this to size output buffers:
    /// `plaintext.len() + Transport::OVERHEAD`.
    pub const OVERHEAD: usize = <N::Cipher as Cipher>::TAG_SIZE;

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
    /// Call this periodically to limit the amount of data encrypted
    /// under a single key.
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
    /// receiver side of one-way patterns (N, K, Kpsk0).
    pub fn local_ephemeral(&self) -> Option<&<N::Curve as Curve>::PublicKey> {
        self.local_ephemeral.as_ref()
    }

    /// The remote party's ephemeral public key, if they sent one.
    ///
    /// Always `Some` for interactive patterns (IK, XK). `None` for the
    /// sender side of one-way patterns (N, K, Kpsk0).
    pub fn remote_ephemeral(&self) -> Option<&<N::Curve as Curve>::PublicKey> {
        self.remote_ephemeral.as_ref()
    }

    /// Split the transport into independent send and receive halves.
    ///
    /// Each half owns its own [`CipherState`] and a clone of both
    /// ephemeral keys and the [`SessionId`].
    pub fn split(self) -> (TransportSend<N>, TransportRecv<N>) {
        let send = TransportSend {
            cipher: self.send,
            session_id: self.session_id.clone(),
            local_ephemeral: self.local_ephemeral.clone(),
            remote_ephemeral: self.remote_ephemeral.clone(),
        };
        let recv = TransportRecv {
            cipher: self.recv,
            session_id: self.session_id,
            local_ephemeral: self.local_ephemeral,
            remote_ephemeral: self.remote_ephemeral,
        };
        (send, recv)
    }
}

/// The send half of a split [`Transport`].
///
/// Owns the outbound [`CipherState`] and both ephemeral public keys.
pub struct TransportSend<N: Protocol> {
    cipher: CipherState<N::Cipher>,
    session_id: SessionId,
    local_ephemeral: Option<<N::Curve as Curve>::PublicKey>,
    remote_ephemeral: Option<<N::Curve as Curve>::PublicKey>,
}

impl<N: Protocol> TransportSend<N> {
    /// The number of bytes added to each plaintext by encryption.
    pub const OVERHEAD: usize = <N::Cipher as Cipher>::TAG_SIZE;

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
    pub fn local_ephemeral(&self) -> Option<&<N::Curve as Curve>::PublicKey> {
        self.local_ephemeral.as_ref()
    }

    /// The remote party's ephemeral public key for this session.
    pub fn remote_ephemeral(&self) -> Option<&<N::Curve as Curve>::PublicKey> {
        self.remote_ephemeral.as_ref()
    }
}

/// The receive half of a split [`Transport`].
///
/// Owns the inbound [`CipherState`] and both ephemeral public keys.
pub struct TransportRecv<N: Protocol> {
    cipher: CipherState<N::Cipher>,
    session_id: SessionId,
    local_ephemeral: Option<<N::Curve as Curve>::PublicKey>,
    remote_ephemeral: Option<<N::Curve as Curve>::PublicKey>,
}

impl<N: Protocol> TransportRecv<N> {
    /// The number of bytes added to each plaintext by encryption.
    pub const OVERHEAD: usize = <N::Cipher as Cipher>::TAG_SIZE;

    /// Decrypt a transport message, writing plaintext into `output`.
    ///
    /// `output` must be at least `ciphertext.len() - OVERHEAD` bytes.
    /// Returns the number of bytes written.
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
    pub fn local_ephemeral(&self) -> Option<&<N::Curve as Curve>::PublicKey> {
        self.local_ephemeral.as_ref()
    }

    /// The remote party's ephemeral public key for this session.
    pub fn remote_ephemeral(&self) -> Option<&<N::Curve as Curve>::PublicKey> {
        self.remote_ephemeral.as_ref()
    }
}
