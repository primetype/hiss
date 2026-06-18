//! Noise handshake errors.

use super::cipher_state::MAX_MESSAGE_LEN;

/// Errors that can occur during a Noise handshake.
#[derive(Debug, thiserror::Error)]
pub enum HandshakeError {
    /// A cryptographic operation failed (e.g. DH, key generation).
    #[error("crypto operation failed: {0}")]
    Crypto(String),

    /// The incoming message is shorter than expected.
    #[error("incoming message too short — expected more data")]
    MessageTooShort,

    /// AEAD decryption failed — authentication tag mismatch.
    #[error("decryption failed — authentication tag mismatch")]
    DecryptionFailed,

    /// A local static key was required but not provided.
    #[error("missing local static key")]
    MissingStaticKey,

    /// A local ephemeral key was expected but has not been generated.
    #[error("missing local ephemeral key")]
    MissingEphemeralKey,

    /// The remote party's static public key was required but not available.
    #[error("missing remote static public key")]
    MissingRemoteStatic,

    /// The remote party's ephemeral public key was expected but not received.
    #[error("missing remote ephemeral public key")]
    MissingRemoteEphemeral,

    /// A pre-shared key was required but not provided.
    #[error("missing pre-shared key")]
    MissingPsk,

    /// The nonce counter has overflowed (2^64 − 1 messages encrypted).
    #[error("nonce overflow — session must be rekeyed")]
    NonceOverflow,

    /// A public key could not be deserialised from the wire.
    #[error("invalid public key: {0}")]
    InvalidPublicKey(String),

    /// The incoming message has the wrong length.
    #[error("unexpected message length: expected {expected} bytes, got {actual}")]
    UnexpectedMessageLength {
        /// Expected byte count (computed from the token list).
        expected: usize,
        /// Actual byte count of the received message.
        actual: usize,
    },

    /// A message exceeds the Noise 65535-byte maximum length (spec §3).
    #[error("message too long: {len} bytes exceeds the {MAX_MESSAGE_LEN}-byte Noise maximum")]
    MessageTooLong {
        /// Length of the offending message (on the wire, including any tag).
        len: usize,
    },

    /// The output buffer is too small for the result.
    #[error("output buffer too small: need {needed} bytes, got {actual}")]
    OutputBufferTooSmall {
        /// Minimum required buffer size.
        needed: usize,
        /// Actual buffer size provided.
        actual: usize,
    },

    /// Rekey was called on a CipherState without a key.
    #[error("cannot rekey — no key has been established")]
    RekeyWithoutKey,

    /// An I/O error occurred while reading or writing the handshake
    /// transcript over a [`std::io`] (or, behind the `async-io`
    /// feature, a `tokio::io`) stream.
    #[error("handshake I/O error: {0}")]
    Io(#[from] std::io::Error),
}
