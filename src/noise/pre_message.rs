//! Cons-list-driven pre-message processing.
//!
//! Pre-messages describe public keys known to both parties before the
//! interactive handshake begins. For IKpsk1, the pre-message `<- s`
//! means the responder's static public key is mixed into the
//! handshake hash by both sides.
//!
//! Processing is driven by trait recursion over the Cons-list from
//! [`Pattern::PreMessages`](super::pattern::Pattern::PreMessages).

use super::cipher::Cipher;
use super::error::HandshakeError;
use super::hash::Hash;
use super::role::{Initiator, Responder, Role};
use super::symmetric_state::SymmetricState;
use super::tokens::*;
use crate::curve::{CryptoProvider, Curve};

/// Process a pre-message Cons-list, mixing known public keys into
/// the handshake hash.
///
/// Implemented for `Nil` (base case) and `Cons<Message<Dir, Tokens>, Rest>`
/// (recursive case).
pub trait ProcessPreMessage<R: Role, Cu: Curve, Ci: Cipher, H: Hash> {
    /// Process this pre-message element (and recursively its tail).
    fn process<CP: CryptoProvider<Cu>>(
        symmetric: &mut SymmetricState<Ci, H>,
        s_pub: &Option<Cu::PublicKey>,
        rs: &Option<Cu::PublicKey>,
    ) -> Result<(), HandshakeError>;
}

// ── Base case: Nil ────────────────────────────────────────────

impl<R: Role, Cu: Curve, Ci: Cipher, H: Hash> ProcessPreMessage<R, Cu, Ci, H> for Nil {
    fn process<CP: CryptoProvider<Cu>>(
        _symmetric: &mut SymmetricState<Ci, H>,
        _s_pub: &Option<Cu::PublicKey>,
        _rs: &Option<Cu::PublicKey>,
    ) -> Result<(), HandshakeError> {
        Ok(())
    }
}

// ── Pre-message token processing ──────────────────────────────

/// Process a single pre-message token list.
///
/// For pre-messages, only `S` tokens are meaningful (they indicate
/// a static key known in advance).
pub trait ProcessPreToken<R: Role, Cu: Curve, Ci: Cipher, H: Hash, Dir> {
    fn process<CP: CryptoProvider<Cu>>(
        symmetric: &mut SymmetricState<Ci, H>,
        s_pub: &Option<Cu::PublicKey>,
        rs: &Option<Cu::PublicKey>,
    ) -> Result<(), HandshakeError>;
}

// Base case for token list.
impl<R: Role, Cu: Curve, Ci: Cipher, H: Hash, Dir> ProcessPreToken<R, Cu, Ci, H, Dir> for Nil {
    fn process<CP: CryptoProvider<Cu>>(
        _symmetric: &mut SymmetricState<Ci, H>,
        _s_pub: &Option<Cu::PublicKey>,
        _rs: &Option<Cu::PublicKey>,
    ) -> Result<(), HandshakeError> {
        Ok(())
    }
}

// S token in a ToInitiator pre-message (`<- s`): responder's static
// key is known.
//
// Initiator: the responder's key is `rs` (remote static).
// Responder: the responder's key is `s_pub` (our own static).

impl<Cu, Ci, H, Rest> ProcessPreToken<Initiator, Cu, Ci, H, ToInitiator> for Cons<S, Rest>
where
    Cu: Curve,
    Cu::PublicKey: AsRef<[u8]>,
    Ci: Cipher,
    H: Hash,
    Rest: ProcessPreToken<Initiator, Cu, Ci, H, ToInitiator>,
{
    fn process<CP: CryptoProvider<Cu>>(
        symmetric: &mut SymmetricState<Ci, H>,
        s_pub: &Option<Cu::PublicKey>,
        rs: &Option<Cu::PublicKey>,
    ) -> Result<(), HandshakeError> {
        let key = rs.as_ref().ok_or(HandshakeError::MissingRemoteStatic)?;
        symmetric.mix_hash(key.as_ref());
        Rest::process::<CP>(symmetric, s_pub, rs)
    }
}

impl<Cu, Ci, H, Rest> ProcessPreToken<Responder, Cu, Ci, H, ToInitiator> for Cons<S, Rest>
where
    Cu: Curve,
    Cu::PublicKey: AsRef<[u8]>,
    Ci: Cipher,
    H: Hash,
    Rest: ProcessPreToken<Responder, Cu, Ci, H, ToInitiator>,
{
    fn process<CP: CryptoProvider<Cu>>(
        symmetric: &mut SymmetricState<Ci, H>,
        s_pub: &Option<Cu::PublicKey>,
        rs: &Option<Cu::PublicKey>,
    ) -> Result<(), HandshakeError> {
        let key = s_pub.as_ref().ok_or(HandshakeError::MissingStaticKey)?;
        symmetric.mix_hash(key.as_ref());
        Rest::process::<CP>(symmetric, s_pub, rs)
    }
}

// S token in a ToResponder pre-message (`-> s`): initiator's static
// key is known.
//
// Initiator: the initiator's key is `s_pub` (our own static).
// Responder: the initiator's key is `rs` (remote static).

impl<Cu, Ci, H, Rest> ProcessPreToken<Initiator, Cu, Ci, H, ToResponder> for Cons<S, Rest>
where
    Cu: Curve,
    Cu::PublicKey: AsRef<[u8]>,
    Ci: Cipher,
    H: Hash,
    Rest: ProcessPreToken<Initiator, Cu, Ci, H, ToResponder>,
{
    fn process<CP: CryptoProvider<Cu>>(
        symmetric: &mut SymmetricState<Ci, H>,
        s_pub: &Option<Cu::PublicKey>,
        rs: &Option<Cu::PublicKey>,
    ) -> Result<(), HandshakeError> {
        let key = s_pub.as_ref().ok_or(HandshakeError::MissingStaticKey)?;
        symmetric.mix_hash(key.as_ref());
        Rest::process::<CP>(symmetric, s_pub, rs)
    }
}

impl<Cu, Ci, H, Rest> ProcessPreToken<Responder, Cu, Ci, H, ToResponder> for Cons<S, Rest>
where
    Cu: Curve,
    Cu::PublicKey: AsRef<[u8]>,
    Ci: Cipher,
    H: Hash,
    Rest: ProcessPreToken<Responder, Cu, Ci, H, ToResponder>,
{
    fn process<CP: CryptoProvider<Cu>>(
        symmetric: &mut SymmetricState<Ci, H>,
        s_pub: &Option<Cu::PublicKey>,
        rs: &Option<Cu::PublicKey>,
    ) -> Result<(), HandshakeError> {
        let key = rs.as_ref().ok_or(HandshakeError::MissingRemoteStatic)?;
        symmetric.mix_hash(key.as_ref());
        Rest::process::<CP>(symmetric, s_pub, rs)
    }
}

// ── Recursive case: Cons<Message<Dir, Tokens>, Rest> ──────────

impl<R, Dir, Tokens, Rest, Cu, Ci, H> ProcessPreMessage<R, Cu, Ci, H>
    for Cons<Message<Dir, Tokens>, Rest>
where
    R: Role,
    Cu: Curve,
    Cu::PublicKey: AsRef<[u8]>,
    Ci: Cipher,
    H: Hash,
    Tokens: ProcessPreToken<R, Cu, Ci, H, Dir>,
    Rest: ProcessPreMessage<R, Cu, Ci, H>,
{
    fn process<CP: CryptoProvider<Cu>>(
        symmetric: &mut SymmetricState<Ci, H>,
        s_pub: &Option<Cu::PublicKey>,
        rs: &Option<Cu::PublicKey>,
    ) -> Result<(), HandshakeError> {
        Tokens::process::<CP>(symmetric, s_pub, rs)?;
        Rest::process::<CP>(symmetric, s_pub, rs)
    }
}
