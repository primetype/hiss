//! Handshake role markers — [`Initiator`] and [`Responder`].
//!
//! Each role determines which message directions are "send" vs
//! "receive" through the associated types on [`Role`].

use super::tokens::{ToInitiator, ToResponder};

mod sealed {
    pub trait Sealed {}
}

/// A Noise handshake role.
///
/// Binds a participant to its send and receive directions and
/// determines key selection for asymmetric DH tokens.
///
/// This is a sealed trait, implemented only by [`Initiator`] and
/// [`Responder`]; downstream crates cannot add further roles.
pub trait Role: sealed::Sealed {
    /// The direction this role writes (sends) messages.
    type SendDir;

    /// The direction this role reads (receives) messages.
    type RecvDir;

    /// `true` for the initiator, `false` for the responder.
    const IS_INITIATOR: bool;
}

/// The initiator — sends the first message.
pub struct Initiator;

impl sealed::Sealed for Initiator {}

impl Role for Initiator {
    type SendDir = ToResponder;
    type RecvDir = ToInitiator;
    const IS_INITIATOR: bool = true;
}

/// The responder — receives the first message.
pub struct Responder;

impl sealed::Sealed for Responder {}

impl Role for Responder {
    type SendDir = ToInitiator;
    type RecvDir = ToResponder;
    const IS_INITIATOR: bool = false;
}
