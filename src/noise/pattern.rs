//! Noise handshake patterns.
//!
//! A pattern defines the pre-message knowledge and the sequence of
//! handshake messages. Each message is a type-level list of tokens
//! wrapped in a [`Message`] with a direction.

use super::tokens::*;

/// A Noise handshake pattern.
///
/// Implementors encode the full message flow as associated types
/// built from [`Cons`]/[`Nil`] lists of [`Message`]s, making the
/// handshake structure available to the compiler at monomorphisation
/// time.
pub trait Pattern {
    /// Noise name component (e.g. `"IKpsk1"`).
    const NAME: &'static str;

    /// Number of handshake messages (excluding pre-messages).
    const NUM_MESSAGES: usize;

    /// Whether a PSK modifier is present.
    const HAS_PSK: bool;

    /// Pre-message pattern — type-level list of [`Message`]s
    /// describing knowledge held before the handshake begins.
    type PreMessages;

    /// Handshake message pattern — type-level list of [`Message`]s
    /// describing the three (or more) handshake flights.
    type Messages;
}

// ── N ───────────────────────────────────────────────────────────

/// `N` — one-way pattern. The sender knows the recipient's static
/// key. No sender authentication.
///
/// Used for encrypting data at rest to a known public key (e.g.
/// sealing per-pair PSKs to the device's own Secure Enclave key).
/// Each seal operation uses a fresh ephemeral key, providing
/// forward secrecy per write.
///
/// ```text
/// N:
///   <- s
///   ...
///   -> e, es
/// ```
pub struct N;

impl Pattern for N {
    const NAME: &'static str = "N";
    const NUM_MESSAGES: usize = 1;
    const HAS_PSK: bool = false;

    // Pre-messages: <- s (recipient's static key known)
    type PreMessages = Cons<Message<ToInitiator, Cons<S, Nil>>, Nil>;

    // -> e, es
    type Messages = Cons<Message<ToResponder, Cons<E, Cons<Es, Nil>>>, Nil>;
}

// ── K ───────────────────────────────────────────────────────────

/// `K` — one-way authenticated pattern. Both static keys are known
/// before the handshake. The sender is authenticated via `ss`.
///
/// Used for sealed envelopes between two peers who have already
/// completed a trust ceremony — the message is confidential,
/// sender-authenticated, and forward-secret.
///
/// ```text
/// K:
///   -> s
///   <- s
///   ...
///   -> e, es, ss
/// ```
pub struct K;

impl Pattern for K {
    const NAME: &'static str = "K";
    const NUM_MESSAGES: usize = 1;
    const HAS_PSK: bool = false;

    // Pre-messages: -> s, <- s (both static keys known)
    type PreMessages =
        Cons<Message<ToResponder, Cons<S, Nil>>, Cons<Message<ToInitiator, Cons<S, Nil>>, Nil>>;

    // -> e, es, ss
    type Messages = Cons<Message<ToResponder, Cons<E, Cons<Es, Cons<Ss, Nil>>>>, Nil>;
}

// ── Kpsk0 ────────────────────────────────────────────────────────

/// `Kpsk0` — one-way authenticated pattern with PSK at position 0.
/// Both static keys are known; the PSK is mixed before the ephemeral
/// key, binding the entire message to the ceremony-established trust.
///
/// ```text
/// Kpsk0:
///   -> s
///   <- s
///   ...
///   -> psk, e, es, ss
/// ```
pub struct Kpsk0;

impl Pattern for Kpsk0 {
    const NAME: &'static str = "Kpsk0";
    const NUM_MESSAGES: usize = 1;
    const HAS_PSK: bool = true;

    // Pre-messages: -> s, <- s
    type PreMessages =
        Cons<Message<ToResponder, Cons<S, Nil>>, Cons<Message<ToInitiator, Cons<S, Nil>>, Nil>>;

    // -> psk, e, es, ss
    type Messages = Cons<Message<ToResponder, Cons<Psk, Cons<E, Cons<Es, Cons<Ss, Nil>>>>>, Nil>;
}

// ── IKpsk1 ──────────────────────────────────────────────────────

/// `IKpsk1` — the initiator knows the responder's static key and
/// transmits their own static key encrypted in msg1. A PSK is
/// mixed at the end of msg1.
///
/// The initiator's identity is revealed to the responder during
/// msg1 processing (after `es` DH), enabling per-pair PSK lookup
/// before the `psk` token.
///
/// ```text
/// IKpsk1:
///   <- s
///   ...
///   -> e, es, s, ss, psk
///   <- e, ee, se
/// ```
pub struct IKpsk1;

impl Pattern for IKpsk1 {
    const NAME: &'static str = "IKpsk1";
    const NUM_MESSAGES: usize = 2;
    const HAS_PSK: bool = true;

    // Pre-messages: <- s
    type PreMessages = Cons<Message<ToInitiator, Cons<S, Nil>>, Nil>;

    // -> e, es, s, ss, psk
    // <- e, ee, se
    type Messages = Cons<
        Message<ToResponder, Cons<E, Cons<Es, Cons<S, Cons<Ss, Cons<Psk, Nil>>>>>>,
        Cons<Message<ToInitiator, Cons<E, Cons<Ee, Cons<Se, Nil>>>>, Nil>,
    >;
}
