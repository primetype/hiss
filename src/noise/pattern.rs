//! Noise handshake patterns.
//!
//! A pattern defines the pre-message knowledge and the sequence of
//! handshake messages. Each message is a type-level list of tokens
//! wrapped in a [`Message`] with a direction.

use super::tokens::*;
use super::well_formed::assert_well_formed;

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

assert_well_formed!(N);

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

assert_well_formed!(K);

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

assert_well_formed!(Kpsk0);

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

assert_well_formed!(IKpsk1);

// ── IK ──────────────────────────────────────────────────────────

/// `IK` — interactive mutual authentication. The initiator knows the
/// responder's static key up front and transmits its own static key,
/// encrypted, in msg1; the responder authenticates in msg2.
///
/// Identical to [`IKpsk1`] without the pre-shared key — full mutual
/// authentication from raw static-key DH alone.
///
/// ```text
/// IK:
///   <- s
///   ...
///   -> e, es, s, ss
///   <- e, ee, se
/// ```
pub struct IK;

impl Pattern for IK {
    const NAME: &'static str = "IK";
    const NUM_MESSAGES: usize = 2;
    const HAS_PSK: bool = false;

    // Pre-messages: <- s (responder's static key known)
    type PreMessages = Cons<Message<ToInitiator, Cons<S, Nil>>, Nil>;

    // -> e, es, s, ss
    // <- e, ee, se
    type Messages = Cons<
        Message<ToResponder, Cons<E, Cons<Es, Cons<S, Cons<Ss, Nil>>>>>,
        Cons<Message<ToInitiator, Cons<E, Cons<Ee, Cons<Se, Nil>>>>, Nil>,
    >;
}

assert_well_formed!(IK);

// ── NK ──────────────────────────────────────────────────────────

/// `NK` — interactive, responder-authenticated handshake. The
/// initiator knows the responder's static key up front and is
/// **anonymous** (it has no static key of its own); only the
/// responder is authenticated, via the `es` DH that binds its static
/// key.
///
/// Like [`IK`] minus the initiator's static key — confidentiality to
/// a known recipient plus a fresh responder ephemeral, without
/// initiator authentication.
///
/// ```text
/// NK:
///   <- s
///   ...
///   -> e, es
///   <- e, ee
/// ```
pub struct NK;

impl Pattern for NK {
    const NAME: &'static str = "NK";
    const NUM_MESSAGES: usize = 2;
    const HAS_PSK: bool = false;

    // Pre-messages: <- s (responder's static key known)
    type PreMessages = Cons<Message<ToInitiator, Cons<S, Nil>>, Nil>;

    // -> e, es
    // <- e, ee
    type Messages = Cons<
        Message<ToResponder, Cons<E, Cons<Es, Nil>>>,
        Cons<Message<ToInitiator, Cons<E, Cons<Ee, Nil>>>, Nil>,
    >;
}

assert_well_formed!(NK);

// ── IX ──────────────────────────────────────────────────────────

/// `IX` — interactive mutual authentication with **no pre-messages**:
/// neither party knows the other's static key up front. Both transmit
/// their static keys *during* the handshake (as `s` tokens).
///
/// Because the initiator's static is sent in msg1 **before any DH**, it
/// travels **in the clear** — exposed to a passive eavesdropper. The
/// responder's static is sent in msg2 *after* `ee` keys the cipher, so
/// it is encrypted. Authentication is mutual: the initiator is
/// authenticated to the responder via `se`, the responder to the
/// initiator via `es`.
///
/// Unlike [`IK`], there is no pre-known static on either side — IX
/// trades the initiator's identity privacy for not needing the
/// responder's static key in advance.
///
/// ```text
/// IX:
///   -> e, s
///   <- e, ee, se, s, es
/// ```
pub struct IX;

impl Pattern for IX {
    const NAME: &'static str = "IX";
    const NUM_MESSAGES: usize = 2;
    const HAS_PSK: bool = false;

    // No pre-messages: neither static is known up front.
    type PreMessages = Nil;

    // -> e, s
    // <- e, ee, se, s, es
    type Messages = Cons<
        Message<ToResponder, Cons<E, Cons<S, Nil>>>,
        Cons<
            Message<ToInitiator, Cons<E, Cons<Ee, Cons<Se, Cons<S, Cons<Es, Nil>>>>>>,
            Nil,
        >,
    >;
}

assert_well_formed!(IX);

// ── XK ──────────────────────────────────────────────────────────

/// `XK` — interactive mutual authentication over **three messages**
/// with strong **initiator-identity privacy**. The initiator knows the
/// responder's static key up front (pre-message `<- s`) and
/// authenticates the responder early via `es`. The initiator's own
/// static key is transmitted **encrypted in msg3** (after `ee` has
/// keyed the cipher), so it is hidden from a passive eavesdropper, and
/// is authenticated via `se`.
///
/// Unlike [`IK`] (where the initiator's static rides in msg1), XK defers
/// the initiator's static to a third flight, after both ephemerals are
/// mixed — giving the initiator's identity full forward-secret
/// confidentiality at the cost of an extra round trip.
///
/// ```text
/// XK:
///   <- s
///   ...
///   -> e, es
///   <- e, ee
///   -> s, se
/// ```
pub struct XK;

impl Pattern for XK {
    const NAME: &'static str = "XK";
    const NUM_MESSAGES: usize = 3;
    const HAS_PSK: bool = false;

    // Pre-messages: <- s (responder's static key known to the initiator)
    type PreMessages = Cons<Message<ToInitiator, Cons<S, Nil>>, Nil>;

    // -> e, es
    // <- e, ee
    // -> s, se
    type Messages = Cons<
        Message<ToResponder, Cons<E, Cons<Es, Nil>>>,
        Cons<
            Message<ToInitiator, Cons<E, Cons<Ee, Nil>>>,
            Cons<Message<ToResponder, Cons<S, Cons<Se, Nil>>>, Nil>,
        >,
    >;
}

assert_well_formed!(XK);
