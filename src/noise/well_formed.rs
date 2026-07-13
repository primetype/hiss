//! Compile-time validity guard for Noise handshake patterns.
//!
//! A handshake [`Pattern`] is *well-formed* when every Diffie–Hellman token
//! operates on two keys that have already been transmitted by that point in
//! the message flow (Noise spec §7.3). A malformed pattern — e.g. one whose
//! first message performs `es` before the initiator has sent `e` — is a
//! **compile error**, not a runtime or interop failure.
//!
//! # How it works — rejection by absent impl
//!
//! The guard is a type-level fold over the pattern's pre-messages and
//! handshake messages. It threads a [`State`] — five type-level booleans:
//! which of the four keys (initiator/responder × ephemeral/static) have been
//! transmitted so far, plus whether the cipher has been keyed — applying one
//! [`Step`] per token:
//!
//! * `e`/`s` mark the *sending* party's ephemeral/static available — and,
//!   because no party ever transmits the same key twice, require that it was
//!   **not** yet available, catching a duplicated `e`/`s`.
//! * each DH token (`ee`/`es`/`se`/`ss`) has a single [`Step`] impl whose
//!   input [`State`] pins the two keys it consumes to [`True`]. If the fold
//!   reaches the token while either key is still [`False`], **no impl
//!   matches** and the type check fails. The invalid case is rejected not by
//!   a negative assertion but by the simple absence of a transition. Each DH
//!   token also marks the cipher keyed.
//! * `psk` moves no key but marks the cipher keyed.
//!
//! Pre-messages run first from the all-`False` start state, then the
//! handshake messages continue from the resulting state — the *same* fold,
//! since a pre-message `<- s` (responder's static known up front) has the
//! same effect on availability as sending it. A DH token mistakenly placed
//! in a pre-message is rejected for free (nothing is available there yet).
//!
//! [`WellFormed`] ties it together: every DH token's keys must be available,
//! and the cipher must be [`Keyed`] by the end (a pattern that performs no DH
//! or `psk` — e.g. a lone `-> e` — would finalise with transport keys derived
//! only from the public protocol name, and is rejected). It is enforced two
//! ways: the `noise!` macro emits a `WellFormed` assertion at a pattern's
//! definition site, and the [`Protocol`](super::Protocol) impl requires it,
//! so an ill-formed pattern can never parameterise a handshake.

use std::marker::PhantomData;

use super::pattern::Pattern;
use super::role::{Initiator, Responder};
use super::tokens::{
    Cons, ContainsPsk, E, Ee, Es, Message, Nil, Psk, S, Se, Ss, ToInitiator, ToResponder,
};

// ── Type-level booleans and availability state ───────────────────

/// Type-level boolean — the key has been transmitted.
#[doc(hidden)]
pub struct True;

/// Type-level boolean — the key has not been transmitted.
#[doc(hidden)]
pub struct False;

/// Availability state threaded through the fold: which of the four keys have
/// been transmitted so far, in the order initiator-ephemeral,
/// responder-ephemeral, initiator-static, responder-static — plus `CK`, whether
/// the cipher has been keyed by a DH or `psk` token at least once.
#[doc(hidden)]
pub struct State<IE, RE, IS, RS, CK>(PhantomData<(IE, RE, IS, RS, CK)>);

/// The all-`False` starting state — nothing transmitted, cipher unkeyed.
type Start = State<False, False, False, False, False>;

// ── Direction → sending party ────────────────────────────────────

/// The party that *sends* a message (or pre-message) of a given direction.
///
/// A `->` (`ToResponder`) line is sent by the initiator; a `<-`
/// (`ToInitiator`) line by the responder. The same mapping serves
/// pre-messages, where it names whose key is known up front.
#[doc(hidden)]
pub trait SenderOf {
    type Sender;
}
impl SenderOf for ToResponder {
    type Sender = Initiator;
}
impl SenderOf for ToInitiator {
    type Sender = Responder;
}

// ── Per-token transition ─────────────────────────────────────────

/// One token's effect on the availability [`State`], given the sending party.
///
/// `e`/`s` set the sender's bit (and require it unset — no key is sent
/// twice); DH tokens require their two keys already set, encoded by pinning
/// those bits to [`True`] in the only impl; `psk` is the identity. A token
/// with no matching impl for the current state is what makes a malformed
/// pattern fail to compile.
#[doc(hidden)]
#[diagnostic::on_unimplemented(
    message = "malformed Noise pattern: a token acts on a key not yet transmitted (or re-sends one)",
    label = "no valid handshake-state transition exists for this token here"
)]
pub trait Step<Sender, StateIn> {
    type Out;
}

// `e` — the sender transmits its ephemeral (and must not have already).
// Carries the cipher-keyed bit `CK` through unchanged.
impl<RE, IS, RS, CK> Step<Initiator, State<False, RE, IS, RS, CK>> for E {
    type Out = State<True, RE, IS, RS, CK>;
}
impl<IE, IS, RS, CK> Step<Responder, State<IE, False, IS, RS, CK>> for E {
    type Out = State<IE, True, IS, RS, CK>;
}

// `s` — the sender transmits its static (and must not have already).
// Carries `CK` through unchanged.
impl<IE, RE, RS, CK> Step<Initiator, State<IE, RE, False, RS, CK>> for S {
    type Out = State<IE, RE, True, RS, CK>;
}
impl<IE, RE, IS, CK> Step<Responder, State<IE, RE, IS, False, CK>> for S {
    type Out = State<IE, RE, IS, True, CK>;
}

// DH tokens — sender-independent; each consumes two already-transmitted keys
// and keys the cipher (`CK` -> `True`).
// `ee` = DH(initiator-e, responder-e): requires IE and RE.
impl<Sndr, IS, RS, CK> Step<Sndr, State<True, True, IS, RS, CK>> for Ee {
    type Out = State<True, True, IS, RS, True>;
}
// `es` = DH(initiator-e, responder-s): requires IE and RS.
impl<Sndr, RE, IS, CK> Step<Sndr, State<True, RE, IS, True, CK>> for Es {
    type Out = State<True, RE, IS, True, True>;
}
// `se` = DH(initiator-s, responder-e): requires IS and RE.
impl<Sndr, IE, RS, CK> Step<Sndr, State<IE, True, True, RS, CK>> for Se {
    type Out = State<IE, True, True, RS, True>;
}
// `ss` = DH(initiator-s, responder-s): requires IS and RS.
impl<Sndr, IE, RE, CK> Step<Sndr, State<IE, RE, True, True, CK>> for Ss {
    type Out = State<IE, RE, True, True, True>;
}

// `psk` mixes a pre-shared key: moves no DH key but keys the cipher.
impl<Sndr, IE, RE, IS, RS, CK> Step<Sndr, State<IE, RE, IS, RS, CK>> for Psk {
    type Out = State<IE, RE, IS, RS, True>;
}

// ── The fold: tokens within a message, messages within a pattern ─

/// Fold the tokens of a single message, threading the availability state.
#[doc(hidden)]
pub trait WalkTokens<Sender, StateIn> {
    type StateOut;
}
impl<Sender, St> WalkTokens<Sender, St> for Nil {
    type StateOut = St;
}
impl<Sender, St, Tok, Rest> WalkTokens<Sender, St> for Cons<Tok, Rest>
where
    Tok: Step<Sender, St>,
    Rest: WalkTokens<Sender, <Tok as Step<Sender, St>>::Out>,
{
    type StateOut = <Rest as WalkTokens<Sender, <Tok as Step<Sender, St>>::Out>>::StateOut;
}

/// Fold a list of messages (or pre-messages), threading the state across them.
#[doc(hidden)]
pub trait WalkMessages<StateIn> {
    type StateOut;
}
impl<St> WalkMessages<St> for Nil {
    type StateOut = St;
}
impl<St, Dir, Toks, Rest> WalkMessages<St> for Cons<Message<Dir, Toks>, Rest>
where
    Dir: SenderOf,
    Toks: WalkTokens<<Dir as SenderOf>::Sender, St>,
    Rest: WalkMessages<<Toks as WalkTokens<<Dir as SenderOf>::Sender, St>>::StateOut>,
{
    type StateOut = <Rest as WalkMessages<
        <Toks as WalkTokens<<Dir as SenderOf>::Sender, St>>::StateOut,
    >>::StateOut;
}

// ── Finalisation: the cipher must be keyed ───────────────────────

/// Marker for a final fold [`State`] whose cipher has been keyed at least once
/// (`CK = True`).
///
/// [`WellFormed`] requires the state after the last handshake message to be
/// `Keyed`, so a pattern that performs no DH (`ee`/`es`/`se`/`ss`) and no `psk`
/// token — and would therefore finalise to a transport whose keys derive solely
/// from the public protocol-name hash — is rejected at compile time. (The bit
/// tracks "a DH or PSK occurred", which is intentionally narrower than the
/// engine's runtime keyed flag: it does not credit the extra `mix_key` an `E`
/// token performs in a PSK pattern, because every PSK pattern already carries a
/// `psk` token that keys.)
#[doc(hidden)]
#[diagnostic::on_unimplemented(
    message = "this Noise pattern never keys the cipher: it performs no DH (ee/es/se/ss) and no psk token, so it provides no confidentiality or authentication",
    label = "pattern finalises with an unkeyed cipher"
)]
pub trait Keyed {}
impl<IE, RE, IS, RS> Keyed for State<IE, RE, IS, RS, True> {}

// ── The public guard ─────────────────────────────────────────────

/// A [`Pattern`] whose token sequence is valid (Noise spec §7.3): every DH
/// token consumes keys already transmitted, and no party sends the same
/// ephemeral or static twice.
///
/// Implemented automatically for every [`Pattern`] that passes the
/// compile-time fold described in the [module docs](self) — so a malformed
/// pattern simply does not implement it. The [`Protocol`](super::Protocol)
/// impl requires `WellFormed`, and the `noise!` macro asserts it at the
/// pattern's own definition, so an ill-formed pattern cannot reach a
/// handshake.
///
/// # Examples
///
/// A shipped pattern is well-formed:
///
/// ```
/// use hiss::noise::WellFormed;
/// fn assert_well_formed<P: WellFormed>() {}
/// assert_well_formed::<hiss::noise::pattern::IKpsk1>();
/// ```
///
/// A DH before its key is transmitted (`es` before the initiator's `e`) is
/// rejected at compile time:
///
/// ```compile_fail
/// use hiss::noise::{Cons, Message, Nil, Pattern, ToResponder, WellFormed, E, Es};
/// struct Bad;
/// impl Pattern for Bad {
///     const NAME: &'static str = "Bad";
///     const NUM_MESSAGES: usize = 1;
///     type PreMessages = Nil;
///     type Messages = Cons<Message<ToResponder, Cons<Es, Cons<E, Nil>>>, Nil>;
/// }
/// fn assert_well_formed<P: WellFormed>() {}
/// assert_well_formed::<Bad>(); // es has no key — does not compile
/// ```
///
/// A Diffie–Hellman token in a pre-message (nothing is transmitted there) is
/// rejected:
///
/// ```compile_fail
/// use hiss::noise::{Cons, Message, Nil, Pattern, ToInitiator, ToResponder, WellFormed, E, Es};
/// struct Bad;
/// impl Pattern for Bad {
///     const NAME: &'static str = "Bad";
///     const NUM_MESSAGES: usize = 1;
///     type PreMessages = Cons<Message<ToInitiator, Cons<Es, Nil>>, Nil>;
///     type Messages = Cons<Message<ToResponder, Cons<E, Nil>>, Nil>;
/// }
/// fn assert_well_formed<P: WellFormed>() {}
/// assert_well_formed::<Bad>();
/// ```
///
/// Sending the same ephemeral twice is rejected:
///
/// ```compile_fail
/// use hiss::noise::{Cons, Ee, Message, Nil, Pattern, ToInitiator, ToResponder, WellFormed, E};
/// struct Bad;
/// impl Pattern for Bad {
///     const NAME: &'static str = "Bad";
///     const NUM_MESSAGES: usize = 3;
///     type PreMessages = Nil;
///     // -> e / <- e, ee / -> e   (initiator sends e twice)
///     type Messages = Cons<
///         Message<ToResponder, Cons<E, Nil>>,
///         Cons<
///             Message<ToInitiator, Cons<E, Cons<Ee, Nil>>>,
///             Cons<Message<ToResponder, Cons<E, Nil>>, Nil>,
///         >,
///     >;
/// }
/// fn assert_well_formed<P: WellFormed>() {}
/// assert_well_formed::<Bad>();
/// ```
///
/// A pattern that never keys the cipher (a lone `-> e` — no DH and no `psk`) is
/// rejected; it would otherwise finalise to a transport keyed only from the
/// public protocol-name hash:
///
/// ```compile_fail
/// use hiss::noise::{Cons, Message, Nil, Pattern, ToResponder, WellFormed, E};
/// struct Bad;
/// impl Pattern for Bad {
///     const NAME: &'static str = "Bad";
///     const NUM_MESSAGES: usize = 1;
///     type PreMessages = Nil;
///     // -> e   (no DH, no psk — the cipher is never keyed)
///     type Messages = Cons<Message<ToResponder, Cons<E, Nil>>, Nil>;
/// }
/// fn assert_well_formed<P: WellFormed>() {}
/// assert_well_formed::<Bad>(); // never keyed — does not compile
/// ```
pub trait WellFormed: Pattern {}

impl<P> WellFormed for P
where
    P: Pattern,
    P::PreMessages: WalkMessages<Start>,
    P::Messages: WalkMessages<<P::PreMessages as WalkMessages<Start>>::StateOut>,
    <P::Messages as WalkMessages<<P::PreMessages as WalkMessages<Start>>::StateOut>>::StateOut:
        Keyed,
{
}

// ── Derived PSK modifier ─────────────────────────────────────────

/// A [`Pattern`]'s PSK modifier, derived from its `Messages` token list.
///
/// `HAS_PSK` is computed by the [`ContainsPsk`] fold rather than declared by
/// hand, so it cannot drift out of sync with the tokens. Because this is a
/// blanket impl, the value is not overridable. The handshake engine reads it
/// here to gate the extra `mix_key` on the `E` token in PSK patterns.
#[doc(hidden)]
pub trait DerivedHasPsk {
    /// Whether the pattern's message list contains a `psk` token.
    const HAS_PSK: bool;
}
impl<P: Pattern> DerivedHasPsk for P {
    const HAS_PSK: bool = <P::Messages as ContainsPsk>::VALUE;
}

// A pattern definition's compile-time `WellFormed` assertion is emitted
// by the `noise!` macro itself (see `hiss-macros`), so a malformed
// pattern is reported at its definition site rather than at a distant
// handshake call.
