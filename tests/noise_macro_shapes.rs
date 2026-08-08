//! Round-trip, interop, and negative coverage for the `noise!` macro's
//! suite-mode codegen shapes the existing acceptance suite
//! (`tests/noise_macro.rs`, IKpsk1 + XX) never exercised.
//!
//! Four shapes, each compiled here for the first time:
//!
//! * `N` — one-way pattern whose single handshake message is also the final
//!   one, so `write_message_1` / `read_message_1` return the `Transport`
//!   directly. Its only pre-message is the *remote* static, so the initiator
//!   constructor is infallible and the responder's (holding the *local*
//!   static) is fallible.
//! * `K` — both statics are pre-messages, so both roles' constructors are
//!   fallible and take their keys in pattern order.
//! * `Kpsk0` — `psk` is the first token of the first message; no `s` precedes
//!   it, so the read side is the plain `read_message_1(&msg, &psk)` form (no
//!   per-peer lookup closure).
//! * `IX` — interactive, no pre-messages (infallible constructors), with an
//!   `s` token in each message (adding a `static_key` argument) and a final
//!   message that completes into the `Transport`.
//! * `X` — one-way whose single message itself reveals the initiator's
//!   static (`s` mid-message, unlike `N`'s anonymous initiator).
//!
//! `X`, `Xpsk0`, and `IX` also pin the `read_message_N_with` **verification**
//! variant: when a received message reveals the peer's static, the generated
//! `_with` read hands that identity to a closure before the message's
//! remaining tokens are processed — on a final message (these three), before
//! the handshake may complete, so an unverified peer never yields a
//! `Transport`. `Xpsk0` additionally pins the argument order when that
//! message carries a plain `psk` ahead of the revealed static:
//! `(message, psk, verify)`.
//!
//! Three further patterns pin the `[N]` **application-payload** suffix and
//! the *non-final* verification hook (slither's IK-with-timestamp shape):
//!
//! * `IK` — the plain twin, compiled only for its wire-size consts;
//! * `IKPayload` — IK with `[12]` on msg1: the writer takes
//!   `payload: &[u8; 12]` last, the reader returns the recovered array
//!   alongside the next state, `MSG1_SIZE` grows by exactly 12, and the
//!   keyed tail keeps the payload off the wire verbatim. Msg1 also reveals
//!   the initiator's static mid-handshake, so the responder's read gains
//!   the `_with` variant: a counting provider pins that the closure fires
//!   after exactly one DH (`es`) — rejection never spends the `ss` — and
//!   that an accepted read proceeds identically to the plain one;
//! * `NNPayload` — the honest twin: `-> e [12]` closes before any DH, so
//!   the payload travels verbatim in the clear, nothing verifies it at
//!   that read, and a tamper only surfaces at the next authenticated
//!   token (msg2's tag).
//!
//! Beyond the macro↔macro round trips (T2), `n_macro_initiator_interops_with_
//! classic_responder` drives the macro `N` initiator against the classic
//! `SyncHandshake` responder: session-id (transcript-hash) equality proves the
//! two implementations produced byte-identical handshakes. The final three
//! tests (T6) confirm tampered messages, a wrong PSK, and a prologue mismatch
//! all surface as `HandshakeError::DecryptionFailed`.

mod common;

use std::cell::Cell;
use std::rc::Rc;

use hiss::curve::{Curve, DhCurve};
use hiss::noise::{Blake2b, ChaChaPoly, HandshakeError, Transport, X25519};
use hiss::provider::{CryptoKeyProvider, DhProvider, EphemeralOnly, ProviderExt};
use hiss::psk::Psk;
use rand::SeedableRng;
use rand::rngs::StdRng;

// The four never-before-compiled codegen shapes, over the same suite the
// existing acceptance tests use.
hiss::noise! { pub N<X25519, ChaChaPoly, Blake2b>     { <- s ... -> e, es } }
hiss::noise! { pub K<X25519, ChaChaPoly, Blake2b>     { -> s <- s ... -> e, es, ss } }
hiss::noise! { pub Kpsk0<X25519, ChaChaPoly, Blake2b> { -> s <- s ... -> psk, e, es, ss } }
hiss::noise! { pub IX<X25519, ChaChaPoly, Blake2b>    { -> e, s <- e, ee, se, s, es } }
hiss::noise! { pub X<X25519, ChaChaPoly, Blake2b>     { <- s ... -> e, es, s, ss } }
hiss::noise! { pub Xpsk0<X25519, ChaChaPoly, Blake2b> { <- s ... -> psk, e, es, s, ss } }

// The `[N]` application-payload suffix and its plain twin (see the module
// docs): IK carrying a 12-byte payload in msg1's keyed tail, and NN
// carrying one in msg1's unkeyed tail.
hiss::noise! { pub IK<X25519, ChaChaPoly, Blake2b>        { <- s ... -> e, es, s, ss <- e, ee, se } }
hiss::noise! { pub IKPayload<X25519, ChaChaPoly, Blake2b> { <- s ... -> e, es, s, ss [12] <- e, ee, se } }
hiss::noise! { pub NNPayload<X25519, ChaChaPoly, Blake2b> { -> e [12] <- e, ee } }

const PROLOGUE: &[u8] = b"hiss macro shapes";

fn provider(seed: u64) -> EphemeralOnly<StdRng> {
    EphemeralOnly::new(StdRng::seed_from_u64(seed))
}

/// Wraps a provider and counts its `dh` calls through a shared cell, so a
/// test can pin exactly how much provider work a read performed — the
/// point of the non-final verification hook is that a rejection stops
/// before the message's remaining DH tokens.
struct CountingDh<P> {
    inner: P,
    dhs: Rc<Cell<usize>>,
}

impl<C: Curve, P: CryptoKeyProvider<C>> CryptoKeyProvider<C> for CountingDh<P> {
    type Error = P::Error;
    type PrivateKey = P::PrivateKey;

    fn public_key(&self, key: &Self::PrivateKey) -> Result<C::PublicKey, Self::Error> {
        self.inner.public_key(key)
    }

    fn generate_static_key(&mut self) -> Result<Self::PrivateKey, Self::Error> {
        self.inner.generate_static_key()
    }

    fn generate_ephemeral_key(&mut self) -> Result<Self::PrivateKey, Self::Error> {
        self.inner.generate_ephemeral_key()
    }
}

impl<C: DhCurve, P: DhProvider<C>> DhProvider<C> for CountingDh<P> {
    fn dh(
        &self,
        key: &Self::PrivateKey,
        peer: &C::PublicKey,
    ) -> Result<C::SharedSecret, Self::Error> {
        self.dhs.set(self.dhs.get() + 1);
        self.inner.dh(key, peer)
    }
}

// ── T2: round trips ──────────────────────────────────────────────

#[test]
fn n_macro_round_trip() {
    // One-way: the initiator is anonymous, so it needs no static of its own;
    // it only pre-knows the responder's static public key.
    let ip = provider(101);
    let mut rp = provider(102);
    let r_static = rp.generate::<X25519>().unwrap();
    let r_pub = rp.public(&r_static).unwrap();

    // `write_message_1` / `read_message_1` return the `Transport` directly —
    // N has a single message that is also the final one.
    let (msg1, mut i_t) = N::initiator(ip, PROLOGUE, r_pub).write_message_1().unwrap();
    let mut r_t = N::responder(rp, PROLOGUE, r_static)
        .unwrap()
        .read_message_1(&msg1)
        .unwrap();

    assert_eq!(i_t.session_id(), r_t.session_id());

    // One transport record, initiator -> responder (N is one-directional at
    // the handshake level, but the transport keys are bidirectional).
    let payload = b"one-way, no io";
    let mut sealed = vec![0u8; payload.len() + Transport::<N>::OVERHEAD];
    let n = i_t.send(payload, &mut sealed).unwrap();
    let mut opened = vec![0u8; n];
    let m = r_t.receive(&sealed[..n], &mut opened).unwrap();
    assert_eq!(&opened[..m], payload);
}

#[test]
fn k_macro_round_trip() {
    let mut ip = provider(201);
    let i_static = ip.generate::<X25519>().unwrap();
    let i_pub = ip.public(&i_static).unwrap();
    let mut rp = provider(202);
    let r_static = rp.generate::<X25519>().unwrap();
    let r_pub = rp.public(&r_static).unwrap();

    // Constructor argument order follows pre-message order:
    //   initiator: `-> s` (our static_key), `<- s` (remote_static)
    //   responder: `-> s` (remote_static),  `<- s` (our static_key)
    let (msg1, mut i_t) = K::initiator(ip, PROLOGUE, i_static, r_pub)
        .unwrap()
        .write_message_1()
        .unwrap();
    let mut r_t = K::responder(rp, PROLOGUE, i_pub, r_static)
        .unwrap()
        .read_message_1(&msg1)
        .unwrap();

    assert_eq!(i_t.session_id(), r_t.session_id());

    let payload = b"K: both statics pre-shared";
    let mut sealed = vec![0u8; payload.len() + Transport::<K>::OVERHEAD];
    let n = i_t.send(payload, &mut sealed).unwrap();
    let mut opened = vec![0u8; n];
    let m = r_t.receive(&sealed[..n], &mut opened).unwrap();
    assert_eq!(&opened[..m], payload);
}

#[test]
fn kpsk0_macro_round_trip() {
    let mut ip = provider(301);
    let i_static = ip.generate::<X25519>().unwrap();
    let i_pub = ip.public(&i_static).unwrap();
    let mut rp = provider(302);
    let r_static = rp.generate::<X25519>().unwrap();
    let r_pub = rp.public(&r_static).unwrap();
    let psk = Psk::from_bytes([0xC3; 32]);

    // Same constructors as K; `psk` is the first message token so it is a
    // `write_message_1(&psk)` argument, and since no `s` is revealed before
    // it the read side is the plain `read_message_1(&msg, &psk)` form.
    let (msg1, mut i_t) = Kpsk0::initiator(ip, PROLOGUE, i_static, r_pub)
        .unwrap()
        .write_message_1(&psk)
        .unwrap();
    let mut r_t = Kpsk0::responder(rp, PROLOGUE, i_pub, r_static)
        .unwrap()
        .read_message_1(&msg1, &psk)
        .unwrap();

    assert_eq!(i_t.session_id(), r_t.session_id());

    let payload = b"psk0 mixes first";
    let mut sealed = vec![0u8; payload.len() + Transport::<Kpsk0>::OVERHEAD];
    let n = i_t.send(payload, &mut sealed).unwrap();
    let mut opened = vec![0u8; n];
    let m = r_t.receive(&sealed[..n], &mut opened).unwrap();
    assert_eq!(&opened[..m], payload);
}

#[test]
fn ix_macro_round_trip() {
    let mut ip = provider(401);
    let i_static = ip.generate::<X25519>().unwrap();
    let i_pub = ip.public(&i_static).unwrap();
    let mut rp = provider(402);
    let r_static = rp.generate::<X25519>().unwrap();
    let r_pub = rp.public(&r_static).unwrap();

    // Interactive, no pre-messages: infallible constructors; each `s` token
    // adds a `static_key` argument; msg2 is final -> `Transport`.
    let (msg1, i_hs) = IX::initiator(ip, PROLOGUE)
        .write_message_1(i_static)
        .unwrap();
    let r_hs = IX::responder(rp, PROLOGUE).read_message_1(&msg1).unwrap();
    let (msg2, mut r_t) = r_hs.write_message_2(r_static).unwrap();
    let mut i_t = i_hs.read_message_2(&msg2).unwrap();

    assert_eq!(i_t.session_id(), r_t.session_id());
    // Both statics are revealed and survive onto the transports.
    assert_eq!(i_t.remote_static().unwrap().as_ref(), r_pub.as_ref());
    assert_eq!(r_t.remote_static().unwrap().as_ref(), i_pub.as_ref());

    let payload = b"interactive mutual auth";
    let mut sealed = vec![0u8; payload.len() + Transport::<IX>::OVERHEAD];
    let n = i_t.send(payload, &mut sealed).unwrap();
    let mut opened = vec![0u8; n];
    let m = r_t.receive(&sealed[..n], &mut opened).unwrap();
    assert_eq!(&opened[..m], payload);

    // IX is interactive: also exercise the responder->initiator cipherstate.
    let reply = b"seen and verified";
    let mut sealed = vec![0u8; reply.len() + Transport::<IX>::OVERHEAD];
    let n = r_t.send(reply, &mut sealed).unwrap();
    let mut opened = vec![0u8; n];
    let m = i_t.receive(&sealed[..n], &mut opened).unwrap();
    assert_eq!(&opened[..m], reply);
}

#[test]
fn x_macro_round_trip() {
    let mut ip = provider(501);
    let i_static = ip.generate::<X25519>().unwrap();
    let i_pub = ip.public(&i_static).unwrap();
    let mut rp = provider(502);
    let r_static = rp.generate::<X25519>().unwrap();
    let r_pub = rp.public(&r_static).unwrap();

    // One-way like N, but the message itself carries the initiator's
    // static (encrypted), so `write_message_1` takes it as an argument.
    let (msg1, mut i_t) = X::initiator(ip, PROLOGUE, r_pub)
        .write_message_1(i_static)
        .unwrap();
    let mut r_t = X::responder(rp, PROLOGUE, r_static)
        .unwrap()
        .read_message_1(&msg1)
        .unwrap();

    assert_eq!(i_t.session_id(), r_t.session_id());
    // The revealed initiator static survives onto the responder's transport.
    assert_eq!(r_t.remote_static().unwrap().as_ref(), i_pub.as_ref());

    let payload = b"X: identified courier";
    let mut sealed = vec![0u8; payload.len() + Transport::<X>::OVERHEAD];
    let n = i_t.send(payload, &mut sealed).unwrap();
    let mut opened = vec![0u8; n];
    let m = r_t.receive(&sealed[..n], &mut opened).unwrap();
    assert_eq!(&opened[..m], payload);
}

// ── the `read_message_N_with` verification variant ────────────────
//
// Generated wherever a received message reveals the peer's static (and
// is not the PSK-lookup shape). The three patterns here exercise the
// *final*-message case: there is no later handshake state to observe the
// key on (only `Transport::remote_static()`, an `Option`), so the
// closure sees it at the protocol-correct moment instead — after
// decryption, before the handshake completes. The non-final case is
// pinned further down, on `IKPayload`.

#[test]
fn x_macro_verify_accepts_the_enrolled_peer() {
    let mut ip = provider(511);
    let i_static = ip.generate::<X25519>().unwrap();
    let i_pub = ip.public(&i_static).unwrap();
    let mut rp = provider(512);
    let r_static = rp.generate::<X25519>().unwrap();
    let r_pub = rp.public(&r_static).unwrap();

    let (msg1, mut i_t) = X::initiator(ip, PROLOGUE, r_pub)
        .write_message_1(i_static)
        .unwrap();
    let mut r_t = X::responder(rp, PROLOGUE, r_static)
        .unwrap()
        .read_message_1_with(&msg1, |peer| {
            if peer.as_ref() == i_pub.as_ref() {
                Ok(())
            } else {
                Err(HandshakeError::PeerRejected {
                    reason: "not enrolled".into(),
                })
            }
        })
        .unwrap();

    assert_eq!(i_t.session_id(), r_t.session_id());

    let payload = b"verified before completion";
    let mut sealed = vec![0u8; payload.len() + Transport::<X>::OVERHEAD];
    let n = i_t.send(payload, &mut sealed).unwrap();
    let mut opened = vec![0u8; n];
    let m = r_t.receive(&sealed[..n], &mut opened).unwrap();
    assert_eq!(&opened[..m], payload);
}

#[test]
fn x_macro_verify_rejects_the_unknown_peer() {
    let mut ip = provider(521);
    let i_static = ip.generate::<X25519>().unwrap();
    let mut rp = provider(522);
    let r_static = rp.generate::<X25519>().unwrap();
    let r_pub = rp.public(&r_static).unwrap();

    let (msg1, _i_t) = X::initiator(ip, PROLOGUE, r_pub)
        .write_message_1(i_static)
        .unwrap();
    // The closure rejects: the handshake aborts and no `Transport` exists
    // for the unverified peer.
    let result = X::responder(rp, PROLOGUE, r_static)
        .unwrap()
        .read_message_1_with(&msg1, |_peer| {
            Err(HandshakeError::PeerRejected {
                reason: "unknown courier".into(),
            })
        });
    assert!(matches!(
        result,
        Err(HandshakeError::PeerRejected { reason }) if reason == "unknown courier"
    ));
}

#[test]
fn xpsk0_macro_verify_takes_the_psk_then_the_closure() {
    let mut ip = provider(541);
    let i_static = ip.generate::<X25519>().unwrap();
    let i_pub = ip.public(&i_static).unwrap();
    let mut rp = provider(542);
    let r_static = rp.generate::<X25519>().unwrap();
    let r_pub = rp.public(&r_static).unwrap();
    let psk = Psk::from_bytes([0xCC; 32]);

    // The `psk` precedes the `s`, so the verification variant keeps a
    // plain `psk` parameter, in token order ahead of the closure:
    // `read_message_1_with(&msg, &psk, verify)`.
    let (msg1, mut i_t) = Xpsk0::initiator(ip, PROLOGUE, r_pub)
        .write_message_1(&psk, i_static)
        .unwrap();
    let mut r_t = Xpsk0::responder(rp, PROLOGUE, r_static)
        .unwrap()
        .read_message_1_with(&msg1, &psk, |peer| {
            if peer.as_ref() == i_pub.as_ref() {
                Ok(())
            } else {
                Err(HandshakeError::PeerRejected {
                    reason: "not enrolled".into(),
                })
            }
        })
        .unwrap();

    assert_eq!(i_t.session_id(), r_t.session_id());

    let payload = b"psk, then identity check";
    let mut sealed = vec![0u8; payload.len() + Transport::<Xpsk0>::OVERHEAD];
    let n = i_t.send(payload, &mut sealed).unwrap();
    let mut opened = vec![0u8; n];
    let m = r_t.receive(&sealed[..n], &mut opened).unwrap();
    assert_eq!(&opened[..m], payload);
}

#[test]
fn ix_macro_verify_runs_before_the_initiator_completes() {
    let mut ip = provider(531);
    let i_static = ip.generate::<X25519>().unwrap();
    let mut rp = provider(532);
    let r_static = rp.generate::<X25519>().unwrap();
    let r_pub = rp.public(&r_static).unwrap();

    // Interactive shape: the *initiator*'s final read (msg2) reveals the
    // responder's static, so it is the side that gets the `_with` variant.
    let (msg1, i_hs) = IX::initiator(ip, PROLOGUE)
        .write_message_1(i_static)
        .unwrap();
    let r_hs = IX::responder(rp, PROLOGUE).read_message_1(&msg1).unwrap();
    let (msg2, mut r_t) = r_hs.write_message_2(r_static).unwrap();

    let mut i_t = i_hs
        .read_message_2_with(&msg2, |peer| {
            if peer.as_ref() == r_pub.as_ref() {
                Ok(())
            } else {
                Err(HandshakeError::PeerRejected {
                    reason: "unexpected responder".into(),
                })
            }
        })
        .unwrap();

    assert_eq!(i_t.session_id(), r_t.session_id());

    let payload = b"mutually verified";
    let mut sealed = vec![0u8; payload.len() + Transport::<IX>::OVERHEAD];
    let n = i_t.send(payload, &mut sealed).unwrap();
    let mut opened = vec![0u8; n];
    let m = r_t.receive(&sealed[..n], &mut opened).unwrap();
    assert_eq!(&opened[..m], payload);
}

// ── the `[N]` application-payload suffix ──────────────────────────
//
// The payload rides the same encrypt-and-hash that already closes every
// message, so its security is positional: keyed on IKPayload's msg1
// (encrypted and authenticated), unkeyed on NNPayload's (verbatim in the
// clear, unverified until the next authenticated token). IKPayload's
// msg1 also reveals the initiator's static mid-handshake, so it pins the
// *non-final* verification hook and its composition with the payload:
// the closure fires after `es` and before `ss` — and therefore before
// the tail decrypts — so the payload only ever comes back from an
// accepted read, and a rejection costs exactly one DH.

#[test]
fn payload_sizes_grow_by_exactly_the_declared_length() {
    // IK msg1: e(32) + s(32+16, keyed) + tag(16) = 96; the `[12]` twin
    // adds exactly its payload. Msg2 carries none and is unchanged.
    assert_eq!(IK::MSG1_SIZE, 96);
    assert_eq!(IKPayload::MSG1_SIZE, IK::MSG1_SIZE + 12);
    assert_eq!(IKPayload::MSG2_SIZE, IK::MSG2_SIZE);
    // NN msg1: bare e(32) + 12 cleartext payload bytes, no key => no tag.
    assert_eq!(NNPayload::MSG1_SIZE, 32 + 12);
}

#[test]
fn ik_payload_round_trip() {
    let mut ip = provider(801);
    let i_static = ip.generate::<X25519>().unwrap();
    let mut rp = provider(802);
    let r_static = rp.generate::<X25519>().unwrap();
    let r_pub = rp.public(&r_static).unwrap();
    let stamp: [u8; 12] = *b"ts0123456789";

    // The payload is the message's tail, so it is the writer's last
    // argument; the reader hands the recovered array back by value,
    // alongside the next state.
    let (msg1, i_hs) = IKPayload::initiator(ip, PROLOGUE, r_pub)
        .write_message_1(i_static, &stamp)
        .unwrap();
    let (got, r_hs) = IKPayload::responder(rp, PROLOGUE, r_static)
        .unwrap()
        .read_message_1(&msg1)
        .unwrap();
    assert_eq!(got, stamp);

    let (msg2, mut r_t) = r_hs.write_message_2().unwrap();
    let mut i_t = i_hs.read_message_2(&msg2).unwrap();
    assert_eq!(i_t.session_id(), r_t.session_id());

    let quote = b"stamped and sealed";
    let mut sealed = vec![0u8; quote.len() + Transport::<IKPayload>::OVERHEAD];
    let n = i_t.send(quote, &mut sealed).unwrap();
    let mut opened = vec![0u8; n];
    let m = r_t.receive(&sealed[..n], &mut opened).unwrap();
    assert_eq!(&opened[..m], quote);
}

#[test]
fn ik_payload_keyed_tail_is_not_on_the_wire() {
    let mut ip = provider(811);
    let i_static = ip.generate::<X25519>().unwrap();
    let mut rp = provider(812);
    let r_static = rp.generate::<X25519>().unwrap();
    let r_pub = rp.public(&r_static).unwrap();
    // A distinctive, unlikely-to-collide plaintext.
    let stamp: [u8; 12] = *b"SECRET-STAMP";

    let (msg1, _i_hs) = IKPayload::initiator(ip, PROLOGUE, r_pub)
        .write_message_1(i_static, &stamp)
        .unwrap();
    assert!(
        !msg1.windows(stamp.len()).any(|w| w == stamp),
        "a keyed payload's plaintext must not appear on the wire",
    );
}

#[test]
fn ik_payload_tampered_tail_fails_the_read() {
    let mut ip = provider(821);
    let i_static = ip.generate::<X25519>().unwrap();
    let mut rp = provider(822);
    let r_static = rp.generate::<X25519>().unwrap();
    let r_pub = rp.public(&r_static).unwrap();
    let stamp = [0x5A; 12];

    let (mut msg1, _i_hs) = IKPayload::initiator(ip, PROLOGUE, r_pub)
        .write_message_1(i_static, &stamp)
        .unwrap();
    // First byte of the payload ciphertext: after e (32) + encrypted s (48).
    msg1[80] ^= 0xFF;

    // The keyed tail's tag check fails: no payload, no next state.
    let outcome = IKPayload::responder(rp, PROLOGUE, r_static)
        .unwrap()
        .read_message_1(&msg1);
    assert!(matches!(outcome, Err(HandshakeError::DecryptionFailed)));
}

#[test]
fn nn_payload_unkeyed_tail_travels_verbatim() {
    let ip = provider(831);
    let rp = provider(832);
    let stamp: [u8; 12] = *b"CLEAR-STAMP!";

    // `-> e [12]` closes before any DH: no key, no tag — the honest twin
    // of the encrypted case, verbatim on the wire after the ephemeral.
    let (msg1, i_hs) = NNPayload::initiator(ip, PROLOGUE)
        .write_message_1(&stamp)
        .unwrap();
    assert_eq!(&msg1[32..], &stamp);

    let (got, r_hs) = NNPayload::responder(rp, PROLOGUE)
        .read_message_1(&msg1)
        .unwrap();
    assert_eq!(got, stamp);

    // The cleartext tail is mixed into the transcript like any other
    // payload, and the handshake still completes.
    let (msg2, r_t) = r_hs.write_message_2().unwrap();
    let i_t = i_hs.read_message_2(&msg2).unwrap();
    assert_eq!(i_t.session_id(), r_t.session_id());
}

#[test]
fn nn_payload_unkeyed_tamper_is_caught_at_the_next_authenticated_token() {
    let ip = provider(841);
    let rp = provider(842);
    let stamp: [u8; 12] = *b"in the clear";

    let (mut msg1, i_hs) = NNPayload::initiator(ip, PROLOGUE)
        .write_message_1(&stamp)
        .unwrap();
    // First byte of the cleartext payload.
    msg1[32] ^= 0xFF;

    // The read itself accepts — an unkeyed tail has no tag to fail — and
    // hands back the tampered bytes as unauthenticated input.
    let (got, r_hs) = NNPayload::responder(rp, PROLOGUE)
        .read_message_1(&msg1)
        .unwrap();
    assert_ne!(got, stamp);

    // But the tail is mixed into the transcript, so the diverged hashes
    // fail the next authenticated token: msg2's tag, on the initiator.
    let (msg2, _r_t) = r_hs.write_message_2().unwrap();
    let outcome = i_hs.read_message_2(&msg2);
    assert!(matches!(outcome, Err(HandshakeError::DecryptionFailed)));
}

#[test]
fn ik_payload_verify_reject_costs_exactly_one_dh() {
    let mut ip = provider(851);
    let i_static = ip.generate::<X25519>().unwrap();
    let mut rp = provider(852);
    let r_static = rp.generate::<X25519>().unwrap();
    let r_pub = rp.public(&r_static).unwrap();
    let stamp = [0xA5; 12];

    let (msg1, _i_hs) = IKPayload::initiator(ip, PROLOGUE, r_pub)
        .write_message_1(i_static, &stamp)
        .unwrap();

    // Msg1 is not final, yet the `_with` variant exists: the closure
    // rejects the claimed identity as soon as `s` decrypts, so the read
    // never reaches `ss` — or the payload behind it.
    let dhs = Rc::new(Cell::new(0usize));
    let counting = CountingDh {
        inner: rp,
        dhs: dhs.clone(),
    };
    let outcome = IKPayload::responder(counting, PROLOGUE, r_static)
        .unwrap()
        .read_message_1_with(&msg1, |_peer| {
            Err(HandshakeError::PeerRejected {
                reason: "not enrolled".into(),
            })
        });
    assert!(matches!(outcome, Err(HandshakeError::PeerRejected { .. })));
    assert_eq!(
        dhs.get(),
        1,
        "rejection costs exactly the one `es` DH — `ss` never runs",
    );
}

#[test]
fn ik_payload_verify_fires_after_es_and_before_ss() {
    // Two identical handshakes (same seeds), one read plain and one read
    // through an accepting closure: the closure observes the identity
    // after exactly one DH (`es`) — `ss` has demonstrably not run — and
    // the accepted read proceeds identically to the plain one.
    let stamp: [u8; 12] = *b"ts9876543210";
    let run = |with_closure: bool| {
        let mut ip = provider(861);
        let i_static = ip.generate::<X25519>().unwrap();
        let i_pub = ip.public(&i_static).unwrap();
        let mut rp = provider(862);
        let r_static = rp.generate::<X25519>().unwrap();
        let r_pub = rp.public(&r_static).unwrap();

        let (msg1, i_hs) = IKPayload::initiator(ip, PROLOGUE, r_pub)
            .write_message_1(i_static, &stamp)
            .unwrap();

        let dhs = Rc::new(Cell::new(0usize));
        let counting = CountingDh {
            inner: rp,
            dhs: dhs.clone(),
        };
        let hs = IKPayload::responder(counting, PROLOGUE, r_static).unwrap();
        let (got, hs) = if with_closure {
            hs.read_message_1_with(&msg1, |peer| {
                assert_eq!(
                    peer.as_ref(),
                    i_pub.as_ref(),
                    "the closure sees the claimed identity",
                );
                assert_eq!(dhs.get(), 1, "`es` has run; `ss` has not");
                Ok(())
            })
            .unwrap()
        } else {
            hs.read_message_1(&msg1).unwrap()
        };
        assert_eq!(dhs.get(), 2, "the completed read ran both `es` and `ss`");
        assert_eq!(got, stamp);

        let (msg2, r_t) = hs.write_message_2().unwrap();
        let i_t = i_hs.read_message_2(&msg2).unwrap();
        assert_eq!(i_t.session_id(), r_t.session_id());
        (msg2, i_t.session_id().as_ref().to_vec())
    };

    let (plain_msg2, plain_sid) = run(false);
    let (with_msg2, with_sid) = run(true);
    assert_eq!(plain_msg2, with_msg2);
    assert_eq!(plain_sid, with_sid);
}

// ── T2: byte-level interop against the classic io_sync driver ─────

// ── T6: negative paths ───────────────────────────────────────────

#[test]
fn tampered_msg_is_rejected() {
    let ip = provider(511);
    let mut rp = provider(522);
    let r_static = rp.generate::<X25519>().unwrap();
    let r_pub = rp.public(&r_static).unwrap();

    let (mut msg1, _i_t) = N::initiator(ip, PROLOGUE, r_pub).write_message_1().unwrap();
    // Corrupt the last byte — inside the trailing payload AEAD tag.
    let last = msg1.len() - 1;
    msg1[last] ^= 0xFF;

    // `read_message_1` returns the `Transport` on success; it has no `Debug`
    // impl (it holds secrets), so match on the `Result` rather than
    // `unwrap_err`.
    let result = N::responder(rp, PROLOGUE, r_static)
        .unwrap()
        .read_message_1(&msg1);
    assert!(matches!(result, Err(HandshakeError::DecryptionFailed)));
}

#[test]
fn wrong_psk_value_is_rejected() {
    let mut ip = provider(611);
    let i_static = ip.generate::<X25519>().unwrap();
    let i_pub = ip.public(&i_static).unwrap();
    let mut rp = provider(622);
    let r_static = rp.generate::<X25519>().unwrap();
    let r_pub = rp.public(&r_static).unwrap();

    let good = Psk::from_bytes([0xAA; 32]);
    let bad = Psk::from_bytes([0xBB; 32]);

    let (msg1, _i_t) = Kpsk0::initiator(ip, PROLOGUE, i_static, r_pub)
        .unwrap()
        .write_message_1(&good)
        .unwrap();

    // The PSK mixes into the key that authenticates msg1, so a wrong value
    // fails the payload tag.
    let result = Kpsk0::responder(rp, PROLOGUE, i_pub, r_static)
        .unwrap()
        .read_message_1(&msg1, &bad);
    assert!(matches!(result, Err(HandshakeError::DecryptionFailed)));
}

#[test]
fn prologue_mismatch_is_rejected() {
    let ip = provider(711);
    let mut rp = provider(722);
    let r_static = rp.generate::<X25519>().unwrap();
    let r_pub = rp.public(&r_static).unwrap();

    let (msg1, _i_t) = N::initiator(ip, PROLOGUE, r_pub).write_message_1().unwrap();

    // The prologue is folded into the transcript hash used as the AEAD ad, so
    // a mismatch fails the first authenticated token.
    let result = N::responder(rp, b"a different prologue", r_static)
        .unwrap()
        .read_message_1(&msg1);
    assert!(matches!(result, Err(HandshakeError::DecryptionFailed)));
}
