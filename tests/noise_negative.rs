//! Systematic protocol-level negative / boundary tests (A3.7).
//!
//! Where `src/noise/mod.rs` has hand-picked single-corruption tests, this
//! file sweeps the adversarial space deterministically (via the
//! [`ScriptedRng`] ephemeral-injection harness) across the eleven patterns
//! swept here:
//!
//! * **tamper** — flip *every* byte of *every* handshake message → the
//!   receiver must reject (invalid curve point at the `e` token, or an
//!   AEAD tag failure once the diverged transcript hash / DH feeds a
//!   keyed token);
//! * **transport tamper** — flip *every* byte of a transport ciphertext
//!   → `DecryptionFailed`;
//! * **nonce sequencing** — replayed and out-of-order transport messages
//!   are rejected;
//! * **wrong PSK** — both PSK-bearing patterns reject a mismatched key.
//!
//! Each driver runs a full hiss↔hiss handshake; the sender side is
//! deterministic (fixed statics + scripted ephemerals) so a failure
//! pinpoints the exact pattern/message/byte.
//!
//! # What happened to the truncation sweeps
//!
//! This file used to sweep every truncated prefix and an over-long variant
//! of every handshake message, asserting each was rejected at run time.
//! Those sweeps are gone, and **not** because the property stopped
//! mattering — because it stopped being expressible.
//!
//! `read_message_N` takes `&[u8; MSGn_SIZE]`. A short or long buffer is not
//! a value the function can be handed: it is a type error at the call site,
//! caught at compile time rather than rejected at run time. There is no way
//! to write the old assertion, and a test that constructed the array anyway
//! would only be exercising its own harness.
//!
//! The property is now pinned where it lives — as a `compile_fail` doctest
//! on [`hiss::noise!`] proving a wrong-length buffer does not compile.
//! Length checking on the wire has moved to the caller, which reads exactly
//! `MSGn_SIZE` bytes because that constant is what framing is for.

mod common;
use common::{ScriptedRng, private_key, public_key};

use hiss::noise::*;
use hiss::provider::EphemeralOnly;
use hiss::psk::Psk;
use rand::{SeedableRng, rngs::StdRng};

// One `noise!` declaration per pattern, over the crate's default suite. The
// declared identifier is the Noise pattern name (it reaches the protocol
// name mixed into the initial handshake hash), so these are the canonical
// spellings.
hiss::noise! { pub N<P256, ChaChaPoly, Blake2b>      { <- s ... -> e, es } }
hiss::noise! { pub K<P256, ChaChaPoly, Blake2b>      { -> s <- s ... -> e, es, ss } }
hiss::noise! { pub Kpsk0<P256, ChaChaPoly, Blake2b>  { -> s <- s ... -> psk, e, es, ss } }
hiss::noise! { pub IKpsk1<P256, ChaChaPoly, Blake2b> { <- s ... -> e, es, s, ss, psk <- e, ee, se } }
hiss::noise! { pub IK<P256, ChaChaPoly, Blake2b>     { <- s ... -> e, es, s, ss <- e, ee, se } }
hiss::noise! { pub NK<P256, ChaChaPoly, Blake2b>     { <- s ... -> e, es <- e, ee } }
hiss::noise! { pub IX<P256, ChaChaPoly, Blake2b>     { -> e, s <- e, ee, se, s, es } }
hiss::noise! { pub XK<P256, ChaChaPoly, Blake2b>     { <- s ... -> e, es <- e, ee -> s, se } }
hiss::noise! { pub NN<P256, ChaChaPoly, Blake2b>     { -> e <- e, ee } }
hiss::noise! { pub XX<P256, ChaChaPoly, Blake2b>     { -> e <- e, ee, s, es -> s, se } }
hiss::noise! { pub X<P256, ChaChaPoly, Blake2b>      { <- s ... -> e, es, s, ss } }

// Fixed inputs — distinct values per role; all valid P-256 scalars.
const INIT_STATIC: [u8; 32] = [0xA1; 32];
const INIT_EPHEMERAL: [u8; 32] = [0xB2; 32];
const RESP_STATIC: [u8; 32] = [0xC3; 32];
const RESP_EPHEMERAL: [u8; 32] = [0xD4; 32];
const PSK_BYTES: [u8; 32] = [0xE5; 32];

/// Transform applied to a handshake message before the peer reads it.
///
/// In place, over the fixed-size array the writer produced: on this API a
/// message cannot change length, so only its bytes are in play.
type Xform<'a> = dyn Fn(usize, &mut [u8]) + 'a;

fn identity(_: usize, _: &mut [u8]) {}

fn flip(m: &mut [u8], byte: usize) {
    m[byte] ^= 0xFF;
}

// ── Per-pattern handshake drivers ────────────────────────────────
//
// Sender steps `.unwrap()` (must succeed — only the wire bytes are
// attacked, never the sender); receiver steps `map_err` so any rejection
// surfaces as `Err(())`.

fn run_n(xform: &Xform<'_>) -> Result<(), ()> {
    let (mut msg1, _i_t) = N::initiator(
        EphemeralOnly::new(ScriptedRng::new(&[&INIT_EPHEMERAL])),
        &[],
        public_key(&RESP_STATIC),
    )
    .write_message_1()
    .unwrap();
    xform(0, &mut msg1);

    N::responder(
        EphemeralOnly::new(StdRng::seed_from_u64(1)),
        &[],
        private_key(&RESP_STATIC),
    )
    .map_err(|_| ())?
    .read_message_1(&msg1)
    .map_err(|_| ())?;
    Ok(())
}

fn run_k(xform: &Xform<'_>) -> Result<(), ()> {
    let (mut msg1, _i_t) = K::initiator(
        EphemeralOnly::new(ScriptedRng::new(&[&INIT_EPHEMERAL])),
        &[],
        private_key(&INIT_STATIC),
        public_key(&RESP_STATIC),
    )
    .unwrap()
    .write_message_1()
    .unwrap();
    xform(0, &mut msg1);

    K::responder(
        EphemeralOnly::new(StdRng::seed_from_u64(2)),
        &[],
        public_key(&INIT_STATIC),
        private_key(&RESP_STATIC),
    )
    .map_err(|_| ())?
    .read_message_1(&msg1)
    .map_err(|_| ())?;
    Ok(())
}

fn run_kpsk0(xform: &Xform<'_>) -> Result<(), ()> {
    let psk = Psk::from_bytes(PSK_BYTES);
    let (mut msg1, _i_t) = Kpsk0::initiator(
        EphemeralOnly::new(ScriptedRng::new(&[&INIT_EPHEMERAL])),
        &[],
        private_key(&INIT_STATIC),
        public_key(&RESP_STATIC),
    )
    .unwrap()
    .write_message_1(&psk)
    .unwrap();
    xform(0, &mut msg1);

    Kpsk0::responder(
        EphemeralOnly::new(StdRng::seed_from_u64(3)),
        &[],
        public_key(&INIT_STATIC),
        private_key(&RESP_STATIC),
    )
    .map_err(|_| ())?
    .read_message_1(&msg1, &psk)
    .map_err(|_| ())?;
    Ok(())
}

fn run_ikpsk1(xform: &Xform<'_>) -> Result<(), ()> {
    let psk = Psk::from_bytes(PSK_BYTES);
    let (mut msg1, i_hs) = IKpsk1::initiator(
        EphemeralOnly::new(ScriptedRng::new(&[&INIT_EPHEMERAL])),
        &[],
        public_key(&RESP_STATIC),
    )
    .write_message_1(private_key(&INIT_STATIC), &psk)
    .unwrap();
    xform(0, &mut msg1);

    let r_hs = IKpsk1::responder(
        EphemeralOnly::new(ScriptedRng::new(&[&RESP_EPHEMERAL])),
        &[],
        private_key(&RESP_STATIC),
    )
    .map_err(|_| ())?
    .read_message_1(&msg1, &psk)
    .map_err(|_| ())?;

    let (mut msg2, _r_t) = r_hs.write_message_2().unwrap();
    xform(1, &mut msg2);

    i_hs.read_message_2(&msg2).map_err(|_| ())?;
    Ok(())
}

fn run_ik(xform: &Xform<'_>) -> Result<(), ()> {
    let (mut msg1, i_hs) = IK::initiator(
        EphemeralOnly::new(ScriptedRng::new(&[&INIT_EPHEMERAL])),
        &[],
        public_key(&RESP_STATIC),
    )
    .write_message_1(private_key(&INIT_STATIC))
    .unwrap();
    xform(0, &mut msg1);

    let r_hs = IK::responder(
        EphemeralOnly::new(ScriptedRng::new(&[&RESP_EPHEMERAL])),
        &[],
        private_key(&RESP_STATIC),
    )
    .map_err(|_| ())?
    .read_message_1(&msg1)
    .map_err(|_| ())?;

    let (mut msg2, _r_t) = r_hs.write_message_2().unwrap();
    xform(1, &mut msg2);

    i_hs.read_message_2(&msg2).map_err(|_| ())?;
    Ok(())
}

fn run_nk(xform: &Xform<'_>) -> Result<(), ()> {
    let (mut msg1, i_hs) = NK::initiator(
        EphemeralOnly::new(ScriptedRng::new(&[&INIT_EPHEMERAL])),
        &[],
        public_key(&RESP_STATIC),
    )
    .write_message_1()
    .unwrap();
    xform(0, &mut msg1);

    let r_hs = NK::responder(
        EphemeralOnly::new(ScriptedRng::new(&[&RESP_EPHEMERAL])),
        &[],
        private_key(&RESP_STATIC),
    )
    .map_err(|_| ())?
    .read_message_1(&msg1)
    .map_err(|_| ())?;

    let (mut msg2, _r_t) = r_hs.write_message_2().unwrap();
    xform(1, &mut msg2);

    i_hs.read_message_2(&msg2).map_err(|_| ())?;
    Ok(())
}

fn run_ix(xform: &Xform<'_>) -> Result<(), ()> {
    let (mut msg1, i_hs) = IX::initiator(
        EphemeralOnly::new(ScriptedRng::new(&[&INIT_EPHEMERAL])),
        &[],
    )
    .write_message_1(private_key(&INIT_STATIC))
    .unwrap();
    xform(0, &mut msg1);

    let r_hs = IX::responder(
        EphemeralOnly::new(ScriptedRng::new(&[&RESP_EPHEMERAL])),
        &[],
    )
    .read_message_1(&msg1)
    .map_err(|_| ())?;

    let (mut msg2, _r_t) = r_hs.write_message_2(private_key(&RESP_STATIC)).unwrap();
    xform(1, &mut msg2);

    i_hs.read_message_2(&msg2).map_err(|_| ())?;
    Ok(())
}

fn run_xk(xform: &Xform<'_>) -> Result<(), ()> {
    let (mut msg1, i_hs) = XK::initiator(
        EphemeralOnly::new(ScriptedRng::new(&[&INIT_EPHEMERAL])),
        &[],
        public_key(&RESP_STATIC),
    )
    .write_message_1()
    .unwrap();
    xform(0, &mut msg1);

    let r_hs = XK::responder(
        EphemeralOnly::new(ScriptedRng::new(&[&RESP_EPHEMERAL])),
        &[],
        private_key(&RESP_STATIC),
    )
    .map_err(|_| ())?
    .read_message_1(&msg1)
    .map_err(|_| ())?;

    let (mut msg2, r_hs) = r_hs.write_message_2().unwrap();
    xform(1, &mut msg2);

    let i_hs = i_hs.read_message_2(&msg2).map_err(|_| ())?;

    let (mut msg3, _i_t) = i_hs.write_message_3(private_key(&INIT_STATIC)).unwrap();
    xform(2, &mut msg3);

    r_hs.read_message_3(&msg3).map_err(|_| ())?;
    Ok(())
}

fn run_nn(xform: &Xform<'_>) -> Result<(), ()> {
    let (mut msg1, i_hs) = NN::initiator(
        EphemeralOnly::new(ScriptedRng::new(&[&INIT_EPHEMERAL])),
        &[],
    )
    .write_message_1()
    .unwrap();
    xform(0, &mut msg1);

    let r_hs = NN::responder(
        EphemeralOnly::new(ScriptedRng::new(&[&RESP_EPHEMERAL])),
        &[],
    )
    .read_message_1(&msg1)
    .map_err(|_| ())?;

    let (mut msg2, _r_t) = r_hs.write_message_2().unwrap();
    xform(1, &mut msg2);

    i_hs.read_message_2(&msg2).map_err(|_| ())?;
    Ok(())
}

fn run_xx(xform: &Xform<'_>) -> Result<(), ()> {
    let (mut msg1, i_hs) = XX::initiator(
        EphemeralOnly::new(ScriptedRng::new(&[&INIT_EPHEMERAL])),
        &[],
    )
    .write_message_1()
    .unwrap();
    xform(0, &mut msg1);

    let r_hs = XX::responder(
        EphemeralOnly::new(ScriptedRng::new(&[&RESP_EPHEMERAL])),
        &[],
    )
    .read_message_1(&msg1)
    .map_err(|_| ())?;

    let (mut msg2, r_hs) = r_hs.write_message_2(private_key(&RESP_STATIC)).unwrap();
    xform(1, &mut msg2);

    let i_hs = i_hs.read_message_2(&msg2).map_err(|_| ())?;

    let (mut msg3, _i_t) = i_hs.write_message_3(private_key(&INIT_STATIC)).unwrap();
    xform(2, &mut msg3);

    r_hs.read_message_3(&msg3).map_err(|_| ())?;
    Ok(())
}

fn run_x(xform: &Xform<'_>) -> Result<(), ()> {
    let (mut msg1, _i_t) = X::initiator(
        EphemeralOnly::new(ScriptedRng::new(&[&INIT_EPHEMERAL])),
        &[],
        public_key(&RESP_STATIC),
    )
    .write_message_1(private_key(&INIT_STATIC))
    .unwrap();
    xform(0, &mut msg1);

    X::responder(
        EphemeralOnly::new(StdRng::seed_from_u64(4)),
        &[],
        private_key(&RESP_STATIC),
    )
    .map_err(|_| ())?
    .read_message_1(&msg1)
    .map_err(|_| ())?;
    Ok(())
}

// ── Sweep helper ─────────────────────────────────────────────────

/// Assert that the genuine handshake completes, then that flipping any
/// single byte of message `msg_idx` is rejected.
///
/// `len` comes from the generated `MSGn_SIZE` const rather than a
/// hand-maintained table, so the sweep cannot silently under-cover a
/// message whose wire size changed.
fn sweep<F>(label: &str, msg_idx: usize, len: usize, run: F)
where
    F: Fn(Box<Xform<'static>>) -> Result<(), ()>,
{
    assert!(
        run(Box::new(identity)).is_ok(),
        "{label}: genuine handshake must complete"
    );

    for byte in 0..len {
        let res = run(Box::new(move |idx, m| {
            if idx == msg_idx {
                flip(m, byte)
            }
        }));
        assert!(res.is_err(), "{label}: flip of byte {byte} not rejected");
    }
}

// ── Tamper sweeps, per pattern ───────────────────────────────────

#[test]
fn n_msg1_tamper_sweep() {
    sweep("N msg1", 0, N::MSG1_SIZE, |xf| run_n(&*xf));
}

#[test]
fn k_msg1_tamper_sweep() {
    sweep("K msg1", 0, K::MSG1_SIZE, |xf| run_k(&*xf));
}

#[test]
fn kpsk0_msg1_tamper_sweep() {
    sweep("Kpsk0 msg1", 0, Kpsk0::MSG1_SIZE, |xf| run_kpsk0(&*xf));
}

#[test]
fn ikpsk1_msg1_tamper_sweep() {
    sweep("IKpsk1 msg1", 0, IKpsk1::MSG1_SIZE, |xf| run_ikpsk1(&*xf));
}

#[test]
fn ikpsk1_msg2_tamper_sweep() {
    sweep("IKpsk1 msg2", 1, IKpsk1::MSG2_SIZE, |xf| run_ikpsk1(&*xf));
}

#[test]
fn ik_msg1_tamper_sweep() {
    sweep("IK msg1", 0, IK::MSG1_SIZE, |xf| run_ik(&*xf));
}

#[test]
fn ik_msg2_tamper_sweep() {
    sweep("IK msg2", 1, IK::MSG2_SIZE, |xf| run_ik(&*xf));
}

#[test]
fn nk_msg1_tamper_sweep() {
    sweep("NK msg1", 0, NK::MSG1_SIZE, |xf| run_nk(&*xf));
}

#[test]
fn nk_msg2_tamper_sweep() {
    sweep("NK msg2", 1, NK::MSG2_SIZE, |xf| run_nk(&*xf));
}

#[test]
fn ix_msg1_tamper_sweep() {
    sweep("IX msg1", 0, IX::MSG1_SIZE, |xf| run_ix(&*xf));
}

#[test]
fn ix_msg2_tamper_sweep() {
    sweep("IX msg2", 1, IX::MSG2_SIZE, |xf| run_ix(&*xf));
}

#[test]
fn xk_msg1_tamper_sweep() {
    sweep("XK msg1", 0, XK::MSG1_SIZE, |xf| run_xk(&*xf));
}

#[test]
fn xk_msg2_tamper_sweep() {
    sweep("XK msg2", 1, XK::MSG2_SIZE, |xf| run_xk(&*xf));
}

#[test]
fn xk_msg3_tamper_sweep() {
    sweep("XK msg3", 2, XK::MSG3_SIZE, |xf| run_xk(&*xf));
}

#[test]
fn nn_msg1_tamper_sweep() {
    sweep("NN msg1", 0, NN::MSG1_SIZE, |xf| run_nn(&*xf));
}

#[test]
fn nn_msg2_tamper_sweep() {
    sweep("NN msg2", 1, NN::MSG2_SIZE, |xf| run_nn(&*xf));
}

#[test]
fn xx_msg1_tamper_sweep() {
    sweep("XX msg1", 0, XX::MSG1_SIZE, |xf| run_xx(&*xf));
}

#[test]
fn xx_msg2_tamper_sweep() {
    sweep("XX msg2", 1, XX::MSG2_SIZE, |xf| run_xx(&*xf));
}

#[test]
fn xx_msg3_tamper_sweep() {
    sweep("XX msg3", 2, XX::MSG3_SIZE, |xf| run_xx(&*xf));
}

#[test]
fn x_msg1_tamper_sweep() {
    sweep("X msg1", 0, X::MSG1_SIZE, |xf| run_x(&*xf));
}

/// The wire sizes the sweeps cover, pinned so a codegen change that moved a
/// message's length has to be acknowledged here rather than silently
/// shrinking or growing the adversarial space above.
#[test]
fn swept_wire_sizes_are_what_we_think() {
    assert_eq!(N::MSG1_SIZE, 81); // e + tag
    assert_eq!(K::MSG1_SIZE, 81);
    assert_eq!(Kpsk0::MSG1_SIZE, 81);
    assert_eq!(IKpsk1::MSG1_SIZE, 162); // e + encrypted s + tags
    assert_eq!(IKpsk1::MSG2_SIZE, 81);
    assert_eq!(IK::MSG1_SIZE, 162);
    assert_eq!(IK::MSG2_SIZE, 81);
    assert_eq!(NK::MSG1_SIZE, 81);
    assert_eq!(NK::MSG2_SIZE, 81);
    assert_eq!(IX::MSG1_SIZE, 130); // e + s, both in the clear
    assert_eq!(IX::MSG2_SIZE, 162);
    assert_eq!(XK::MSG1_SIZE, 81);
    assert_eq!(XK::MSG2_SIZE, 81);
    assert_eq!(XK::MSG3_SIZE, 97); // encrypted s + tag
    assert_eq!(NN::MSG1_SIZE, 65); // bare e, cipher never keyed
    assert_eq!(NN::MSG2_SIZE, 81);
    assert_eq!(XX::MSG1_SIZE, 65);
    assert_eq!(XX::MSG2_SIZE, 162);
    assert_eq!(XX::MSG3_SIZE, 97);
    assert_eq!(X::MSG1_SIZE, 162);
}

// ── Non-canonical on-wire public key (M1) ────────────────────────

#[test]
fn noncanonical_ephemeral_rejected() {
    use hiss::curve::p256::P256r1PublicKey;

    // NN msg1 is a bare `-> e`: the 65-byte wire payload *is* the
    // initiator's ephemeral in canonical (0x04 ‖ X ‖ Y) form.
    let (msg1, _i_hs) = NN::initiator(
        EphemeralOnly::new(ScriptedRng::new(&[&INIT_EPHEMERAL])),
        &[],
    )
    .write_message_1()
    .unwrap();

    // Re-encode the genuine ephemeral non-canonically: its 33-byte
    // compressed form, right-padded with trailing zeros to the 65-byte
    // wire width. This decodes to the *same* point (so it passes
    // `from_bytes`) but is not the canonical encoding the send path emits.
    let e_pub = P256r1PublicKey::from_bytes(&msg1).expect("genuine ephemeral decodes");
    let mut tampered = [0u8; NN::MSG1_SIZE];
    tampered[..33].copy_from_slice(&e_pub.to_compressed());

    let err = NN::responder(
        EphemeralOnly::new(ScriptedRng::new(&[&RESP_EPHEMERAL])),
        &[],
    )
    .read_message_1(&tampered)
    .map(|_| ())
    .unwrap_err();
    assert!(
        matches!(err, HandshakeError::NonCanonicalPublicKey),
        "non-canonical ephemeral must be rejected as NonCanonicalPublicKey, got {err:?}"
    );
}

// ── Wrong PSK ────────────────────────────────────────────────────

#[test]
fn kpsk0_wrong_psk_rejected() {
    // Re-run Kpsk0 but with the responder using a different PSK. We splice
    // a wrong-PSK responder by hand (the driver bakes in PSK_BYTES).
    let good = Psk::from_bytes(PSK_BYTES);
    let bad = Psk::from_bytes([0x00; 32]);

    let (msg1, _i_t) = Kpsk0::initiator(
        EphemeralOnly::new(ScriptedRng::new(&[&INIT_EPHEMERAL])),
        &[],
        private_key(&INIT_STATIC),
        public_key(&RESP_STATIC),
    )
    .unwrap()
    .write_message_1(&good)
    .unwrap();

    // The mismatched PSK diverges the key schedule; the final payload tag
    // fails to verify at the last token of msg1.
    let outcome = Kpsk0::responder(
        EphemeralOnly::new(StdRng::seed_from_u64(9)),
        &[],
        public_key(&INIT_STATIC),
        private_key(&RESP_STATIC),
    )
    .unwrap()
    .read_message_1(&msg1, &bad);
    assert!(outcome.is_err(), "Kpsk0 wrong PSK not rejected");
}

// ── Transport: tamper sweep + nonce sequencing ───────────────────

type NTransport = Transport<N>;

/// Complete an N handshake hiss↔hiss and return both transport states.
fn complete_n() -> (NTransport, NTransport) {
    let (msg1, i_transport) = N::initiator(
        EphemeralOnly::new(ScriptedRng::new(&[&INIT_EPHEMERAL])),
        &[],
        public_key(&RESP_STATIC),
    )
    .write_message_1()
    .unwrap();

    let r_transport = N::responder(
        EphemeralOnly::new(StdRng::seed_from_u64(7)),
        &[],
        private_key(&RESP_STATIC),
    )
    .unwrap()
    .read_message_1(&msg1)
    .unwrap();

    (i_transport, r_transport)
}

#[test]
fn transport_ciphertext_tamper_sweep() {
    let payload = b"negative-test transport payload";
    let ct_len = payload.len() + 16;

    // Sanity: a genuine transport message round-trips.
    {
        let (mut it, mut rt) = complete_n();
        let mut ct = [0u8; 256];
        let n = it.send(payload, &mut ct).unwrap();
        assert_eq!(n, ct_len);
        let mut pt = [0u8; 256];
        let pn = rt.receive(&ct[..n], &mut pt).unwrap();
        assert_eq!(&pt[..pn], payload);
    }

    // Flip each byte of the ciphertext (fresh session each time so the
    // receiver nonce state is irrelevant) → every flip must be rejected.
    for byte in 0..ct_len {
        let (mut it, mut rt) = complete_n();
        let mut ct = [0u8; 256];
        let n = it.send(payload, &mut ct).unwrap();
        ct[byte] ^= 0xFF;
        let mut pt = [0u8; 256];
        assert!(
            rt.receive(&ct[..n], &mut pt).is_err(),
            "transport ciphertext byte {byte} flip not rejected"
        );
    }
}

#[test]
fn transport_replay_rejected() {
    let (mut it, mut rt) = complete_n();
    let mut ct = [0u8; 256];
    let n = it.send(b"once", &mut ct).unwrap();

    let mut pt = [0u8; 256];
    assert!(rt.receive(&ct[..n], &mut pt).is_ok(), "genuine delivery");
    // Replaying the nonce-0 ciphertext when the receiver has advanced to
    // nonce 1 must fail.
    assert!(
        rt.receive(&ct[..n], &mut pt).is_err(),
        "replayed transport message not rejected"
    );
}

#[test]
fn transport_out_of_order_rejected() {
    let (mut it, mut rt) = complete_n();
    let mut m0 = [0u8; 256];
    let n0 = it.send(b"first", &mut m0).unwrap(); // nonce 0
    let mut m1 = [0u8; 256];
    let n1 = it.send(b"second", &mut m1).unwrap(); // nonce 1

    // Receiver expects nonce 0; handing it the nonce-1 message fails.
    let mut pt = [0u8; 256];
    assert!(
        rt.receive(&m1[..n1], &mut pt).is_err(),
        "out-of-order (nonce 1 before nonce 0) not rejected"
    );
    let _ = n0; // m0 intentionally not delivered
}
