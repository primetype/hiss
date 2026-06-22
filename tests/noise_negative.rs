//! Systematic protocol-level negative / boundary tests (A3.7).
//!
//! Where `src/noise/mod.rs` has hand-picked single-corruption tests, this
//! file sweeps the adversarial space deterministically (via the
//! [`ScriptedRng`] ephemeral-injection harness) across all ten supported
//! patterns:
//!
//! * **tamper** — flip *every* byte of *every* handshake message → the
//!   receiver must reject (invalid curve point at the `e` token, or an
//!   AEAD tag failure once the diverged transcript hash / DH feeds a
//!   keyed token);
//! * **truncation / wrong length** — *every* prefix length (and an
//!   over-long message) → rejected by the message-length check;
//! * **transport tamper** — flip *every* byte of a transport ciphertext
//!   → `DecryptionFailed`;
//! * **nonce sequencing** — replayed and out-of-order transport messages
//!   are rejected;
//! * **wrong PSK** — both PSK-bearing patterns reject a mismatched key.
//!
//! Each driver runs a full hiss↔hiss handshake; the sender side is
//! deterministic (fixed statics + scripted ephemerals) so a failure
//! pinpoints the exact pattern/message/byte.

mod common;
use common::{PeerStream, ScriptedRng, private_key, public_key};

use hiss::noise::*;
use hiss::provider::EphemeralOnly;
use hiss::psk::Psk;
use rand::{SeedableRng, rngs::StdRng};

// Each case below exercises one Noise pattern over the crate's default suite.
// The public API has no suite-bound aliases — `N`, `XX`, … are *patterns*
// (under `noise::pattern`), not whole `Noise<P, Cu, Ci, H>` protocols — so the
// full protocol is bound locally, one per pattern, named for the pattern tested.
type N = Noise<pattern::N, P256, ChaChaPoly, Blake2b>;
type K = Noise<pattern::K, P256, ChaChaPoly, Blake2b>;
type Kpsk0 = Noise<pattern::Kpsk0, P256, ChaChaPoly, Blake2b>;
type IKpsk1 = Noise<pattern::IKpsk1, P256, ChaChaPoly, Blake2b>;
type IK = Noise<pattern::IK, P256, ChaChaPoly, Blake2b>;
type NK = Noise<pattern::NK, P256, ChaChaPoly, Blake2b>;
type IX = Noise<pattern::IX, P256, ChaChaPoly, Blake2b>;
type XK = Noise<pattern::XK, P256, ChaChaPoly, Blake2b>;
type NN = Noise<pattern::NN, P256, ChaChaPoly, Blake2b>;
type XX = Noise<pattern::XX, P256, ChaChaPoly, Blake2b>;

// Fixed inputs — distinct values per role; all valid P-256 scalars.
const INIT_STATIC: [u8; 32] = [0xA1; 32];
const INIT_EPHEMERAL: [u8; 32] = [0xB2; 32];
const RESP_STATIC: [u8; 32] = [0xC3; 32];
const RESP_EPHEMERAL: [u8; 32] = [0xD4; 32];
const PSK_BYTES: [u8; 32] = [0xE5; 32];

// On-wire handshake-message sizes (65-byte ephemeral / encrypted static,
// 16-byte AEAD tags).
const ONE_MSG: usize = 81; // N / K / Kpsk0 msg1
const IK_MSG1: usize = 162; // IK / IKpsk1 msg1: e + encrypted s + tags
const IK_MSG2: usize = 81; // IK / IKpsk1 msg2: e + tag
const NK_MSG1: usize = 81; // NK msg1: e + es (keys cipher) + tag
const NK_MSG2: usize = 81; // NK msg2: e + ee + tag
const IX_MSG1: usize = 130; // IX msg1: e + s (both plaintext, no DH yet)
const IX_MSG2: usize = 162; // IX msg2: e + ee/se key cipher + encrypted s + es + tag
const XK_MSG1: usize = 81; // XK msg1: e + es (keys cipher) + tag
const XK_MSG2: usize = 81; // XK msg2: e + ee (keyed) + tag
const XK_MSG3: usize = 97; // XK msg3: encrypted s (keyed) + se + tag
const NN_MSG1: usize = 65; // NN msg1: bare e (cipher never keyed → no tag)
const NN_MSG2: usize = 81; // NN msg2: e + ee (keys cipher) + tag
const XX_MSG1: usize = 65; // XX msg1: bare e (cipher never keyed → no tag)
const XX_MSG2: usize = 162; // XX msg2: e + ee keys cipher + encrypted s + es + tag
const XX_MSG3: usize = 97; // XX msg3: encrypted s (keyed) + se + tag

/// Transform applied to a handshake message before the peer reads it.
type Xform<'a> = dyn Fn(usize, Vec<u8>) -> Vec<u8> + 'a;

fn identity(_: usize, m: Vec<u8>) -> Vec<u8> {
    m
}

fn flip(mut m: Vec<u8>, byte: usize) -> Vec<u8> {
    m[byte] ^= 0xFF;
    m
}

// ── Per-pattern handshake drivers ────────────────────────────────
//
// Sender steps `.unwrap()` (must succeed — only the wire bytes are
// attacked, never the sender); receiver steps `?` so any rejection
// surfaces as `Err(())`.

/// Confirm both endpoints consumed exactly what they were fed; leftover
/// bytes mean an over-long (trailing-garbage) message desynced the
/// stream.
fn fully_drained(a: &PeerStream, b: &PeerStream) -> Result<(), ()> {
    if a.remaining() == 0 && b.remaining() == 0 {
        Ok(())
    } else {
        Err(())
    }
}

fn run_n(xform: &Xform<'_>) -> Result<(), ()> {
    let i_stream = PeerStream::new();
    let i = SyncHandshake::<N, Initiator, _, _, _, _>::initiate(
        EphemeralOnly::new(ScriptedRng::new(&[&INIT_EPHEMERAL])),
        &[],
        i_stream.clone(),
    )
    .set_rs(public_key(&RESP_STATIC));
    let _ = i.e().unwrap().es().unwrap();
    let msg1 = xform(0, i_stream.take_written());

    let r_stream = PeerStream::new();
    r_stream.feed(&msg1);
    let r = SyncHandshake::<N, Responder, _, _, _, _>::respond(
        EphemeralOnly::new(StdRng::seed_from_u64(1)),
        &[],
        r_stream.clone(),
    )
    .set_s(private_key(&RESP_STATIC))
    .map_err(|_| ())?;
    let (_, recv) = r.recv().e().map_err(|_| ())?;
    recv.es().map_err(|_| ())?;
    fully_drained(&i_stream, &r_stream)
}

fn run_k(xform: &Xform<'_>) -> Result<(), ()> {
    let i_stream = PeerStream::new();
    let i = SyncHandshake::<K, Initiator, _, _, _, _>::initiate(
        EphemeralOnly::new(ScriptedRng::new(&[&INIT_EPHEMERAL])),
        &[],
        i_stream.clone(),
    )
    .set_s(private_key(&INIT_STATIC))
    .unwrap()
    .set_rs(public_key(&RESP_STATIC));
    let _ = i.e().unwrap().es().unwrap().ss().unwrap();
    let msg1 = xform(0, i_stream.take_written());

    let r_stream = PeerStream::new();
    r_stream.feed(&msg1);
    let r = SyncHandshake::<K, Responder, _, _, _, _>::respond(
        EphemeralOnly::new(StdRng::seed_from_u64(2)),
        &[],
        r_stream.clone(),
    )
    .set_rs(public_key(&INIT_STATIC))
    .set_s(private_key(&RESP_STATIC))
    .map_err(|_| ())?;
    let (_, recv) = r.recv().e().map_err(|_| ())?;
    recv.es().map_err(|_| ())?.ss().map_err(|_| ())?;
    fully_drained(&i_stream, &r_stream)
}

fn run_kpsk0(xform: &Xform<'_>) -> Result<(), ()> {
    let psk = Psk::from_bytes(PSK_BYTES);
    let i_stream = PeerStream::new();
    let i = SyncHandshake::<Kpsk0, Initiator, _, _, _, _>::initiate(
        EphemeralOnly::new(ScriptedRng::new(&[&INIT_EPHEMERAL])),
        &[],
        i_stream.clone(),
    )
    .set_s(private_key(&INIT_STATIC))
    .unwrap()
    .set_rs(public_key(&RESP_STATIC));
    let _ = i
        .psk(&psk)
        .unwrap()
        .e()
        .unwrap()
        .es()
        .unwrap()
        .ss()
        .unwrap();
    let msg1 = xform(0, i_stream.take_written());

    let r_stream = PeerStream::new();
    r_stream.feed(&msg1);
    let r = SyncHandshake::<Kpsk0, Responder, _, _, _, _>::respond(
        EphemeralOnly::new(StdRng::seed_from_u64(3)),
        &[],
        r_stream.clone(),
    )
    .set_rs(public_key(&INIT_STATIC))
    .set_s(private_key(&RESP_STATIC))
    .map_err(|_| ())?;
    let recv = r.recv().psk(&psk).map_err(|_| ())?;
    let (_, recv) = recv.e().map_err(|_| ())?;
    recv.es().map_err(|_| ())?.ss().map_err(|_| ())?;
    fully_drained(&i_stream, &r_stream)
}

fn run_ikpsk1(xform: &Xform<'_>) -> Result<(), ()> {
    let psk = Psk::from_bytes(PSK_BYTES);
    let i_stream = PeerStream::new();
    let i = SyncHandshake::<IKpsk1, Initiator, _, _, _, _>::initiate(
        EphemeralOnly::new(ScriptedRng::new(&[&INIT_EPHEMERAL])),
        &[],
        i_stream.clone(),
    )
    .set_rs(public_key(&RESP_STATIC));
    let i = i
        .e()
        .unwrap()
        .es()
        .unwrap()
        .s(private_key(&INIT_STATIC))
        .unwrap()
        .ss()
        .unwrap()
        .psk(&psk)
        .unwrap();
    let msg1 = xform(0, i_stream.take_written());

    // Responder reads msg1.
    let r_stream = PeerStream::new();
    r_stream.feed(&msg1);
    let r = SyncHandshake::<IKpsk1, Responder, _, _, _, _>::respond(
        EphemeralOnly::new(ScriptedRng::new(&[&RESP_EPHEMERAL])),
        &[],
        r_stream.clone(),
    )
    .set_s(private_key(&RESP_STATIC))
    .map_err(|_| ())?;
    let (_, recv) = r.recv().e().map_err(|_| ())?;
    let recv = recv.es().map_err(|_| ())?;
    let (_, recv) = recv.s().map_err(|_| ())?;
    let recv = recv.ss().map_err(|_| ())?;
    let r = recv.psk(&psk).map_err(|_| ())?;

    // Responder sends msg2 (genuine).
    let _ = r.e().unwrap().ee().unwrap().se().unwrap();
    let msg2 = xform(1, r_stream.take_written());

    // Initiator reads msg2.
    i_stream.feed(&msg2);
    let (_, recv) = i.recv().e().map_err(|_| ())?;
    recv.ee().map_err(|_| ())?.se().map_err(|_| ())?;
    fully_drained(&i_stream, &r_stream)
}

fn run_ik(xform: &Xform<'_>) -> Result<(), ()> {
    let i_stream = PeerStream::new();
    let i = SyncHandshake::<IK, Initiator, _, _, _, _>::initiate(
        EphemeralOnly::new(ScriptedRng::new(&[&INIT_EPHEMERAL])),
        &[],
        i_stream.clone(),
    )
    .set_rs(public_key(&RESP_STATIC));
    let i = i
        .e()
        .unwrap()
        .es()
        .unwrap()
        .s(private_key(&INIT_STATIC))
        .unwrap()
        .ss()
        .unwrap();
    let msg1 = xform(0, i_stream.take_written());

    // Responder reads msg1.
    let r_stream = PeerStream::new();
    r_stream.feed(&msg1);
    let r = SyncHandshake::<IK, Responder, _, _, _, _>::respond(
        EphemeralOnly::new(ScriptedRng::new(&[&RESP_EPHEMERAL])),
        &[],
        r_stream.clone(),
    )
    .set_s(private_key(&RESP_STATIC))
    .map_err(|_| ())?;
    let (_, recv) = r.recv().e().map_err(|_| ())?;
    let recv = recv.es().map_err(|_| ())?;
    let (_, recv) = recv.s().map_err(|_| ())?;
    let r = recv.ss().map_err(|_| ())?;

    // Responder sends msg2 (genuine).
    let _ = r.e().unwrap().ee().unwrap().se().unwrap();
    let msg2 = xform(1, r_stream.take_written());

    // Initiator reads msg2.
    i_stream.feed(&msg2);
    let (_, recv) = i.recv().e().map_err(|_| ())?;
    recv.ee().map_err(|_| ())?.se().map_err(|_| ())?;
    fully_drained(&i_stream, &r_stream)
}

fn run_nk(xform: &Xform<'_>) -> Result<(), ()> {
    // NK initiator is anonymous: no static, responder static known.
    let i_stream = PeerStream::new();
    let i = SyncHandshake::<NK, Initiator, _, _, _, _>::initiate(
        EphemeralOnly::new(ScriptedRng::new(&[&INIT_EPHEMERAL])),
        &[],
        i_stream.clone(),
    )
    .set_rs(public_key(&RESP_STATIC));
    let i = i.e().unwrap().es().unwrap();
    let msg1 = xform(0, i_stream.take_written());

    // Responder reads msg1.
    let r_stream = PeerStream::new();
    r_stream.feed(&msg1);
    let r = SyncHandshake::<NK, Responder, _, _, _, _>::respond(
        EphemeralOnly::new(ScriptedRng::new(&[&RESP_EPHEMERAL])),
        &[],
        r_stream.clone(),
    )
    .set_s(private_key(&RESP_STATIC))
    .map_err(|_| ())?;
    let (_, recv) = r.recv().e().map_err(|_| ())?;
    let r = recv.es().map_err(|_| ())?;

    // Responder sends msg2 (genuine).
    let _ = r.e().unwrap().ee().unwrap();
    let msg2 = xform(1, r_stream.take_written());

    // Initiator reads msg2.
    i_stream.feed(&msg2);
    let (_, recv) = i.recv().e().map_err(|_| ())?;
    recv.ee().map_err(|_| ())?;
    fully_drained(&i_stream, &r_stream)
}

fn run_ix(xform: &Xform<'_>) -> Result<(), ()> {
    // IX has no pre-messages: both statics are transmitted in-handshake
    // via `s` tokens, so neither side has a pre-message setter.
    let i_stream = PeerStream::new();
    let i = SyncHandshake::<IX, Initiator, _, _, _, _>::initiate(
        EphemeralOnly::new(ScriptedRng::new(&[&INIT_EPHEMERAL])),
        &[],
        i_stream.clone(),
    );
    let i = i.e().unwrap().s(private_key(&INIT_STATIC)).unwrap();
    let msg1 = xform(0, i_stream.take_written());

    // Responder reads msg1 (-> e, s); the `s` reveals the initiator static.
    let r_stream = PeerStream::new();
    r_stream.feed(&msg1);
    let r = SyncHandshake::<IX, Responder, _, _, _, _>::respond(
        EphemeralOnly::new(ScriptedRng::new(&[&RESP_EPHEMERAL])),
        &[],
        r_stream.clone(),
    );
    let (_, recv) = r.recv().e().map_err(|_| ())?;
    let (_, recv) = recv.s().map_err(|_| ())?;

    // Responder sends msg2 (<- e, ee, se, s, es) — genuine.
    let _ = recv
        .e()
        .unwrap()
        .ee()
        .unwrap()
        .se()
        .unwrap()
        .s(private_key(&RESP_STATIC))
        .unwrap()
        .es()
        .unwrap();
    let msg2 = xform(1, r_stream.take_written());

    // Initiator reads msg2; the `s` reveals the responder static.
    i_stream.feed(&msg2);
    let (_, recv) = i.recv().e().map_err(|_| ())?;
    let recv = recv.ee().map_err(|_| ())?.se().map_err(|_| ())?;
    let (_, recv) = recv.s().map_err(|_| ())?;
    recv.es().map_err(|_| ())?;
    fully_drained(&i_stream, &r_stream)
}

fn run_xk(xform: &Xform<'_>) -> Result<(), ()> {
    // XK pre-message `<- s`: the initiator pre-knows the responder static
    // (`set_rs`); the responder holds its own static (`set_s`).
    let i_stream = PeerStream::new();
    let i = SyncHandshake::<XK, Initiator, _, _, _, _>::initiate(
        EphemeralOnly::new(ScriptedRng::new(&[&INIT_EPHEMERAL])),
        &[],
        i_stream.clone(),
    )
    .set_rs(public_key(&RESP_STATIC));

    // msg1: -> e, es
    let i = i.e().unwrap().es().unwrap();
    let msg1 = xform(0, i_stream.take_written());

    // Responder reads msg1 (-> e, es).
    let r_stream = PeerStream::new();
    r_stream.feed(&msg1);
    let r = SyncHandshake::<XK, Responder, _, _, _, _>::respond(
        EphemeralOnly::new(ScriptedRng::new(&[&RESP_EPHEMERAL])),
        &[],
        r_stream.clone(),
    )
    .set_s(private_key(&RESP_STATIC))
    .map_err(|_| ())?;
    let (_, recv) = r.recv().e().map_err(|_| ())?;
    let r = recv.es().map_err(|_| ())?;

    // msg2: <- e, ee — genuine.
    let r = r.e().unwrap().ee().unwrap();
    let msg2 = xform(1, r_stream.take_written());

    // Initiator reads msg2 (<- e, ee).
    i_stream.feed(&msg2);
    let (_, recv) = i.recv().e().map_err(|_| ())?;
    let i = recv.ee().map_err(|_| ())?;

    // msg3: -> s, se — the initiator's static is sent encrypted (after ee).
    let _ = i.s(private_key(&INIT_STATIC)).unwrap().se().unwrap();
    let msg3 = xform(2, i_stream.take_written());

    // Responder reads msg3; the `s` reveals the initiator static.
    r_stream.feed(&msg3);
    let (_, recv) = r.recv().s().map_err(|_| ())?;
    recv.se().map_err(|_| ())?;
    fully_drained(&i_stream, &r_stream)
}

fn run_nn(xform: &Xform<'_>) -> Result<(), ()> {
    // NN has no static keys and no pre-messages: both parties are
    // anonymous. msg1 is a bare `-> e` (the single-`e` send finalizer).
    let i_stream = PeerStream::new();
    let i = SyncHandshake::<NN, Initiator, _, _, _, _>::initiate(
        EphemeralOnly::new(ScriptedRng::new(&[&INIT_EPHEMERAL])),
        &[],
        i_stream.clone(),
    );
    let i = i.e().unwrap();
    let msg1 = xform(0, i_stream.take_written());

    // Responder reads msg1 (-> e).
    let r_stream = PeerStream::new();
    r_stream.feed(&msg1);
    let r = SyncHandshake::<NN, Responder, _, _, _, _>::respond(
        EphemeralOnly::new(ScriptedRng::new(&[&RESP_EPHEMERAL])),
        &[],
        r_stream.clone(),
    );
    let (_, recv) = r.recv().e().map_err(|_| ())?;

    // Responder sends msg2 (<- e, ee), genuine.
    let _ = recv.e().unwrap().ee().unwrap();
    let msg2 = xform(1, r_stream.take_written());

    // Initiator reads msg2.
    i_stream.feed(&msg2);
    let (_, recv) = i.recv().e().map_err(|_| ())?;
    recv.ee().map_err(|_| ())?;
    fully_drained(&i_stream, &r_stream)
}

fn run_xx(xform: &Xform<'_>) -> Result<(), ()> {
    // XX has no pre-messages: neither static is pre-known. Both parties
    // transmit their statics in-handshake, encrypted (after `ee`).
    // msg1 is a bare `-> e` (the single-`e` send finalizer).
    let i_stream = PeerStream::new();
    let i = SyncHandshake::<XX, Initiator, _, _, _, _>::initiate(
        EphemeralOnly::new(ScriptedRng::new(&[&INIT_EPHEMERAL])),
        &[],
        i_stream.clone(),
    );
    let i = i.e().unwrap();
    let msg1 = xform(0, i_stream.take_written());

    // Responder reads msg1 (-> e).
    let r_stream = PeerStream::new();
    r_stream.feed(&msg1);
    let r = SyncHandshake::<XX, Responder, _, _, _, _>::respond(
        EphemeralOnly::new(ScriptedRng::new(&[&RESP_EPHEMERAL])),
        &[],
        r_stream.clone(),
    );
    let (_, recv) = r.recv().e().map_err(|_| ())?;

    // msg2: <- e, ee, s, es — the responder's static is sent encrypted
    // (after ee), genuine.
    let r = recv
        .e()
        .unwrap()
        .ee()
        .unwrap()
        .s(private_key(&RESP_STATIC))
        .unwrap()
        .es()
        .unwrap();
    let msg2 = xform(1, r_stream.take_written());

    // Initiator reads msg2 (<- e, ee, s, es); the `s` reveals the
    // responder static.
    i_stream.feed(&msg2);
    let (_, recv) = i.recv().e().map_err(|_| ())?;
    let recv = recv.ee().map_err(|_| ())?;
    let (_, recv) = recv.s().map_err(|_| ())?;
    let i = recv.es().map_err(|_| ())?;

    // msg3: -> s, se — the initiator's static is sent encrypted (after ee).
    let _ = i.s(private_key(&INIT_STATIC)).unwrap().se().unwrap();
    let msg3 = xform(2, i_stream.take_written());

    // Responder reads msg3; the `s` reveals the initiator static.
    r_stream.feed(&msg3);
    let (_, recv) = r.recv().s().map_err(|_| ())?;
    recv.se().map_err(|_| ())?;
    fully_drained(&i_stream, &r_stream)
}

// ── Sweep helpers ────────────────────────────────────────────────

/// Assert that the genuine handshake completes, then that flipping any
/// single byte of message `msg_idx` (of length `len`) is rejected, and
/// that every truncated prefix and an over-long variant are rejected.
fn sweep<F>(label: &str, msg_idx: usize, len: usize, run: F)
where
    F: Fn(Box<Xform<'static>>) -> Result<(), ()>,
{
    assert!(
        run(Box::new(identity)).is_ok(),
        "{label}: genuine handshake must complete"
    );

    for byte in 0..len {
        let res = run(Box::new(
            move |idx, m| if idx == msg_idx { flip(m, byte) } else { m },
        ));
        assert!(res.is_err(), "{label}: flip of byte {byte} not rejected");
    }

    for prefix in 0..len {
        let res = run(Box::new(move |idx, m| {
            if idx == msg_idx {
                m[..prefix].to_vec()
            } else {
                m
            }
        }));
        assert!(res.is_err(), "{label}: truncation to {prefix} not rejected");
    }

    let over = run(Box::new(move |idx, mut m| {
        if idx == msg_idx {
            m.push(0);
        }
        m
    }));
    assert!(over.is_err(), "{label}: over-length message not rejected");
}

// ── Tamper + truncation sweeps, per pattern ──────────────────────

#[test]
fn n_msg1_tamper_truncation_sweep() {
    sweep("N msg1", 0, ONE_MSG, |xf| run_n(&*xf));
}

#[test]
fn k_msg1_tamper_truncation_sweep() {
    sweep("K msg1", 0, ONE_MSG, |xf| run_k(&*xf));
}

#[test]
fn kpsk0_msg1_tamper_truncation_sweep() {
    sweep("Kpsk0 msg1", 0, ONE_MSG, |xf| run_kpsk0(&*xf));
}

#[test]
fn ikpsk1_msg1_tamper_truncation_sweep() {
    sweep("IKpsk1 msg1", 0, IK_MSG1, |xf| run_ikpsk1(&*xf));
}

#[test]
fn ikpsk1_msg2_tamper_truncation_sweep() {
    sweep("IKpsk1 msg2", 1, IK_MSG2, |xf| run_ikpsk1(&*xf));
}

#[test]
fn ik_msg1_tamper_truncation_sweep() {
    sweep("IK msg1", 0, IK_MSG1, |xf| run_ik(&*xf));
}

#[test]
fn ik_msg2_tamper_truncation_sweep() {
    sweep("IK msg2", 1, IK_MSG2, |xf| run_ik(&*xf));
}

#[test]
fn nk_msg1_tamper_truncation_sweep() {
    sweep("NK msg1", 0, NK_MSG1, |xf| run_nk(&*xf));
}

#[test]
fn nk_msg2_tamper_truncation_sweep() {
    sweep("NK msg2", 1, NK_MSG2, |xf| run_nk(&*xf));
}

#[test]
fn ix_msg1_tamper_truncation_sweep() {
    sweep("IX msg1", 0, IX_MSG1, |xf| run_ix(&*xf));
}

#[test]
fn ix_msg2_tamper_truncation_sweep() {
    sweep("IX msg2", 1, IX_MSG2, |xf| run_ix(&*xf));
}

#[test]
fn xk_msg1_tamper_truncation_sweep() {
    sweep("XK msg1", 0, XK_MSG1, |xf| run_xk(&*xf));
}

#[test]
fn xk_msg2_tamper_truncation_sweep() {
    sweep("XK msg2", 1, XK_MSG2, |xf| run_xk(&*xf));
}

#[test]
fn xk_msg3_tamper_truncation_sweep() {
    sweep("XK msg3", 2, XK_MSG3, |xf| run_xk(&*xf));
}

#[test]
fn nn_msg1_tamper_truncation_sweep() {
    sweep("NN msg1", 0, NN_MSG1, |xf| run_nn(&*xf));
}

#[test]
fn nn_msg2_tamper_truncation_sweep() {
    sweep("NN msg2", 1, NN_MSG2, |xf| run_nn(&*xf));
}

#[test]
fn xx_msg1_tamper_truncation_sweep() {
    sweep("XX msg1", 0, XX_MSG1, |xf| run_xx(&*xf));
}

#[test]
fn xx_msg2_tamper_truncation_sweep() {
    sweep("XX msg2", 1, XX_MSG2, |xf| run_xx(&*xf));
}

#[test]
fn xx_msg3_tamper_truncation_sweep() {
    sweep("XX msg3", 2, XX_MSG3, |xf| run_xx(&*xf));
}

// ── Non-canonical on-wire public key (M1) ────────────────────────

#[test]
fn noncanonical_ephemeral_rejected() {
    use hiss::curve::p256::P256r1PublicKey;

    // NN msg1 is a bare `-> e`: the 65-byte wire payload *is* the
    // initiator's ephemeral in canonical (0x04 ‖ X ‖ Y) form.
    let i_stream = PeerStream::new();
    let i = SyncHandshake::<NN, Initiator, _, _, _, _>::initiate(
        EphemeralOnly::new(ScriptedRng::new(&[&INIT_EPHEMERAL])),
        &[],
        i_stream.clone(),
    );
    let _ = i.e().unwrap();
    let msg1 = i_stream.take_written();
    assert_eq!(msg1.len(), NN_MSG1, "NN msg1 is a bare 65-byte ephemeral");

    // Re-encode the genuine ephemeral non-canonically: its 33-byte
    // compressed form, right-padded with trailing zeros to the 65-byte
    // wire width. This decodes to the *same* point (so it passes
    // `from_bytes`) but is not the canonical encoding the send path emits.
    let e_pub = P256r1PublicKey::from_bytes(&msg1).expect("genuine ephemeral decodes");
    let mut tampered = vec![0u8; NN_MSG1];
    tampered[..33].copy_from_slice(&e_pub.to_compressed());

    let r_stream = PeerStream::new();
    r_stream.feed(&tampered);
    let r = SyncHandshake::<NN, Responder, _, _, _, _>::respond(
        EphemeralOnly::new(ScriptedRng::new(&[&RESP_EPHEMERAL])),
        &[],
        r_stream.clone(),
    );
    let err = r.recv().e().map(|_| ()).unwrap_err();
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

    let i_stream = PeerStream::new();
    let i = SyncHandshake::<Kpsk0, Initiator, _, _, _, _>::initiate(
        EphemeralOnly::new(ScriptedRng::new(&[&INIT_EPHEMERAL])),
        &[],
        i_stream.clone(),
    )
    .set_s(private_key(&INIT_STATIC))
    .unwrap()
    .set_rs(public_key(&RESP_STATIC));
    let _ = i
        .psk(&good)
        .unwrap()
        .e()
        .unwrap()
        .es()
        .unwrap()
        .ss()
        .unwrap();
    let msg1 = i_stream.take_written();

    let r_stream = PeerStream::new();
    r_stream.feed(&msg1);
    let r = SyncHandshake::<Kpsk0, Responder, _, _, _, _>::respond(
        EphemeralOnly::new(StdRng::seed_from_u64(9)),
        &[],
        r_stream.clone(),
    )
    .set_rs(public_key(&INIT_STATIC))
    .set_s(private_key(&RESP_STATIC))
    .unwrap();
    let recv = r.recv().psk(&bad).unwrap();
    let (_, recv) = recv.e().unwrap();
    let recv = recv.es().unwrap();
    // The mismatched PSK diverges the key schedule; the final payload tag
    // fails to verify at the last token of msg1.
    assert!(recv.ss().is_err(), "Kpsk0 wrong PSK not rejected");
}

// ── Transport: tamper sweep + nonce sequencing ───────────────────

type ChannelN = Noise<pattern::N, P256, ChaChaPoly, Blake2b>;
type NTransport = Transport<ChannelN>;

/// Complete an N handshake hiss↔hiss and return both transport states.
fn complete_n() -> (NTransport, NTransport) {
    let i_stream = PeerStream::new();
    let i = SyncHandshake::<ChannelN, Initiator, _, _, _, _>::initiate(
        EphemeralOnly::new(ScriptedRng::new(&[&INIT_EPHEMERAL])),
        &[],
        i_stream.clone(),
    )
    .set_rs(public_key(&RESP_STATIC));
    let chain = i.e().unwrap().es().unwrap();
    let (i_transport, _) = chain.into_parts();
    let msg1 = i_stream.take_written();

    let r_stream = PeerStream::new();
    r_stream.feed(&msg1);
    let r = SyncHandshake::<ChannelN, Responder, _, _, _, _>::respond(
        EphemeralOnly::new(StdRng::seed_from_u64(7)),
        &[],
        r_stream.clone(),
    )
    .set_s(private_key(&RESP_STATIC))
    .unwrap();
    let (_, recv) = r.recv().e().unwrap();
    let (r_transport, _) = recv.es().unwrap().into_parts();
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
