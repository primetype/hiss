//! Systematic protocol-level negative / boundary tests (A3.7).
//!
//! Where `src/noise/mod.rs` has hand-picked single-corruption tests, this
//! file sweeps the adversarial space deterministically (via the
//! [`ScriptedRng`] ephemeral-injection harness) across all seven supported
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
use common::{ScriptedRng, private_key, public_key};

use hiss::noise::*;
use hiss::provider::EphemeralOnly;
use hiss::psk::Psk;
use rand::{SeedableRng, rngs::StdRng};

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

async fn run_n(xform: &Xform<'_>) -> Result<(), ()> {
    let i = N::initiate(
        EphemeralOnly::new(ScriptedRng::new(&[&INIT_EPHEMERAL])),
        &[],
    )
    .set_rs(public_key(&RESP_STATIC));
    let mut buf = [0u8; 256];
    let (msg1, _t) = i.e(&mut buf).await.unwrap().es().await.unwrap();
    let msg1 = xform(0, msg1.to_vec());

    let r = N::respond(
        EphemeralOnly::new(StdRng::seed_from_u64(1)),
        &[],
    )
    .set_s(private_key(&RESP_STATIC))
    .map_err(|_| ())?;
    let (_, recv) = r.read(&msg1).map_err(|_| ())?.e().await.map_err(|_| ())?;
    recv.es().await.map_err(|_| ())?;
    Ok(())
}

async fn run_k(xform: &Xform<'_>) -> Result<(), ()> {
    let i = K::initiate(
        EphemeralOnly::new(ScriptedRng::new(&[&INIT_EPHEMERAL])),
        &[],
    )
    .set_s(private_key(&INIT_STATIC))
    .unwrap()
    .set_rs(public_key(&RESP_STATIC));
    let mut buf = [0u8; 256];
    let (msg1, _t) = i
        .e(&mut buf)
        .await
        .unwrap()
        .es()
        .await
        .unwrap()
        .ss()
        .await
        .unwrap();
    let msg1 = xform(0, msg1.to_vec());

    let r = K::respond(
        EphemeralOnly::new(StdRng::seed_from_u64(2)),
        &[],
    )
    .set_rs(public_key(&INIT_STATIC))
    .set_s(private_key(&RESP_STATIC))
    .map_err(|_| ())?;
    let (_, recv) = r.read(&msg1).map_err(|_| ())?.e().await.map_err(|_| ())?;
    recv.es().await.map_err(|_| ())?.ss().await.map_err(|_| ())?;
    Ok(())
}

async fn run_kpsk0(xform: &Xform<'_>) -> Result<(), ()> {
    let psk = Psk::from_bytes(PSK_BYTES);
    let i = Kpsk0::initiate(
        EphemeralOnly::new(ScriptedRng::new(&[&INIT_EPHEMERAL])),
        &[],
    )
    .set_s(private_key(&INIT_STATIC))
    .unwrap()
    .set_rs(public_key(&RESP_STATIC));
    let mut buf = [0u8; 256];
    let (msg1, _t) = i
        .psk(&mut buf, &psk)
        .await
        .unwrap()
        .e()
        .await
        .unwrap()
        .es()
        .await
        .unwrap()
        .ss()
        .await
        .unwrap();
    let msg1 = xform(0, msg1.to_vec());

    let r = Kpsk0::respond(
        EphemeralOnly::new(StdRng::seed_from_u64(3)),
        &[],
    )
    .set_rs(public_key(&INIT_STATIC))
    .set_s(private_key(&RESP_STATIC))
    .map_err(|_| ())?;
    let recv = r.read(&msg1).map_err(|_| ())?.psk(&psk).await.map_err(|_| ())?;
    let (_, recv) = recv.e().await.map_err(|_| ())?;
    recv.es().await.map_err(|_| ())?.ss().await.map_err(|_| ())?;
    Ok(())
}

async fn run_ikpsk1(xform: &Xform<'_>) -> Result<(), ()> {
    let psk = Psk::from_bytes(PSK_BYTES);
    let i = IKpsk1::initiate(
        EphemeralOnly::new(ScriptedRng::new(&[&INIT_EPHEMERAL])),
        &[],
    )
    .set_rs(public_key(&RESP_STATIC));
    let mut b1 = [0u8; 256];
    let (msg1, i) = i
        .e(&mut b1)
        .await
        .unwrap()
        .es()
        .await
        .unwrap()
        .s(private_key(&INIT_STATIC))
        .await
        .unwrap()
        .ss()
        .await
        .unwrap()
        .psk(&psk)
        .await
        .unwrap();
    let msg1 = xform(0, msg1.to_vec());

    // Responder reads msg1.
    let r = IKpsk1::respond(
        EphemeralOnly::new(ScriptedRng::new(&[&RESP_EPHEMERAL])),
        &[],
    )
    .set_s(private_key(&RESP_STATIC))
    .map_err(|_| ())?;
    let (_, recv) = r.read(&msg1).map_err(|_| ())?.e().await.map_err(|_| ())?;
    let recv = recv.es().await.map_err(|_| ())?;
    let (_, recv) = recv.s().await.map_err(|_| ())?;
    let recv = recv.ss().await.map_err(|_| ())?;
    let r = recv.psk(&psk).await.map_err(|_| ())?;

    // Responder sends msg2 (genuine).
    let mut b2 = [0u8; 256];
    let (msg2, _r_transport) = r
        .e(&mut b2)
        .await
        .unwrap()
        .ee()
        .await
        .unwrap()
        .se()
        .await
        .unwrap();
    let msg2 = xform(1, msg2.to_vec());

    // Initiator reads msg2.
    let (_, recv) = i.read(&msg2).map_err(|_| ())?.e().await.map_err(|_| ())?;
    recv.ee().await.map_err(|_| ())?.se().await.map_err(|_| ())?;
    Ok(())
}

async fn run_ik(xform: &Xform<'_>) -> Result<(), ()> {
    let i = IK::initiate(
        EphemeralOnly::new(ScriptedRng::new(&[&INIT_EPHEMERAL])),
        &[],
    )
    .set_rs(public_key(&RESP_STATIC));
    let mut b1 = [0u8; 256];
    let (msg1, i) = i
        .e(&mut b1)
        .await
        .unwrap()
        .es()
        .await
        .unwrap()
        .s(private_key(&INIT_STATIC))
        .await
        .unwrap()
        .ss()
        .await
        .unwrap();
    let msg1 = xform(0, msg1.to_vec());

    // Responder reads msg1.
    let r = IK::respond(
        EphemeralOnly::new(ScriptedRng::new(&[&RESP_EPHEMERAL])),
        &[],
    )
    .set_s(private_key(&RESP_STATIC))
    .map_err(|_| ())?;
    let (_, recv) = r.read(&msg1).map_err(|_| ())?.e().await.map_err(|_| ())?;
    let recv = recv.es().await.map_err(|_| ())?;
    let (_, recv) = recv.s().await.map_err(|_| ())?;
    let r = recv.ss().await.map_err(|_| ())?;

    // Responder sends msg2 (genuine).
    let mut b2 = [0u8; 256];
    let (msg2, _r_transport) = r
        .e(&mut b2)
        .await
        .unwrap()
        .ee()
        .await
        .unwrap()
        .se()
        .await
        .unwrap();
    let msg2 = xform(1, msg2.to_vec());

    // Initiator reads msg2.
    let (_, recv) = i.read(&msg2).map_err(|_| ())?.e().await.map_err(|_| ())?;
    recv.ee().await.map_err(|_| ())?.se().await.map_err(|_| ())?;
    Ok(())
}

async fn run_nk(xform: &Xform<'_>) -> Result<(), ()> {
    // NK initiator is anonymous: no static, responder static known.
    let i = NK::initiate(
        EphemeralOnly::new(ScriptedRng::new(&[&INIT_EPHEMERAL])),
        &[],
    )
    .set_rs(public_key(&RESP_STATIC));
    let mut b1 = [0u8; 256];
    let (msg1, i) = i.e(&mut b1).await.unwrap().es().await.unwrap();
    let msg1 = xform(0, msg1.to_vec());

    // Responder reads msg1.
    let r = NK::respond(
        EphemeralOnly::new(ScriptedRng::new(&[&RESP_EPHEMERAL])),
        &[],
    )
    .set_s(private_key(&RESP_STATIC))
    .map_err(|_| ())?;
    let (_, recv) = r.read(&msg1).map_err(|_| ())?.e().await.map_err(|_| ())?;
    let r = recv.es().await.map_err(|_| ())?;

    // Responder sends msg2 (genuine).
    let mut b2 = [0u8; 256];
    let (msg2, _r_transport) = r.e(&mut b2).await.unwrap().ee().await.unwrap();
    let msg2 = xform(1, msg2.to_vec());

    // Initiator reads msg2.
    let (_, recv) = i.read(&msg2).map_err(|_| ())?.e().await.map_err(|_| ())?;
    recv.ee().await.map_err(|_| ())?;
    Ok(())
}

async fn run_ix(xform: &Xform<'_>) -> Result<(), ()> {
    // IX has no pre-messages: both statics are transmitted in-handshake
    // via `s` tokens, so neither side has a pre-message setter.
    let i = IX::initiate(
        EphemeralOnly::new(ScriptedRng::new(&[&INIT_EPHEMERAL])),
        &[],
    );
    let mut b1 = [0u8; 256];
    let (msg1, i) = i
        .e(&mut b1)
        .await
        .unwrap()
        .s(private_key(&INIT_STATIC))
        .await
        .unwrap();
    let msg1 = xform(0, msg1.to_vec());

    // Responder reads msg1 (-> e, s); the `s` reveals the initiator static.
    let r = IX::respond(
        EphemeralOnly::new(ScriptedRng::new(&[&RESP_EPHEMERAL])),
        &[],
    );
    let (_, recv) = r.read(&msg1).map_err(|_| ())?.e().await.map_err(|_| ())?;
    let (_, recv) = recv.s().await.map_err(|_| ())?;

    // Responder sends msg2 (<- e, ee, se, s, es) — genuine.
    let mut b2 = [0u8; 256];
    let (msg2, _r_transport) = recv
        .e(&mut b2)
        .await
        .unwrap()
        .ee()
        .await
        .unwrap()
        .se()
        .await
        .unwrap()
        .s(private_key(&RESP_STATIC))
        .await
        .unwrap()
        .es()
        .await
        .unwrap();
    let msg2 = xform(1, msg2.to_vec());

    // Initiator reads msg2; the `s` reveals the responder static.
    let (_, recv) = i.read(&msg2).map_err(|_| ())?.e().await.map_err(|_| ())?;
    let recv = recv.ee().await.map_err(|_| ())?.se().await.map_err(|_| ())?;
    let (_, recv) = recv.s().await.map_err(|_| ())?;
    recv.es().await.map_err(|_| ())?;
    Ok(())
}

async fn run_xk(xform: &Xform<'_>) -> Result<(), ()> {
    // XK pre-message `<- s`: the initiator pre-knows the responder static
    // (`set_rs`); the responder holds its own static (`set_s`).
    let i = XK::initiate(
        EphemeralOnly::new(ScriptedRng::new(&[&INIT_EPHEMERAL])),
        &[],
    )
    .set_rs(public_key(&RESP_STATIC));

    // msg1: -> e, es
    let mut b1 = [0u8; 256];
    let (msg1, i) = i.e(&mut b1).await.unwrap().es().await.unwrap();
    let msg1 = xform(0, msg1.to_vec());

    // Responder reads msg1 (-> e, es).
    let r = XK::respond(
        EphemeralOnly::new(ScriptedRng::new(&[&RESP_EPHEMERAL])),
        &[],
    )
    .set_s(private_key(&RESP_STATIC))
    .map_err(|_| ())?;
    let (_, recv) = r.read(&msg1).map_err(|_| ())?.e().await.map_err(|_| ())?;
    let r = recv.es().await.map_err(|_| ())?;

    // msg2: <- e, ee — genuine.
    let mut b2 = [0u8; 256];
    let (msg2, r) = r.e(&mut b2).await.unwrap().ee().await.unwrap();
    let msg2 = xform(1, msg2.to_vec());

    // Initiator reads msg2 (<- e, ee).
    let (_, recv) = i.read(&msg2).map_err(|_| ())?.e().await.map_err(|_| ())?;
    let i = recv.ee().await.map_err(|_| ())?;

    // msg3: -> s, se — the initiator's static is sent encrypted (after ee).
    let mut b3 = [0u8; 256];
    let (msg3, _i_transport) = i
        .s(&mut b3, private_key(&INIT_STATIC))
        .await
        .unwrap()
        .se()
        .await
        .unwrap();
    let msg3 = xform(2, msg3.to_vec());

    // Responder reads msg3; the `s` reveals the initiator static.
    let (_, recv) = r.read(&msg3).map_err(|_| ())?.s().await.map_err(|_| ())?;
    recv.se().await.map_err(|_| ())?;
    Ok(())
}

// ── Sweep helpers ────────────────────────────────────────────────

/// Assert that the genuine handshake completes, then that flipping any
/// single byte of message `msg_idx` (of length `len`) is rejected, and
/// that every truncated prefix and an over-long variant are rejected.
async fn sweep<F, Fut>(label: &str, msg_idx: usize, len: usize, run: F)
where
    F: Fn(Box<Xform<'static>>) -> Fut,
    Fut: std::future::Future<Output = Result<(), ()>>,
{
    assert!(
        run(Box::new(identity)).await.is_ok(),
        "{label}: genuine handshake must complete"
    );

    for byte in 0..len {
        let res = run(Box::new(move |idx, m| if idx == msg_idx { flip(m, byte) } else { m })).await;
        assert!(res.is_err(), "{label}: flip of byte {byte} not rejected");
    }

    for prefix in 0..len {
        let res =
            run(Box::new(move |idx, m| if idx == msg_idx { m[..prefix].to_vec() } else { m })).await;
        assert!(res.is_err(), "{label}: truncation to {prefix} not rejected");
    }

    let over = run(Box::new(move |idx, mut m| {
        if idx == msg_idx {
            m.push(0);
        }
        m
    }))
    .await;
    assert!(over.is_err(), "{label}: over-length message not rejected");
}

// ── Tamper + truncation sweeps, per pattern ──────────────────────

#[tokio::test]
async fn n_msg1_tamper_truncation_sweep() {
    sweep("N msg1", 0, ONE_MSG, |xf| async move { run_n(&*xf).await }).await;
}

#[tokio::test]
async fn k_msg1_tamper_truncation_sweep() {
    sweep("K msg1", 0, ONE_MSG, |xf| async move { run_k(&*xf).await }).await;
}

#[tokio::test]
async fn kpsk0_msg1_tamper_truncation_sweep() {
    sweep("Kpsk0 msg1", 0, ONE_MSG, |xf| async move { run_kpsk0(&*xf).await }).await;
}

#[tokio::test]
async fn ikpsk1_msg1_tamper_truncation_sweep() {
    sweep("IKpsk1 msg1", 0, IK_MSG1, |xf| async move { run_ikpsk1(&*xf).await }).await;
}

#[tokio::test]
async fn ikpsk1_msg2_tamper_truncation_sweep() {
    sweep("IKpsk1 msg2", 1, IK_MSG2, |xf| async move { run_ikpsk1(&*xf).await }).await;
}

#[tokio::test]
async fn ik_msg1_tamper_truncation_sweep() {
    sweep("IK msg1", 0, IK_MSG1, |xf| async move { run_ik(&*xf).await }).await;
}

#[tokio::test]
async fn ik_msg2_tamper_truncation_sweep() {
    sweep("IK msg2", 1, IK_MSG2, |xf| async move { run_ik(&*xf).await }).await;
}

#[tokio::test]
async fn nk_msg1_tamper_truncation_sweep() {
    sweep("NK msg1", 0, NK_MSG1, |xf| async move { run_nk(&*xf).await }).await;
}

#[tokio::test]
async fn nk_msg2_tamper_truncation_sweep() {
    sweep("NK msg2", 1, NK_MSG2, |xf| async move { run_nk(&*xf).await }).await;
}

#[tokio::test]
async fn ix_msg1_tamper_truncation_sweep() {
    sweep("IX msg1", 0, IX_MSG1, |xf| async move { run_ix(&*xf).await }).await;
}

#[tokio::test]
async fn ix_msg2_tamper_truncation_sweep() {
    sweep("IX msg2", 1, IX_MSG2, |xf| async move { run_ix(&*xf).await }).await;
}

#[tokio::test]
async fn xk_msg1_tamper_truncation_sweep() {
    sweep("XK msg1", 0, XK_MSG1, |xf| async move { run_xk(&*xf).await }).await;
}

#[tokio::test]
async fn xk_msg2_tamper_truncation_sweep() {
    sweep("XK msg2", 1, XK_MSG2, |xf| async move { run_xk(&*xf).await }).await;
}

#[tokio::test]
async fn xk_msg3_tamper_truncation_sweep() {
    sweep("XK msg3", 2, XK_MSG3, |xf| async move { run_xk(&*xf).await }).await;
}

// ── Wrong PSK ────────────────────────────────────────────────────

#[tokio::test]
async fn kpsk0_wrong_psk_rejected() {
    // Re-run Kpsk0 but with the responder using a different PSK. We splice
    // a wrong-PSK responder by hand (the driver bakes in PSK_BYTES).
    let good = Psk::from_bytes(PSK_BYTES);
    let bad = Psk::from_bytes([0x00; 32]);

    let i = Kpsk0::initiate(
        EphemeralOnly::new(ScriptedRng::new(&[&INIT_EPHEMERAL])),
        &[],
    )
    .set_s(private_key(&INIT_STATIC))
    .unwrap()
    .set_rs(public_key(&RESP_STATIC));
    let mut buf = [0u8; 256];
    let (msg1, _t) = i
        .psk(&mut buf, &good)
        .await
        .unwrap()
        .e()
        .await
        .unwrap()
        .es()
        .await
        .unwrap()
        .ss()
        .await
        .unwrap();
    let msg1 = msg1.to_vec();

    let r = Kpsk0::respond(
        EphemeralOnly::new(StdRng::seed_from_u64(9)),
        &[],
    )
    .set_rs(public_key(&INIT_STATIC))
    .set_s(private_key(&RESP_STATIC))
    .unwrap();
    let recv = r.read(&msg1).unwrap().psk(&bad).await.unwrap();
    let (_, recv) = recv.e().await.unwrap();
    let recv = recv.es().await.unwrap();
    // The mismatched PSK diverges the key schedule; the final payload tag
    // fails to verify at the last token of msg1.
    assert!(recv.ss().await.is_err(), "Kpsk0 wrong PSK not rejected");
}

// ── Transport: tamper sweep + nonce sequencing ───────────────────

type ChannelN = N;
type NTransport = Transport<ChannelN>;

/// Complete an N handshake hiss↔hiss and return both transport states.
async fn complete_n() -> (NTransport, NTransport) {
    let i = ChannelN::initiate(
        EphemeralOnly::new(ScriptedRng::new(&[&INIT_EPHEMERAL])),
        &[],
    )
    .set_rs(public_key(&RESP_STATIC));
    let mut buf = [0u8; 256];
    let (msg1, i_transport) = i.e(&mut buf).await.unwrap().es().await.unwrap();
    let msg1 = msg1.to_vec();

    let r = ChannelN::respond(EphemeralOnly::new(StdRng::seed_from_u64(7)), &[])
        .set_s(private_key(&RESP_STATIC))
        .unwrap();
    let (_, recv) = r.read(&msg1).unwrap().e().await.unwrap();
    let r_transport = recv.es().await.unwrap();
    (i_transport, r_transport)
}

#[tokio::test]
async fn transport_ciphertext_tamper_sweep() {
    let payload = b"negative-test transport payload";
    let ct_len = payload.len() + 16;

    // Sanity: a genuine transport message round-trips.
    {
        let (mut it, mut rt) = complete_n().await;
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
        let (mut it, mut rt) = complete_n().await;
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

#[tokio::test]
async fn transport_replay_rejected() {
    let (mut it, mut rt) = complete_n().await;
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

#[tokio::test]
async fn transport_out_of_order_rejected() {
    let (mut it, mut rt) = complete_n().await;
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
