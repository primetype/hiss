//! Acceptance tests for the `noise!` macro.
//!
//! Two patterns cover the code-generation space:
//!
//! * `IKpsk1` — pre-message, in-band static, PSK-lookup closure, two
//!   messages;
//! * `XX` — no pre-messages, three messages, a bare single-`e` first
//!   message (no tag), statics revealed in both directions.
//!
//! Besides macro↔macro round trips, the IKpsk1 handshake is driven
//! against the existing `SyncHandshake` driver in both directions: the
//! wire bytes must interoperate and both ends must derive the same
//! session id (the transcript hash — equality proves byte-identical
//! handshakes).

mod common;

use common::PeerStream;
use hiss::noise::{
    Blake2b, ChaChaPoly, HandshakeError, Initiator, Noise, Responder, SyncHandshake, Transport,
    X25519, pattern,
};
use hiss::provider::{EphemeralOnly, ProviderExt};
use hiss::psk::Psk;
use rand::SeedableRng;
use rand::rngs::StdRng;

hiss::noise! {
    /// `IKpsk1` over X25519 / ChaChaPoly / BLAKE2b.
    pub IKpsk1<X25519, ChaChaPoly, Blake2b> {
        <- s
        ...
        -> e, es, s, ss, psk
        <- e, ee, se
    }
}

hiss::noise! {
    /// `XX` over X25519 / ChaChaPoly / BLAKE2b.
    pub XX<X25519, ChaChaPoly, Blake2b> {
        -> e
        <- e, ee, s, es
        -> s, se
    }
}

/// The classic type-state protocol the interop tests drive against.
type Classic = Noise<pattern::IKpsk1, X25519, ChaChaPoly, Blake2b>;

const PROLOGUE: &[u8] = b"hiss noise! acceptance";

fn provider(seed: u64) -> EphemeralOnly<StdRng> {
    EphemeralOnly::new(StdRng::seed_from_u64(seed))
}

#[test]
fn message_sizes_are_exact() {
    // X25519 public key = 32, ChaChaPoly tag = 16.
    // IKpsk1 msg1: e(32) + s(32+16, keyed) + tag(16) = 96.
    assert_eq!(IKpsk1::MSG1_SIZE, 96);
    // IKpsk1 msg2: e(32) + tag(16) = 48.
    assert_eq!(IKpsk1::MSG2_SIZE, 48);
    // XX msg1: bare e(32), cipher never keyed => no tag.
    assert_eq!(XX::MSG1_SIZE, 32);
    // XX msg2: e(32) + s(32+16, keyed after ee) + tag(16) = 96.
    assert_eq!(XX::MSG2_SIZE, 96);
    // XX msg3: s(32+16) + tag(16) = 64.
    assert_eq!(XX::MSG3_SIZE, 64);
}

#[test]
fn ikpsk1_macro_round_trip() {
    let mut ip = provider(1);
    let i_static = ip.generate::<X25519>().unwrap();
    let i_pub = ip.public(&i_static).unwrap();
    let mut rp = provider(2);
    let r_static = rp.generate::<X25519>().unwrap();
    let r_pub = rp.public(&r_static).unwrap();
    let psk = Psk::from_bytes([0xAA; 32]);

    // Initiator: one call for msg1 = -> e, es, s, ss, psk. The remote
    // static is observable from the first state — it came from the
    // pre-message argument.
    let hs = IKpsk1::initiator(ip, PROLOGUE, r_pub);
    assert_eq!(hs.remote_static().as_ref(), r_pub.as_ref());
    let (msg1, i_hs) = hs.write_message_1(i_static, &psk).unwrap();

    // Responder: one call reads msg1. This deployment selects the PSK
    // per peer, so the `_with` variant receives the identity the message
    // reveals — that ordering is IKpsk1's point.
    let hs = IKpsk1::responder(rp, PROLOGUE, r_static).unwrap();
    let hs = hs
        .read_message_1_with(&msg1, |identity| {
            assert_eq!(identity.as_ref(), i_pub.as_ref());
            Ok(psk.clone())
        })
        .unwrap();
    // The revealed identity is observable on the state (and later on the
    // Transport) rather than returned from the call.
    assert_eq!(hs.remote_static().as_ref(), i_pub.as_ref());
    let (msg2, mut r_t) = hs.write_message_2().unwrap();

    // Initiator: one call reads msg2 = <- e, ee, se and completes. The
    // pre-message remote static survives onto the Transport.
    let mut i_t = i_hs.read_message_2(&msg2).unwrap();
    assert_eq!(i_t.remote_static().unwrap().as_ref(), r_pub.as_ref());
    assert_eq!(r_t.remote_static().unwrap().as_ref(), i_pub.as_ref());

    assert_eq!(i_t.session_id(), r_t.session_id());

    // Transport round trip in both directions.
    let quote = b"the serpent sheds its io";
    let mut sealed = vec![0u8; quote.len() + Transport::<IKpsk1>::OVERHEAD];
    let n = i_t.send(quote, &mut sealed).unwrap();
    let mut opened = vec![0u8; n];
    let m = r_t.receive(&sealed[..n], &mut opened).unwrap();
    assert_eq!(&opened[..m], quote);

    let reply = b"and keeps the type state";
    let mut sealed = vec![0u8; reply.len() + Transport::<IKpsk1>::OVERHEAD];
    let n = r_t.send(reply, &mut sealed).unwrap();
    let mut opened = vec![0u8; n];
    let m = i_t.receive(&sealed[..n], &mut opened).unwrap();
    assert_eq!(&opened[..m], reply);
}

#[test]
fn ikpsk1_unknown_peer_is_rejected_by_the_psk_lookup() {
    let mut ip = provider(7);
    let i_static = ip.generate::<X25519>().unwrap();
    let mut rp = provider(8);
    let r_static = rp.generate::<X25519>().unwrap();
    let r_pub = rp.public(&r_static).unwrap();
    let psk = Psk::from_bytes([0xAA; 32]);

    let (msg1, _i_hs) = IKpsk1::initiator(ip, PROLOGUE, r_pub)
        .write_message_1(i_static, &psk)
        .unwrap();

    let hs = IKpsk1::responder(rp, PROLOGUE, r_static).unwrap();
    let outcome = hs.read_message_1_with(&msg1, |_unknown| {
        Err(HandshakeError::PeerRejected {
            reason: "no PSK enrolled".into(),
        })
    });
    assert!(matches!(outcome, Err(HandshakeError::PeerRejected { .. })));
}

#[test]
fn ikpsk1_macro_initiator_interops_with_classic_responder() {
    let mut ip = provider(11);
    let i_static = ip.generate::<X25519>().unwrap();
    let i_pub = ip.public(&i_static).unwrap();
    let mut rp = provider(22);
    let r_static = rp.generate::<X25519>().unwrap();
    let r_pub = rp.public(&r_static).unwrap();
    let psk = Psk::from_bytes([0x55; 32]);

    // Macro initiator produces msg1 as a fixed array.
    let (msg1, i_hs) = IKpsk1::initiator(ip, PROLOGUE, r_pub)
        .write_message_1(i_static, &psk)
        .unwrap();

    // Classic io-driver responder consumes it off an in-memory stream.
    let stream = PeerStream::new();
    stream.feed(&msg1);
    let r_hs =
        SyncHandshake::<Classic, Responder, _, _, _, _>::respond(rp, PROLOGUE, stream.clone())
            .set_s(r_static)
            .unwrap();
    let (_re, recv) = r_hs.recv().e().unwrap();
    let recv = recv.es().unwrap();
    let (revealed_i, recv) = recv.s().unwrap();
    assert_eq!(revealed_i.as_ref(), i_pub.as_ref());
    let recv = recv.ss().unwrap();
    let r_hs = recv.psk(&psk).unwrap();
    let mut r_t = r_hs.e().unwrap().ee().unwrap().se().unwrap();
    assert_eq!(stream.remaining(), 0, "classic responder must drain msg1");

    // The classic responder's msg2 bytes drive the macro initiator home.
    let msg2_bytes = stream.take_written();
    assert_eq!(msg2_bytes.len(), IKpsk1::MSG2_SIZE);
    let msg2: &[u8; IKpsk1::MSG2_SIZE] = msg2_bytes.as_slice().try_into().unwrap();
    let mut i_t = i_hs.read_message_2(msg2).unwrap();

    assert_eq!(i_t.session_id(), r_t.transport().session_id());

    // Ciphertexts cross the implementation boundary.
    let word = b"interop";
    let mut sealed = vec![0u8; word.len() + Transport::<IKpsk1>::OVERHEAD];
    let n = i_t.send(word, &mut sealed).unwrap();
    let mut opened = vec![0u8; n];
    let m = r_t.transport().receive(&sealed[..n], &mut opened).unwrap();
    assert_eq!(&opened[..m], word);
}

#[test]
fn ikpsk1_classic_initiator_interops_with_macro_responder() {
    let mut ip = provider(33);
    let i_static = ip.generate::<X25519>().unwrap();
    let mut rp = provider(44);
    let r_static = rp.generate::<X25519>().unwrap();
    let r_pub = rp.public(&r_static).unwrap();
    let psk = Psk::from_bytes([0x66; 32]);

    // Classic io-driver initiator writes msg1 into the stream.
    let stream = PeerStream::new();
    let i_hs =
        SyncHandshake::<Classic, Initiator, _, _, _, _>::initiate(ip, PROLOGUE, stream.clone())
            .set_rs(r_pub);
    let i_hs = i_hs
        .e()
        .unwrap()
        .es()
        .unwrap()
        .s(i_static)
        .unwrap()
        .ss()
        .unwrap()
        .psk(&psk)
        .unwrap();

    let msg1_bytes = stream.take_written();
    assert_eq!(msg1_bytes.len(), IKpsk1::MSG1_SIZE);
    let msg1: &[u8; IKpsk1::MSG1_SIZE] = msg1_bytes.as_slice().try_into().unwrap();

    // Macro responder consumes the fixed array and answers with msg2 —
    // this deployment knows the PSK in advance, so it is a plain
    // argument, no lookup.
    let hs = IKpsk1::responder(rp, PROLOGUE, r_static).unwrap();
    let hs = hs.read_message_1(msg1, &psk).unwrap();
    let (msg2, mut r_t) = hs.write_message_2().unwrap();

    // Feed msg2 to the classic initiator.
    stream.feed(&msg2);
    let (_re, recv) = i_hs.recv().e().unwrap();
    let mut i_t = recv.ee().unwrap().se().unwrap();
    assert_eq!(stream.remaining(), 0, "classic initiator must drain msg2");

    assert_eq!(i_t.transport().session_id(), r_t.session_id());

    let word = b"poretni";
    let mut sealed = vec![0u8; word.len() + Transport::<IKpsk1>::OVERHEAD];
    let n = r_t.send(word, &mut sealed).unwrap();
    let mut opened = vec![0u8; n];
    let m = i_t.transport().receive(&sealed[..n], &mut opened).unwrap();
    assert_eq!(&opened[..m], word);
}

#[test]
fn xx_macro_round_trip() {
    let mut ip = provider(5);
    let i_static = ip.generate::<X25519>().unwrap();
    let i_pub = ip.public(&i_static).unwrap();
    let mut rp = provider(6);
    let r_static = rp.generate::<X25519>().unwrap();
    let r_pub = rp.public(&r_static).unwrap();

    // msg1: -> e (bare ephemeral, no tag). No pre-messages: the
    // constructors take only provider + prologue.
    let (msg1, i_hs) = XX::initiator(ip, &[]).write_message_1().unwrap();

    // Responder: read msg1, send msg2 = <- e, ee, s, es.
    let r_hs = XX::responder(rp, &[]).read_message_1(&msg1).unwrap();

    // Mid-handshake, both sides can already observe the ephemeral msg1
    // carried — no Option: the accessors exist only on states where the
    // state machine guarantees the key is set.
    assert_eq!(
        i_hs.local_ephemeral().as_ref(),
        r_hs.remote_ephemeral().as_ref(),
    );

    let (msg2, r_hs) = r_hs.write_message_2(r_static).unwrap();

    // Initiator: read msg2 — the responder's static becomes observable
    // on the next state, where it can be verified — then send msg3.
    let i_hs = i_hs.read_message_2(&msg2).unwrap();
    assert_eq!(i_hs.remote_static().as_ref(), r_pub.as_ref());
    let (msg3, mut i_t) = i_hs.write_message_3(i_static).unwrap();

    // Responder: read msg3 — the final message, so the initiator's
    // revealed static lands on the Transport.
    let mut r_t = r_hs.read_message_3(&msg3).unwrap();
    assert_eq!(r_t.remote_static().unwrap().as_ref(), i_pub.as_ref());

    assert_eq!(i_t.session_id(), r_t.session_id());
    assert_eq!(
        i_t.remote_ephemeral().unwrap().as_ref(),
        r_t.local_ephemeral().unwrap().as_ref(),
    );

    let quote = b"three flights, no io";
    let mut sealed = vec![0u8; quote.len() + Transport::<XX>::OVERHEAD];
    let n = i_t.send(quote, &mut sealed).unwrap();
    let mut opened = vec![0u8; n];
    let m = r_t.receive(&sealed[..n], &mut opened).unwrap();
    assert_eq!(&opened[..m], quote);
}
