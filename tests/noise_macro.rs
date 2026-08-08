//! Acceptance tests for the `noise!` macro.
//!
//! Two patterns cover the code-generation space:
//!
//! * `IKpsk1` — pre-message, in-band static, PSK-lookup closure, two
//!   messages;
//! * `XX` — no pre-messages, three messages, a bare single-`e` first
//!   message (no tag), statics revealed in both directions.
//!
//! This file used to also drive IKpsk1 against the `SyncHandshake` driver
//! in both directions, as a bridge between the two implementations. The
//! driver is gone, so the bridge has nothing to compare against and those
//! two tests went with it. Cross-implementation agreement is now covered
//! where it belongs — against `snow`, in `snow_interop*.rs`, and against
//! the frozen vectors in `noise_kat.rs`.

use hiss::noise::{Blake2b, ChaChaPoly, HandshakeError, Transport, X25519};
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
