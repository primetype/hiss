//! End-to-end Noise handshake over **X448** (the `448` DH function),
//! hiss ↔ hiss.
//!
//! `snow`'s default resolver has no `448`, so — unlike X25519
//! ([`snow_interop_25519`]) — there is no cross-implementation interop to run
//! here. Instead this drives a full **XX** handshake between two hiss parties
//! over X448 and confirms the things interop would: both statics are revealed
//! correctly, the parties agree on the handshake hash (session id), and
//! transport messages round-trip in both directions. The X448 DH primitive
//! itself is pinned against the authoritative RFC 7748 known-answer vectors in
//! `curve::x448`'s unit tests.

mod common;
use common::PeerStream;

use hiss::noise::*;
use hiss::provider::{EphemeralOnly, ProviderExt};
use rand::{SeedableRng, rngs::StdRng};

// The bare pattern markers are curve-agnostic; spell the X448 suite out.
type Xx448 = Noise<pattern::XX, X448, ChaChaPoly, Blake2b>;

#[test]
fn xx_round_trip_hiss_to_hiss_over_x448() {
    let mut provider = EphemeralOnly::new(StdRng::from_os_rng());
    let initiator_static = provider.generate::<X448>().unwrap();
    let initiator_pub = provider.public(&initiator_static).unwrap();
    let responder_static = provider.generate::<X448>().unwrap();
    let responder_pub = provider.public(&responder_static).unwrap();

    let i_stream = PeerStream::new();
    let r_stream = PeerStream::new();

    let i_hs = SyncHandshake::<Xx448, Initiator, _, _, _, _>::initiate(
        EphemeralOnly::new(StdRng::from_os_rng()),
        &[],
        i_stream.clone(),
    );
    let r_hs = SyncHandshake::<Xx448, Responder, _, _, _, _>::respond(
        EphemeralOnly::new(StdRng::from_os_rng()),
        &[],
        r_stream.clone(),
    );

    // msg1: -> e (bare ephemeral, cipher never keyed)
    let i_hs = i_hs.e().unwrap();
    let msg1 = i_stream.take_written();
    r_stream.feed(&msg1);
    let (_, recv) = r_hs.recv().e().unwrap();

    // msg2: <- e, ee, s, es (responder's static is sent encrypted, after ee)
    let r_hs = recv
        .e()
        .unwrap()
        .ee()
        .unwrap()
        .s(responder_static)
        .unwrap()
        .es()
        .unwrap();
    let msg2 = r_stream.take_written();
    i_stream.feed(&msg2);

    // Initiator reads msg2; the `s` reveals the responder static.
    let (_, recv) = i_hs.recv().e().unwrap();
    let recv = recv.ee().unwrap();
    let (revealed_responder, recv) = recv.s().unwrap();
    assert_eq!(revealed_responder.as_bytes(), responder_pub.as_bytes());
    let i_hs = recv.es().unwrap();

    // msg3: -> s, se (initiator's static is sent encrypted, after ee)
    let i_chain = i_hs.s(initiator_static).unwrap().se().unwrap();
    let (mut i_transport, _) = i_chain.into_parts();
    let msg3 = i_stream.take_written();
    r_stream.feed(&msg3);

    // Responder reads msg3; the `s` reveals the initiator static.
    let (revealed_initiator, recv) = r_hs.recv().s().unwrap();
    assert_eq!(revealed_initiator.as_bytes(), initiator_pub.as_bytes());
    let r_chain = recv.se().unwrap();
    let (mut r_transport, _) = r_chain.into_parts();

    // Both sides derived the same handshake hash.
    assert_eq!(
        i_transport.session_id().as_ref(),
        r_transport.session_id().as_ref(),
    );

    // Transport messages round-trip in both directions.
    let mut ct = [0u8; 256];
    let mut pt = [0u8; 256];

    let to_responder = b"x448 round trip: initiator -> responder";
    let n = i_transport.send(to_responder, &mut ct).unwrap();
    let m = r_transport.receive(&ct[..n], &mut pt).unwrap();
    assert_eq!(&pt[..m], to_responder);

    let to_initiator = b"x448 round trip: responder -> initiator";
    let n = r_transport.send(to_initiator, &mut ct).unwrap();
    let m = i_transport.receive(&ct[..n], &mut pt).unwrap();
    assert_eq!(&pt[..m], to_initiator);
}
