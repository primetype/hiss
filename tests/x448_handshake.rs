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

use hiss::noise::{Blake2b, ChaChaPoly, X448};
use hiss::provider::{EphemeralOnly, ProviderExt};
use rand::{SeedableRng, rngs::StdRng};

// The bare pattern markers are curve-agnostic; spell the X448 suite out.
//
// The declared identifier *is* the Noise pattern name: it becomes
// `Pattern::NAME`, which goes into the protocol name mixed into the initial
// handshake hash. So this must be `XX` — a descriptive alias like `Xx448`
// would silently produce `Noise_Xx448_448_ChaChaPoly_BLAKE2b` and interop
// with nothing.
hiss::noise! { pub XX<X448, ChaChaPoly, Blake2b> { -> e <- e, ee, s, es -> s, se } }

#[test]
fn xx_round_trip_hiss_to_hiss_over_x448() {
    let mut provider = EphemeralOnly::new(StdRng::from_os_rng());
    let initiator_static = provider.generate::<X448>().unwrap();
    let initiator_pub = provider.public(&initiator_static).unwrap();
    let responder_static = provider.generate::<X448>().unwrap();
    let responder_pub = provider.public(&responder_static).unwrap();

    // XX has no pre-messages, so both constructors are infallible and take
    // nothing but a provider and the prologue.
    let i_hs = XX::initiator(EphemeralOnly::new(StdRng::from_os_rng()), &[]);
    let r_hs = XX::responder(EphemeralOnly::new(StdRng::from_os_rng()), &[]);

    // msg1: -> e (bare ephemeral, cipher never keyed)
    let (msg1, i_hs) = i_hs.write_message_1().unwrap();
    let r_hs = r_hs.read_message_1(&msg1).unwrap();

    // msg2: <- e, ee, s, es (responder's static is sent encrypted, after ee)
    let (msg2, r_hs) = r_hs.write_message_2(responder_static).unwrap();

    // Initiator reads msg2; the `s` reveals the responder static.
    let i_hs = i_hs.read_message_2(&msg2).unwrap();
    assert_eq!(i_hs.remote_static().as_bytes(), responder_pub.as_bytes());

    // msg3: -> s, se (initiator's static is sent encrypted, after ee) —
    // the final message, so writing it yields the transport.
    let (msg3, mut i_transport) = i_hs.write_message_3(initiator_static).unwrap();

    // Responder reads msg3; the `s` reveals the initiator static.
    let mut r_transport = r_hs.read_message_3(&msg3).unwrap();
    assert_eq!(
        r_transport.remote_static().unwrap().as_bytes(),
        initiator_pub.as_bytes(),
    );

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
