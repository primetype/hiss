//! Interoperability tests between our Noise implementation and `snow`,
//! over the **X25519** (`25519`) DH function.
//!
//! The mirror of `snow_interop.rs` (which exercises P-256): both sides use
//! X25519, ChaCha20-Poly1305, and BLAKE2b, so every handshake here is
//! `Noise_*_25519_ChaChaPoly_BLAKE2b`. snow supports `25519` natively and
//! `cryptoxide` clamps identically, so the handshakes are byte-for-byte
//! compatible.
//!
//! Coverage: the `es` token (N), pre-message static + `ee`/`se` (IK both
//! directions), and the full three-message mutual-auth flow with both
//! statics transmitted encrypted (XX both directions). Each test confirms
//! the handshake completes, the handshake hashes match, and transport
//! messages decrypt across implementations.

use hiss::noise::*;
use hiss::provider::EphemeralOnly;
use hiss::provider::ProviderExt;
use rand::{SeedableRng, rngs::StdRng};

// The declared identifier is the Noise pattern name — it reaches the
// protocol name mixed into the initial handshake hash — so these are `N`,
// `IK`, `XX` and not `N25519`-style aliases. The suite is spelled out in the
// type parameters instead, which is where the `25519` in the protocol name
// comes from.
hiss::noise! { pub N<X25519, ChaChaPoly, Blake2b>  { <- s ... -> e, es } }
hiss::noise! { pub IK<X25519, ChaChaPoly, Blake2b> { <- s ... -> e, es, s, ss <- e, ee, se } }
hiss::noise! { pub XX<X25519, ChaChaPoly, Blake2b> { -> e <- e, ee, s, es -> s, se } }

/// snow reports a length into a scratch buffer; the generated readers take a
/// fixed-size array. Narrowing here pins the wire size.
fn exact<const M: usize>(buf: &[u8]) -> &[u8; M] {
    buf.try_into()
        .expect("snow's message length matches the generated wire size")
}

// ── N: our initiator ↔ snow responder ───────────────────────────

#[test]
fn n_hiss_initiator_snow_responder() {
    let proto = "Noise_N_25519_ChaChaPoly_BLAKE2b";

    let snow_builder = snow::Builder::new(proto.parse().unwrap());
    let snow_keypair = snow_builder.generate_keypair().unwrap();
    let responder_pub = X25519::public_key_from_bytes(&snow_keypair.public).unwrap();

    let mut snow_responder = snow::Builder::new(proto.parse().unwrap())
        .local_private_key(&snow_keypair.private)
        .unwrap()
        .build_responder()
        .unwrap();

    // msg1: -> e, es (one-way seal, then transport mode)
    let (msg, mut transport) = N::initiator(
        EphemeralOnly::new(StdRng::from_os_rng()),
        &[],
        responder_pub,
    )
    .write_message_1()
    .unwrap();

    let payload = b"x25519 N interop";
    let mut sealed = [0u8; 256];
    let sealed_len = transport.send(payload, &mut sealed).unwrap();

    // Snow responder reads the handshake, then opens the sealed payload.
    let mut buf = [0u8; 256];
    snow_responder.read_message(&msg, &mut buf).unwrap();
    let mut snow_responder = snow_responder.into_transport_mode().unwrap();

    let mut opened = [0u8; 256];
    let opened_len = snow_responder
        .read_message(&sealed[..sealed_len], &mut opened)
        .unwrap();
    assert_eq!(&opened[..opened_len], payload);
}

// ── IK: our initiator ↔ snow responder ──────────────────────────

#[test]
fn ik_hiss_initiator_snow_responder() {
    let mut provider = EphemeralOnly::new(StdRng::from_os_rng());
    let initiator_static = provider.generate::<X25519>().unwrap();

    let proto = "Noise_IK_25519_ChaChaPoly_BLAKE2b";

    let snow_responder_builder = snow::Builder::new(proto.parse().unwrap());
    let snow_responder_keypair = snow_responder_builder.generate_keypair().unwrap();
    let responder_pub = X25519::public_key_from_bytes(&snow_responder_keypair.public).unwrap();

    let mut snow_responder = snow_responder_builder
        .local_private_key(&snow_responder_keypair.private)
        .unwrap()
        .build_responder()
        .unwrap();

    // msg1: -> e, es, s, ss
    let (msg1, i_hs) = IK::initiator(
        EphemeralOnly::new(StdRng::from_os_rng()),
        &[],
        responder_pub,
    )
    .write_message_1(initiator_static)
    .unwrap();

    let mut buf = [0u8; 256];
    snow_responder.read_message(&msg1, &mut buf).unwrap();

    // msg2: <- e, ee, se
    let mut msg2 = [0u8; 256];
    let msg2_len = snow_responder.write_message(&[], &mut msg2).unwrap();
    let mut i_transport = i_hs.read_message_2(exact(&msg2[..msg2_len])).unwrap();

    assert_eq!(
        i_transport.session_id().as_ref(),
        snow_responder.get_handshake_hash(),
    );

    let mut snow_responder = snow_responder.into_transport_mode().unwrap();

    // Transport: bidirectional exchange.
    let plaintext = b"hello from hiss IK 25519 initiator";
    let mut ct = [0u8; 256];
    let ct_len = i_transport.send(plaintext, &mut ct).unwrap();
    let mut pt = [0u8; 256];
    let pt_len = snow_responder.read_message(&ct[..ct_len], &mut pt).unwrap();
    assert_eq!(&pt[..pt_len], plaintext);

    let reply = b"hello from snow IK 25519 responder";
    let mut ct = [0u8; 256];
    let ct_len = snow_responder.write_message(reply, &mut ct).unwrap();
    let mut pt = [0u8; 256];
    let pt_len = i_transport.receive(&ct[..ct_len], &mut pt).unwrap();
    assert_eq!(&pt[..pt_len], reply);
}

// ── IK: snow initiator ↔ our responder ──────────────────────────

#[test]
fn ik_snow_initiator_hiss_responder() {
    let mut provider = EphemeralOnly::new(StdRng::from_os_rng());
    let responder_static = provider.generate::<X25519>().unwrap();
    let responder_pub = provider.public(&responder_static).unwrap();

    let proto = "Noise_IK_25519_ChaChaPoly_BLAKE2b";

    let snow_initiator_builder = snow::Builder::new(proto.parse().unwrap());
    let snow_initiator_keypair = snow_initiator_builder.generate_keypair().unwrap();

    let mut snow_initiator = snow_initiator_builder
        .local_private_key(&snow_initiator_keypair.private)
        .unwrap()
        .remote_public_key(responder_pub.as_ref())
        .unwrap()
        .build_initiator()
        .unwrap();

    // msg1: -> e, es, s, ss (snow initiator sends)
    let mut msg1 = [0u8; 256];
    let msg1_len = snow_initiator.write_message(&[], &mut msg1).unwrap();

    let r_hs = IK::responder(
        EphemeralOnly::new(StdRng::from_os_rng()),
        &[],
        responder_static,
    )
    .unwrap()
    .read_message_1(exact(&msg1[..msg1_len]))
    .unwrap();

    assert_eq!(
        r_hs.remote_static().as_ref(),
        snow_initiator_keypair.public.as_slice(),
    );

    // msg2: <- e, ee, se (our responder sends)
    let (msg2, mut r_transport) = r_hs.write_message_2().unwrap();

    let mut buf = [0u8; 256];
    snow_initiator.read_message(&msg2, &mut buf).unwrap();

    assert_eq!(
        r_transport.session_id().as_ref(),
        snow_initiator.get_handshake_hash(),
    );

    let mut snow_initiator = snow_initiator.into_transport_mode().unwrap();

    let plaintext = b"hello from snow IK 25519 initiator";
    let mut ct = [0u8; 256];
    let ct_len = snow_initiator.write_message(plaintext, &mut ct).unwrap();
    let mut pt = [0u8; 256];
    let pt_len = r_transport.receive(&ct[..ct_len], &mut pt).unwrap();
    assert_eq!(&pt[..pt_len], plaintext);

    let reply = b"hello from hiss IK 25519 responder";
    let mut ct = [0u8; 256];
    let ct_len = r_transport.send(reply, &mut ct).unwrap();
    let mut pt = [0u8; 256];
    let pt_len = snow_initiator.read_message(&ct[..ct_len], &mut pt).unwrap();
    assert_eq!(&pt[..pt_len], reply);
}

// ── XX: our initiator ↔ snow responder ──────────────────────────

#[test]
fn xx_hiss_initiator_snow_responder() {
    let mut provider = EphemeralOnly::new(StdRng::from_os_rng());
    let initiator_static = provider.generate::<X25519>().unwrap();
    let initiator_pub = provider.public(&initiator_static).unwrap();

    let proto = "Noise_XX_25519_ChaChaPoly_BLAKE2b";

    let snow_responder_builder = snow::Builder::new(proto.parse().unwrap());
    let snow_responder_keypair = snow_responder_builder.generate_keypair().unwrap();
    let responder_static_pub =
        X25519::public_key_from_bytes(&snow_responder_keypair.public).unwrap();

    let mut snow_responder = snow_responder_builder
        .local_private_key(&snow_responder_keypair.private)
        .unwrap()
        .build_responder()
        .unwrap();

    // msg1: -> e (bare ephemeral, cipher never keyed)
    let (msg1, i_hs) = XX::initiator(EphemeralOnly::new(StdRng::from_os_rng()), &[])
        .write_message_1()
        .unwrap();

    let mut buf = [0u8; 256];
    snow_responder.read_message(&msg1, &mut buf).unwrap();

    // msg2: <- e, ee, s, es (snow responder's static is encrypted)
    let mut msg2 = [0u8; 256];
    let msg2_len = snow_responder.write_message(&[], &mut msg2).unwrap();
    let i_hs = i_hs.read_message_2(exact(&msg2[..msg2_len])).unwrap();
    assert_eq!(
        i_hs.remote_static().as_bytes(),
        responder_static_pub.as_bytes(),
    );

    // msg3: -> s, se (our initiator's static is encrypted)
    let (msg3, mut i_transport) = i_hs.write_message_3(initiator_static).unwrap();

    let mut buf = [0u8; 256];
    snow_responder.read_message(&msg3, &mut buf).unwrap();

    assert_eq!(
        snow_responder.get_remote_static().unwrap(),
        initiator_pub.as_ref(),
    );
    assert_eq!(
        i_transport.session_id().as_ref(),
        snow_responder.get_handshake_hash(),
    );

    let mut snow_responder = snow_responder.into_transport_mode().unwrap();

    let plaintext = b"hello from hiss XX 25519 initiator";
    let mut ct = [0u8; 256];
    let ct_len = i_transport.send(plaintext, &mut ct).unwrap();
    let mut pt = [0u8; 256];
    let pt_len = snow_responder.read_message(&ct[..ct_len], &mut pt).unwrap();
    assert_eq!(&pt[..pt_len], plaintext);

    let reply = b"hello from snow XX 25519 responder";
    let mut ct = [0u8; 256];
    let ct_len = snow_responder.write_message(reply, &mut ct).unwrap();
    let mut pt = [0u8; 256];
    let pt_len = i_transport.receive(&ct[..ct_len], &mut pt).unwrap();
    assert_eq!(&pt[..pt_len], reply);
}

// ── XX: snow initiator ↔ our responder ──────────────────────────

#[test]
fn xx_snow_initiator_hiss_responder() {
    let mut provider = EphemeralOnly::new(StdRng::from_os_rng());
    let responder_static = provider.generate::<X25519>().unwrap();
    let responder_pub = provider.public(&responder_static).unwrap();

    let proto = "Noise_XX_25519_ChaChaPoly_BLAKE2b";

    let snow_initiator_builder = snow::Builder::new(proto.parse().unwrap());
    let snow_initiator_keypair = snow_initiator_builder.generate_keypair().unwrap();

    let mut snow_initiator = snow_initiator_builder
        .local_private_key(&snow_initiator_keypair.private)
        .unwrap()
        .build_initiator()
        .unwrap();

    // msg1: -> e (snow initiator sends)
    let mut msg1 = [0u8; 256];
    let msg1_len = snow_initiator.write_message(&[], &mut msg1).unwrap();
    let r_hs = XX::responder(EphemeralOnly::new(StdRng::from_os_rng()), &[])
        .read_message_1(exact(&msg1[..msg1_len]))
        .unwrap();

    // msg2: <- e, ee, s, es (our responder's static is encrypted)
    let (msg2, r_hs) = r_hs.write_message_2(responder_static).unwrap();

    let mut buf = [0u8; 256];
    snow_initiator.read_message(&msg2, &mut buf).unwrap();

    assert_eq!(
        snow_initiator.get_remote_static().unwrap(),
        responder_pub.as_ref(),
    );

    // msg3: -> s, se (snow initiator's static is encrypted)
    let mut msg3 = [0u8; 256];
    let msg3_len = snow_initiator.write_message(&[], &mut msg3).unwrap();
    let mut r_transport = r_hs.read_message_3(exact(&msg3[..msg3_len])).unwrap();

    assert_eq!(
        r_transport.remote_static().unwrap().as_ref(),
        snow_initiator_keypair.public.as_slice(),
    );
    assert_eq!(
        r_transport.session_id().as_ref(),
        snow_initiator.get_handshake_hash(),
    );

    let mut snow_initiator = snow_initiator.into_transport_mode().unwrap();

    let plaintext = b"hello from snow XX 25519 initiator";
    let mut ct = [0u8; 256];
    let ct_len = snow_initiator.write_message(plaintext, &mut ct).unwrap();
    let mut pt = [0u8; 256];
    let pt_len = r_transport.receive(&ct[..ct_len], &mut pt).unwrap();
    assert_eq!(&pt[..pt_len], plaintext);

    let reply = b"hello from hiss XX 25519 responder";
    let mut ct = [0u8; 256];
    let ct_len = r_transport.send(reply, &mut ct).unwrap();
    let mut pt = [0u8; 256];
    let pt_len = snow_initiator.read_message(&ct[..ct_len], &mut pt).unwrap();
    assert_eq!(&pt[..pt_len], reply);
}
