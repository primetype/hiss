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

// The bare `noise::{N, IK, XX}` aliases are pinned to P-256; spell the
// X25519 suites out explicitly here.
type N25519 = Noise<pattern::N, X25519, ChaChaPoly, Blake2b>;
type IK25519 = Noise<pattern::IK, X25519, ChaChaPoly, Blake2b>;
type XX25519 = Noise<pattern::XX, X25519, ChaChaPoly, Blake2b>;

// ── N: our initiator ↔ snow responder ───────────────────────────

#[tokio::test]
async fn n_hiss_initiator_snow_responder() {
    let proto = "Noise_N_25519_ChaChaPoly_BLAKE2b";

    let snow_builder = snow::Builder::new(proto.parse().unwrap());
    let snow_keypair = snow_builder.generate_keypair().unwrap();
    let responder_pub = X25519::public_key_from_bytes(&snow_keypair.public).unwrap();

    let mut snow_responder = snow::Builder::new(proto.parse().unwrap())
        .local_private_key(&snow_keypair.private)
        .unwrap()
        .build_responder()
        .unwrap();

    let sealer =
        N25519::initiate(EphemeralOnly::new(StdRng::from_os_rng()), &[]).set_rs(responder_pub);

    // msg1: -> e, es (one-way seal, then transport mode)
    let mut msg_buf = [0u8; 256];
    let (msg, mut transport) = sealer.e(&mut msg_buf).await.unwrap().es().await.unwrap();
    let msg = msg.to_vec();

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

#[tokio::test]
async fn ik_hiss_initiator_snow_responder() {
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

    let i_hs =
        IK25519::initiate(EphemeralOnly::new(StdRng::from_os_rng()), &[]).set_rs(responder_pub);

    // msg1: -> e, es, s, ss
    let mut msg1_buf = [0u8; 256];
    let (msg1, i_hs) = i_hs
        .e(&mut msg1_buf)
        .await
        .unwrap()
        .es()
        .await
        .unwrap()
        .s(initiator_static)
        .await
        .unwrap()
        .ss()
        .await
        .unwrap();
    let msg1 = msg1.to_vec();

    let mut buf = [0u8; 256];
    snow_responder.read_message(&msg1, &mut buf).unwrap();

    // msg2: <- e, ee, se
    let mut msg2 = [0u8; 256];
    let msg2_len = snow_responder.write_message(&[], &mut msg2).unwrap();
    let (_, recv) = i_hs.read(&msg2[..msg2_len]).unwrap().e().await.unwrap();
    let i_transport = recv.ee().await.unwrap().se().await.unwrap();

    assert_eq!(
        i_transport.session_id().as_ref(),
        snow_responder.get_handshake_hash(),
    );

    let mut snow_responder = snow_responder.into_transport_mode().unwrap();
    let mut i_transport = i_transport;

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

#[tokio::test]
async fn ik_snow_initiator_hiss_responder() {
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

    let r_hs = IK25519::respond(EphemeralOnly::new(StdRng::from_os_rng()), &[])
        .set_s(responder_static)
        .unwrap();

    // msg1: -> e, es, s, ss (snow initiator sends)
    let mut msg1 = [0u8; 256];
    let msg1_len = snow_initiator.write_message(&[], &mut msg1).unwrap();

    let (_, recv) = r_hs.read(&msg1[..msg1_len]).unwrap().e().await.unwrap();
    let recv = recv.es().await.unwrap();
    let (revealed_initiator_pub, recv) = recv.s().await.unwrap();
    let r_hs = recv.ss().await.unwrap();

    assert_eq!(
        revealed_initiator_pub.as_ref(),
        snow_initiator_keypair.public.as_slice(),
    );

    // msg2: <- e, ee, se (our responder sends)
    let mut msg2_buf = [0u8; 256];
    let (msg2, r_transport) = r_hs
        .e(&mut msg2_buf)
        .await
        .unwrap()
        .ee()
        .await
        .unwrap()
        .se()
        .await
        .unwrap();
    let msg2 = msg2.to_vec();

    let mut buf = [0u8; 256];
    snow_initiator.read_message(&msg2, &mut buf).unwrap();

    assert_eq!(
        r_transport.session_id().as_ref(),
        snow_initiator.get_handshake_hash(),
    );

    let mut snow_initiator = snow_initiator.into_transport_mode().unwrap();
    let mut r_transport = r_transport;

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

#[tokio::test]
async fn xx_hiss_initiator_snow_responder() {
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

    let i_hs = XX25519::initiate(EphemeralOnly::new(StdRng::from_os_rng()), &[]);

    // msg1: -> e (bare ephemeral, cipher never keyed)
    let mut msg1_buf = [0u8; 256];
    let (msg1, i_hs) = i_hs.e(&mut msg1_buf).await.unwrap();
    let msg1 = msg1.to_vec();

    let mut buf = [0u8; 256];
    snow_responder.read_message(&msg1, &mut buf).unwrap();

    // msg2: <- e, ee, s, es (snow responder's static is encrypted)
    let mut msg2 = [0u8; 256];
    let msg2_len = snow_responder.write_message(&[], &mut msg2).unwrap();
    let (_, recv) = i_hs.read(&msg2[..msg2_len]).unwrap().e().await.unwrap();
    let recv = recv.ee().await.unwrap();
    let (revealed_responder_pub, recv) = recv.s().await.unwrap();
    assert_eq!(
        revealed_responder_pub.as_bytes(),
        responder_static_pub.as_bytes(),
    );
    let i_hs = recv.es().await.unwrap();

    // msg3: -> s, se (our initiator's static is encrypted)
    let mut msg3_buf = [0u8; 256];
    let (msg3, i_transport) = i_hs
        .s(&mut msg3_buf, initiator_static)
        .await
        .unwrap()
        .se()
        .await
        .unwrap();
    let msg3 = msg3.to_vec();

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
    let mut i_transport = i_transport;

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

#[tokio::test]
async fn xx_snow_initiator_hiss_responder() {
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

    let r_hs = XX25519::respond(EphemeralOnly::new(StdRng::from_os_rng()), &[]);

    // msg1: -> e (snow initiator sends)
    let mut msg1 = [0u8; 256];
    let msg1_len = snow_initiator.write_message(&[], &mut msg1).unwrap();
    let (_, recv) = r_hs.read(&msg1[..msg1_len]).unwrap().e().await.unwrap();

    // msg2: <- e, ee, s, es (our responder's static is encrypted)
    let mut msg2_buf = [0u8; 256];
    let (msg2, r_hs) = recv
        .e(&mut msg2_buf)
        .await
        .unwrap()
        .ee()
        .await
        .unwrap()
        .s(responder_static)
        .await
        .unwrap()
        .es()
        .await
        .unwrap();
    let msg2 = msg2.to_vec();

    let mut buf = [0u8; 256];
    snow_initiator.read_message(&msg2, &mut buf).unwrap();

    assert_eq!(
        snow_initiator.get_remote_static().unwrap(),
        responder_pub.as_ref(),
    );

    // msg3: -> s, se (snow initiator's static is encrypted)
    let mut msg3 = [0u8; 256];
    let msg3_len = snow_initiator.write_message(&[], &mut msg3).unwrap();
    let (revealed_initiator_pub, recv) = r_hs.read(&msg3[..msg3_len]).unwrap().s().await.unwrap();
    let r_transport = recv.se().await.unwrap();

    assert_eq!(
        revealed_initiator_pub.as_ref(),
        snow_initiator_keypair.public.as_slice(),
    );
    assert_eq!(
        r_transport.session_id().as_ref(),
        snow_initiator.get_handshake_hash(),
    );

    let mut snow_initiator = snow_initiator.into_transport_mode().unwrap();
    let mut r_transport = r_transport;

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
