//! Interoperability tests between our Noise implementation and `snow`.
//!
//! These tests verify that our type-level Noise framework produces
//! byte-compatible handshakes with `snow` — the most widely used
//! Rust Noise library. Both sides use P-256, ChaCha20-Poly1305,
//! and BLAKE2b.
//!
//! Each test runs one side with our implementation and the other
//! with snow, then verifies:
//! 1. The handshake completes successfully
//! 2. Both sides derive the same handshake hash
//! 3. Transport messages can be exchanged bidirectionally

use hiss::provider::ProviderExt;
use hiss::provider::EphemeralOnly;
use rand::{SeedableRng, rngs::StdRng};
use hiss::noise::*;
use hiss::psk::Psk;

const PROTOCOL: &str = "Noise_IKpsk1_P256_ChaChaPoly_BLAKE2b";

// ── IKpsk1: our initiator ↔ snow responder ──────────────────────

#[tokio::test]
async fn ikpsk1_hiss_initiator_snow_responder() {
    let mut provider = EphemeralOnly::new(StdRng::from_os_rng());

    // Generate keys for both sides.
    let initiator_static = provider.generate::<P256>().unwrap();
    let _initiator_pub = provider.public(&initiator_static).unwrap();

    let psk = Psk::from_bytes([0xAA; 32]);

    // ── Snow responder setup ─────────────────────────────────
    let snow_responder_builder = snow::Builder::new(PROTOCOL.parse().unwrap());
    let snow_responder_keypair = snow_responder_builder.generate_keypair().unwrap();
    let responder_pub_bytes = &snow_responder_keypair.public;

    // Parse snow's public key into our format.
    let responder_pub = P256::public_key_from_bytes(responder_pub_bytes).unwrap();

    let mut snow_responder = snow_responder_builder
        .local_private_key(&snow_responder_keypair.private)
        .unwrap()
        .psk(1, psk.as_bytes())
        .unwrap()
        .build_responder()
        .unwrap();

    // ── Our initiator setup ──────────────────────────────────
    type Channel = IKpsk1;

    let i_hs = Channel::initiate(EphemeralOnly::new(StdRng::from_os_rng()), &[]).set_rs(responder_pub);

    // ── Message 1: -> e, es, s, ss, psk (our initiator sends) ──
    let mut msg1_buf = [0u8; 162];
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
        .unwrap()
        .psk(&psk)
        .await
        .unwrap();

    let msg1 = msg1.to_vec();

    // Snow responder reads msg1.
    let mut buf = [0u8; 256];
    let _len = snow_responder.read_message(&msg1, &mut buf).unwrap();

    // ── Message 2: <- e, ee, se (snow responder sends) ──────
    let mut msg2 = [0u8; 256];
    let msg2_len = snow_responder.write_message(&[], &mut msg2).unwrap();

    // Our initiator reads msg2.
    let (_, recv) = i_hs.read(&msg2[..msg2_len]).unwrap().e().await.unwrap();
    let i_transport = recv.ee().await.unwrap().se().await.unwrap();

    // Verify handshake hashes match (must check before transport mode).
    assert_eq!(
        i_transport.session_id().as_ref(),
        snow_responder.get_handshake_hash(),
    );

    let mut snow_responder = snow_responder.into_transport_mode().unwrap();

    // ── Transport: bidirectional message exchange ─────────────
    let mut i_transport = i_transport;

    // Our initiator → snow responder.
    let plaintext = b"hello from hiss initiator";
    let mut ct = [0u8; 256];
    let ct_len = i_transport.send(plaintext, &mut ct).unwrap();

    let mut pt = [0u8; 256];
    let pt_len = snow_responder.read_message(&ct[..ct_len], &mut pt).unwrap();
    assert_eq!(&pt[..pt_len], plaintext);

    // Snow responder → our initiator.
    let reply = b"hello from snow responder";
    let mut ct = [0u8; 256];
    let ct_len = snow_responder.write_message(reply, &mut ct).unwrap();

    let mut pt = [0u8; 256];
    let pt_len = i_transport.receive(&ct[..ct_len], &mut pt).unwrap();
    assert_eq!(&pt[..pt_len], reply);
}

// ── IKpsk1: snow initiator ↔ our responder ──────────────────────

#[tokio::test]
async fn ikpsk1_snow_initiator_hiss_responder() {
    let mut provider = EphemeralOnly::new(StdRng::from_os_rng());

    // Generate keys for our responder.
    let responder_static = provider.generate::<P256>().unwrap();
    let responder_pub = provider.public(&responder_static).unwrap();

    let psk = Psk::from_bytes([0xBB; 32]);

    // ── Snow initiator setup ─────────────────────────────────
    let snow_initiator_builder = snow::Builder::new(PROTOCOL.parse().unwrap());
    let snow_initiator_keypair = snow_initiator_builder.generate_keypair().unwrap();

    let mut snow_initiator = snow_initiator_builder
        .local_private_key(&snow_initiator_keypair.private)
        .unwrap()
        .remote_public_key(responder_pub.to_bytes())
        .unwrap()
        .psk(1, psk.as_bytes())
        .unwrap()
        .build_initiator()
        .unwrap();

    // ── Our responder setup ──────────────────────────────────
    type Channel = IKpsk1;

    let r_hs = Channel::respond(EphemeralOnly::new(StdRng::from_os_rng()), &[])
        .set_s(responder_static)
        .unwrap();

    // ── Message 1: -> e, es, s, ss, psk (snow initiator sends) ──
    let mut msg1 = [0u8; 256];
    let msg1_len = snow_initiator.write_message(&[], &mut msg1).unwrap();

    // Our responder reads msg1.
    let (_, recv) = r_hs.read(&msg1[..msg1_len]).unwrap().e().await.unwrap();
    let recv = recv.es().await.unwrap();
    let (revealed_initiator_pub, recv) = recv.s().await.unwrap();
    let recv = recv.ss().await.unwrap();
    let r_hs = recv.psk(&psk).await.unwrap();

    // Verify revealed initiator public key matches snow's.
    assert_eq!(
        revealed_initiator_pub.to_bytes(),
        snow_initiator_keypair.public.as_slice(),
    );

    // ── Message 2: <- e, ee, se (our responder sends) ───────
    let mut msg2_buf = [0u8; 81];
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

    // Snow initiator reads msg2.
    let mut buf = [0u8; 256];
    let _len = snow_initiator.read_message(&msg2, &mut buf).unwrap();

    // ── Verify: both sides are now in transport mode ─────────
    assert_eq!(
        r_transport.session_id().as_ref(),
        snow_initiator.get_handshake_hash(),
    );

    let mut snow_initiator = snow_initiator.into_transport_mode().unwrap();

    // ── Transport: bidirectional message exchange ─────────────
    let mut r_transport = r_transport;

    // Snow initiator → our responder.
    let plaintext = b"hello from snow initiator";
    let mut ct = [0u8; 256];
    let ct_len = snow_initiator.write_message(plaintext, &mut ct).unwrap();

    let mut pt = [0u8; 256];
    let pt_len = r_transport.receive(&ct[..ct_len], &mut pt).unwrap();
    assert_eq!(&pt[..pt_len], plaintext);

    // Our responder → snow initiator.
    let reply = b"hello from hiss responder";
    let mut ct = [0u8; 256];
    let ct_len = r_transport.send(reply, &mut ct).unwrap();

    let mut pt = [0u8; 256];
    let pt_len = snow_initiator.read_message(&ct[..ct_len], &mut pt).unwrap();
    assert_eq!(&pt[..pt_len], reply);
}

// ── N pattern: our initiator ↔ snow responder ───────────────────

#[tokio::test]
async fn n_hiss_initiator_snow_responder() {
    let psk_to_seal = Psk::from_bytes([0x42; 32]);

    // Snow generates the responder's static key.
    let snow_builder = snow::Builder::new("Noise_N_P256_ChaChaPoly_BLAKE2b".parse().unwrap());
    let snow_keypair = snow_builder.generate_keypair().unwrap();

    let responder_pub = P256::public_key_from_bytes(&snow_keypair.public).unwrap();

    let mut snow_responder = snow::Builder::new("Noise_N_P256_ChaChaPoly_BLAKE2b".parse().unwrap())
        .local_private_key(&snow_keypair.private)
        .unwrap()
        .build_responder()
        .unwrap();

    // ── Our initiator seals ──────────────────────────────────
    type NoiseSeal = N;

    let sealer = NoiseSeal::initiate(EphemeralOnly::new(StdRng::from_os_rng()), &[]).set_rs(responder_pub);

    let mut msg_buf = [0u8; 81];
    let (msg, mut transport) = sealer.e(&mut msg_buf).await.unwrap().es().await.unwrap();

    let msg = msg.to_vec();
    assert_eq!(msg.len(), 81); // 65 (ephemeral) + 16 (payload tag)

    let mut sealed = [0u8; 64]; // 32 + 16 tag
    let sealed_len = transport.send(psk_to_seal.as_bytes(), &mut sealed).unwrap();

    // ── Snow responder opens ─────────────────────────────────
    let mut buf = [0u8; 256];
    let _len = snow_responder.read_message(&msg, &mut buf).unwrap();

    let mut snow_responder = snow_responder.into_transport_mode().unwrap();

    let mut opened = [0u8; 256];
    let opened_len = snow_responder
        .read_message(&sealed[..sealed_len], &mut opened)
        .unwrap();

    assert_eq!(opened_len, 32);
    assert_eq!(&opened[..opened_len], psk_to_seal.as_bytes());
}

// ── Kpsk0 pattern: our initiator ↔ snow responder ───────────────

#[tokio::test]
async fn kpsk0_hiss_initiator_snow_responder() {
    let mut provider = EphemeralOnly::new(StdRng::from_os_rng());

    let alice_static = provider.generate::<P256>().unwrap();
    let alice_pub = provider.public(&alice_static).unwrap();

    let psk = Psk::from_bytes([0x55; 32]);
    let payload: [u8; 32] = [0x42; 32];

    // Snow generates Bob's keys.
    let snow_builder = snow::Builder::new("Noise_Kpsk0_P256_ChaChaPoly_BLAKE2b".parse().unwrap());
    let bob_keypair = snow_builder.generate_keypair().unwrap();
    let bob_pub = P256::public_key_from_bytes(&bob_keypair.public).unwrap();

    let mut snow_responder =
        snow::Builder::new("Noise_Kpsk0_P256_ChaChaPoly_BLAKE2b".parse().unwrap())
            .local_private_key(&bob_keypair.private)
            .unwrap()
            .remote_public_key(alice_pub.to_bytes())
            .unwrap()
            .psk(0, psk.as_bytes())
            .unwrap()
            .build_responder()
            .unwrap();

    // ── Our initiator seals ──────────────────────────────────
    type NoiseKpsk0 = Kpsk0;

    let sealer = NoiseKpsk0::initiate(EphemeralOnly::new(StdRng::from_os_rng()), &[])
        .set_s(alice_static)
        .unwrap()
        .set_rs(bob_pub);

    let mut msg_buf = [0u8; 81];
    let (msg, mut transport) = sealer
        .psk(&mut msg_buf, &psk)
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

    let msg = msg.to_vec();
    assert_eq!(msg.len(), 81); // 65 (ephemeral) + 16 (payload tag)

    let mut sealed = [0u8; 64];
    let sealed_len = transport.send(&payload, &mut sealed).unwrap();

    // ── Snow responder opens ─────────────────────────────────
    let mut buf = [0u8; 256];
    let _len = snow_responder.read_message(&msg, &mut buf).unwrap();

    let mut snow_responder = snow_responder.into_transport_mode().unwrap();

    let mut opened = [0u8; 256];
    let opened_len = snow_responder
        .read_message(&sealed[..sealed_len], &mut opened)
        .unwrap();

    assert_eq!(opened_len, 32);
    assert_eq!(&opened[..opened_len], &payload);
}

// ── N pattern with prologue: our initiator ↔ snow responder ──────

#[tokio::test]
async fn n_with_prologue_hiss_initiator_snow_responder() {
    let prologue = b"hiss/v1";

    let snow_builder = snow::Builder::new("Noise_N_P256_ChaChaPoly_BLAKE2b".parse().unwrap());
    let snow_keypair = snow_builder.generate_keypair().unwrap();

    let responder_pub = P256::public_key_from_bytes(&snow_keypair.public).unwrap();

    let mut snow_responder = snow::Builder::new("Noise_N_P256_ChaChaPoly_BLAKE2b".parse().unwrap())
        .local_private_key(&snow_keypair.private)
        .unwrap()
        .prologue(prologue)
        .unwrap()
        .build_responder()
        .unwrap();

    // ── Our initiator seals with prologue ───────────────────────
    type NoiseSeal = N;

    let sealer = NoiseSeal::initiate(EphemeralOnly::new(StdRng::from_os_rng()), prologue).set_rs(responder_pub);

    let mut msg_buf = [0u8; 81];
    let (msg, mut transport) = sealer.e(&mut msg_buf).await.unwrap().es().await.unwrap();
    let msg = msg.to_vec();

    let payload = b"sealed with prologue";
    let mut sealed = [0u8; 64];
    let sealed_len = transport.send(payload, &mut sealed).unwrap();

    // ── Snow responder opens ─────────────────────────────────
    let mut buf = [0u8; 256];
    let _len = snow_responder.read_message(&msg, &mut buf).unwrap();

    let mut snow_responder = snow_responder.into_transport_mode().unwrap();

    let mut opened = [0u8; 256];
    let opened_len = snow_responder
        .read_message(&sealed[..sealed_len], &mut opened)
        .unwrap();

    assert_eq!(&opened[..opened_len], payload);
}

// ── IKpsk1 with prologue: both directions ────────────────────────

#[tokio::test]
async fn ikpsk1_with_prologue_hiss_initiator_snow_responder() {
    let mut provider = EphemeralOnly::new(StdRng::from_os_rng());
    let prologue = b"hiss/v1/ikpsk1";

    let initiator_static = provider.generate::<P256>().unwrap();
    let psk = Psk::from_bytes([0xCC; 32]);

    let snow_responder_builder = snow::Builder::new(PROTOCOL.parse().unwrap());
    let snow_responder_keypair = snow_responder_builder.generate_keypair().unwrap();
    let responder_pub = P256::public_key_from_bytes(&snow_responder_keypair.public).unwrap();

    let mut snow_responder = snow_responder_builder
        .local_private_key(&snow_responder_keypair.private)
        .unwrap()
        .psk(1, psk.as_bytes())
        .unwrap()
        .prologue(prologue)
        .unwrap()
        .build_responder()
        .unwrap();

    type Channel = IKpsk1;

    let i_hs = Channel::initiate(EphemeralOnly::new(StdRng::from_os_rng()), prologue).set_rs(responder_pub);

    // msg1: -> e, es, s, ss, psk
    let mut msg1_buf = [0u8; 162];
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
        .unwrap()
        .psk(&psk)
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

    // Handshake hashes must match.
    assert_eq!(
        i_transport.session_id().as_ref(),
        snow_responder.get_handshake_hash(),
    );

    let mut snow_responder = snow_responder.into_transport_mode().unwrap();
    let mut i_transport = i_transport;

    // Transport round-trip.
    let plaintext = b"prologue interop test";
    let mut ct = [0u8; 256];
    let ct_len = i_transport.send(plaintext, &mut ct).unwrap();
    let mut pt = [0u8; 256];
    let pt_len = snow_responder.read_message(&ct[..ct_len], &mut pt).unwrap();
    assert_eq!(&pt[..pt_len], plaintext);
}

// ── Rekey interop: hiss ↔ snow ─────────────────────────────────

#[tokio::test]
async fn n_rekey_hiss_initiator_snow_responder() {
    let snow_builder = snow::Builder::new("Noise_N_P256_ChaChaPoly_BLAKE2b".parse().unwrap());
    let snow_keypair = snow_builder.generate_keypair().unwrap();

    let responder_pub = P256::public_key_from_bytes(&snow_keypair.public).unwrap();

    let mut snow_responder = snow::Builder::new("Noise_N_P256_ChaChaPoly_BLAKE2b".parse().unwrap())
        .local_private_key(&snow_keypair.private)
        .unwrap()
        .build_responder()
        .unwrap();

    type NoiseSeal = N;

    let sealer = NoiseSeal::initiate(EphemeralOnly::new(StdRng::from_os_rng()), &[]).set_rs(responder_pub);

    let mut msg_buf = [0u8; 81];
    let (msg, mut transport) = sealer.e(&mut msg_buf).await.unwrap().es().await.unwrap();
    let msg = msg.to_vec();

    let mut buf = [0u8; 256];
    snow_responder.read_message(&msg, &mut buf).unwrap();

    let mut snow_responder = snow_responder.into_transport_mode().unwrap();

    // Send a message before rekey.
    let mut ct = [0u8; 256];
    let mut pt = [0u8; 256];
    let ct_len = transport.send(b"before rekey", &mut ct).unwrap();
    let pt_len = snow_responder.read_message(&ct[..ct_len], &mut pt).unwrap();
    assert_eq!(&pt[..pt_len], b"before rekey");

    // Rekey both sides — hiss rekeys send, snow rekeys incoming.
    transport.rekey().unwrap();
    snow_responder.rekey_incoming();

    // Messages after rekey must still be compatible.
    let ct_len = transport.send(b"after rekey", &mut ct).unwrap();
    let pt_len = snow_responder.read_message(&ct[..ct_len], &mut pt).unwrap();
    assert_eq!(&pt[..pt_len], b"after rekey");
}

#[tokio::test]
async fn ikpsk1_rekey_hiss_initiator_snow_responder() {
    let mut provider = EphemeralOnly::new(StdRng::from_os_rng());

    let initiator_static = provider.generate::<P256>().unwrap();
    let psk = Psk::from_bytes([0xDD; 32]);

    let snow_responder_builder = snow::Builder::new(PROTOCOL.parse().unwrap());
    let snow_responder_keypair = snow_responder_builder.generate_keypair().unwrap();
    let responder_pub = P256::public_key_from_bytes(&snow_responder_keypair.public).unwrap();

    let mut snow_responder = snow_responder_builder
        .local_private_key(&snow_responder_keypair.private)
        .unwrap()
        .psk(1, psk.as_bytes())
        .unwrap()
        .build_responder()
        .unwrap();

    type Channel = IKpsk1;

    let i_hs = Channel::initiate(EphemeralOnly::new(StdRng::from_os_rng()), &[]).set_rs(responder_pub);

    // Complete handshake.
    // msg1: -> e, es, s, ss, psk
    let mut msg1_buf = [0u8; 162];
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
        .unwrap()
        .psk(&psk)
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

    let mut snow_responder = snow_responder.into_transport_mode().unwrap();
    let mut i_transport = i_transport;

    // Bidirectional messages before rekey.
    let mut ct = [0u8; 256];
    let mut pt = [0u8; 256];

    let ct_len = i_transport.send(b"pre-rekey i->r", &mut ct).unwrap();
    let pt_len = snow_responder.read_message(&ct[..ct_len], &mut pt).unwrap();
    assert_eq!(&pt[..pt_len], b"pre-rekey i->r");

    let ct_len = snow_responder
        .write_message(b"pre-rekey r->i", &mut ct)
        .unwrap();
    let pt_len = i_transport.receive(&ct[..ct_len], &mut pt).unwrap();
    assert_eq!(&pt[..pt_len], b"pre-rekey r->i");

    // Rekey both sides in both directions.
    i_transport.rekey().unwrap();
    snow_responder.rekey_outgoing();
    snow_responder.rekey_incoming();

    // Bidirectional messages after rekey.
    let ct_len = i_transport.send(b"post-rekey i->r", &mut ct).unwrap();
    let pt_len = snow_responder.read_message(&ct[..ct_len], &mut pt).unwrap();
    assert_eq!(&pt[..pt_len], b"post-rekey i->r");

    let ct_len = snow_responder
        .write_message(b"post-rekey r->i", &mut ct)
        .unwrap();
    let pt_len = i_transport.receive(&ct[..ct_len], &mut pt).unwrap();
    assert_eq!(&pt[..pt_len], b"post-rekey r->i");
}

// ── IK: our initiator ↔ snow responder ──────────────────────────

#[tokio::test]
async fn ik_hiss_initiator_snow_responder() {
    let mut provider = EphemeralOnly::new(StdRng::from_os_rng());
    let initiator_static = provider.generate::<P256>().unwrap();

    let proto = "Noise_IK_P256_ChaChaPoly_BLAKE2b";

    // ── Snow responder setup ─────────────────────────────────
    let snow_responder_builder = snow::Builder::new(proto.parse().unwrap());
    let snow_responder_keypair = snow_responder_builder.generate_keypair().unwrap();
    let responder_pub = P256::public_key_from_bytes(&snow_responder_keypair.public).unwrap();

    let mut snow_responder = snow_responder_builder
        .local_private_key(&snow_responder_keypair.private)
        .unwrap()
        .build_responder()
        .unwrap();

    // ── Our initiator setup ──────────────────────────────────
    type Channel = IK;

    let i_hs =
        Channel::initiate(EphemeralOnly::new(StdRng::from_os_rng()), &[]).set_rs(responder_pub);

    // msg1: -> e, es, s, ss (our initiator sends)
    let mut msg1_buf = [0u8; 162];
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

    // msg2: <- e, ee, se (snow responder sends)
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
    let plaintext = b"hello from hiss IK initiator";
    let mut ct = [0u8; 256];
    let ct_len = i_transport.send(plaintext, &mut ct).unwrap();
    let mut pt = [0u8; 256];
    let pt_len = snow_responder.read_message(&ct[..ct_len], &mut pt).unwrap();
    assert_eq!(&pt[..pt_len], plaintext);

    let reply = b"hello from snow IK responder";
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
    let responder_static = provider.generate::<P256>().unwrap();
    let responder_pub = provider.public(&responder_static).unwrap();

    let proto = "Noise_IK_P256_ChaChaPoly_BLAKE2b";

    // ── Snow initiator setup ─────────────────────────────────
    let snow_initiator_builder = snow::Builder::new(proto.parse().unwrap());
    let snow_initiator_keypair = snow_initiator_builder.generate_keypair().unwrap();

    let mut snow_initiator = snow_initiator_builder
        .local_private_key(&snow_initiator_keypair.private)
        .unwrap()
        .remote_public_key(responder_pub.to_bytes())
        .unwrap()
        .build_initiator()
        .unwrap();

    // ── Our responder setup ──────────────────────────────────
    type Channel = IK;

    let r_hs = Channel::respond(EphemeralOnly::new(StdRng::from_os_rng()), &[])
        .set_s(responder_static)
        .unwrap();

    // msg1: -> e, es, s, ss (snow initiator sends)
    let mut msg1 = [0u8; 256];
    let msg1_len = snow_initiator.write_message(&[], &mut msg1).unwrap();

    // Our responder reads msg1.
    let (_, recv) = r_hs.read(&msg1[..msg1_len]).unwrap().e().await.unwrap();
    let recv = recv.es().await.unwrap();
    let (revealed_initiator_pub, recv) = recv.s().await.unwrap();
    let r_hs = recv.ss().await.unwrap();

    // The revealed initiator static must match snow's.
    assert_eq!(
        revealed_initiator_pub.to_bytes(),
        snow_initiator_keypair.public.as_slice(),
    );

    // msg2: <- e, ee, se (our responder sends)
    let mut msg2_buf = [0u8; 81];
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

    // Transport: bidirectional exchange.
    let plaintext = b"hello from snow IK initiator";
    let mut ct = [0u8; 256];
    let ct_len = snow_initiator.write_message(plaintext, &mut ct).unwrap();
    let mut pt = [0u8; 256];
    let pt_len = r_transport.receive(&ct[..ct_len], &mut pt).unwrap();
    assert_eq!(&pt[..pt_len], plaintext);

    let reply = b"hello from hiss IK responder";
    let mut ct = [0u8; 256];
    let ct_len = r_transport.send(reply, &mut ct).unwrap();
    let mut pt = [0u8; 256];
    let pt_len = snow_initiator.read_message(&ct[..ct_len], &mut pt).unwrap();
    assert_eq!(&pt[..pt_len], reply);
}

// ── K pattern: our initiator ↔ snow responder ───────────────────

#[tokio::test]
async fn k_hiss_initiator_snow_responder() {
    let mut provider = EphemeralOnly::new(StdRng::from_os_rng());

    let alice_static = provider.generate::<P256>().unwrap();
    let alice_pub = provider.public(&alice_static).unwrap();

    let payload: [u8; 32] = [0x42; 32];

    // Snow generates Bob's keys.
    let snow_builder = snow::Builder::new("Noise_K_P256_ChaChaPoly_BLAKE2b".parse().unwrap());
    let bob_keypair = snow_builder.generate_keypair().unwrap();
    let bob_pub = P256::public_key_from_bytes(&bob_keypair.public).unwrap();

    let mut snow_responder = snow::Builder::new("Noise_K_P256_ChaChaPoly_BLAKE2b".parse().unwrap())
        .local_private_key(&bob_keypair.private)
        .unwrap()
        .remote_public_key(alice_pub.to_bytes())
        .unwrap()
        .build_responder()
        .unwrap();

    // ── Our initiator seals ──────────────────────────────────
    type NoiseK = K;

    let sealer = NoiseK::initiate(EphemeralOnly::new(StdRng::from_os_rng()), &[])
        .set_s(alice_static)
        .unwrap()
        .set_rs(bob_pub);

    let mut msg_buf = [0u8; 81];
    let (msg, mut transport) = sealer
        .e(&mut msg_buf)
        .await
        .unwrap()
        .es()
        .await
        .unwrap()
        .ss()
        .await
        .unwrap();

    let msg = msg.to_vec();
    assert_eq!(msg.len(), 81); // 65 (ephemeral) + 16 (payload tag)

    let mut sealed = [0u8; 64];
    let sealed_len = transport.send(&payload, &mut sealed).unwrap();

    // ── Snow responder opens ─────────────────────────────────
    let mut buf = [0u8; 256];
    let _len = snow_responder.read_message(&msg, &mut buf).unwrap();

    let mut snow_responder = snow_responder.into_transport_mode().unwrap();

    let mut opened = [0u8; 256];
    let opened_len = snow_responder
        .read_message(&sealed[..sealed_len], &mut opened)
        .unwrap();

    assert_eq!(opened_len, 32);
    assert_eq!(&opened[..opened_len], &payload);
}
