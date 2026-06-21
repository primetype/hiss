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

mod common;

use common::PeerStream;
use hiss::noise::*;
use hiss::provider::EphemeralOnly;
use hiss::provider::ProviderExt;
use hiss::psk::Psk;
use rand::{SeedableRng, rngs::StdRng};

const PROTOCOL: &str = "Noise_IKpsk1_P256_ChaChaPoly_BLAKE2b";

// ── IKpsk1: our initiator ↔ snow responder ──────────────────────

#[test]
fn ikpsk1_hiss_initiator_snow_responder() {
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
    type Channel = Noise<pattern::IKpsk1, P256, ChaChaPoly, Blake2b>;

    let stream = PeerStream::new();
    let i_hs = SyncHandshake::<Channel, Initiator, _, _, _, _>::initiate(
        EphemeralOnly::new(StdRng::from_os_rng()),
        &[],
        stream.clone(),
    )
    .set_rs(responder_pub);

    // ── Message 1: -> e, es, s, ss, psk (our initiator sends) ──
    let i_hs = i_hs
        .e()
        .unwrap()
        .es()
        .unwrap()
        .s(initiator_static)
        .unwrap()
        .ss()
        .unwrap()
        .psk(&psk)
        .unwrap();

    let msg1 = stream.take_written();

    // Snow responder reads msg1.
    let mut buf = [0u8; 256];
    let _len = snow_responder.read_message(&msg1, &mut buf).unwrap();

    // ── Message 2: <- e, ee, se (snow responder sends) ──────
    let mut msg2 = [0u8; 256];
    let msg2_len = snow_responder.write_message(&[], &mut msg2).unwrap();
    stream.feed(&msg2[..msg2_len]);

    // Our initiator reads msg2.
    let (_, recv) = i_hs.recv().e().unwrap();
    let (mut i_transport, _) = recv.ee().unwrap().se().unwrap().into_parts();

    // Verify handshake hashes match (must check before transport mode).
    assert_eq!(
        i_transport.session_id().as_ref(),
        snow_responder.get_handshake_hash(),
    );

    let mut snow_responder = snow_responder.into_transport_mode().unwrap();

    // ── Transport: bidirectional message exchange ─────────────

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

#[test]
fn ikpsk1_snow_initiator_hiss_responder() {
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
    type Channel = Noise<pattern::IKpsk1, P256, ChaChaPoly, Blake2b>;

    let stream = PeerStream::new();
    let r_hs = SyncHandshake::<Channel, Responder, _, _, _, _>::respond(
        EphemeralOnly::new(StdRng::from_os_rng()),
        &[],
        stream.clone(),
    )
    .set_s(responder_static)
    .unwrap();

    // ── Message 1: -> e, es, s, ss, psk (snow initiator sends) ──
    let mut msg1 = [0u8; 256];
    let msg1_len = snow_initiator.write_message(&[], &mut msg1).unwrap();
    stream.feed(&msg1[..msg1_len]);

    // Our responder reads msg1.
    let (_, recv) = r_hs.recv().e().unwrap();
    let recv = recv.es().unwrap();
    let (revealed_initiator_pub, recv) = recv.s().unwrap();
    let recv = recv.ss().unwrap();
    let r_hs = recv.psk(&psk).unwrap();

    // Verify revealed initiator public key matches snow's.
    assert_eq!(
        revealed_initiator_pub.to_bytes(),
        snow_initiator_keypair.public.as_slice(),
    );

    // ── Message 2: <- e, ee, se (our responder sends) ───────
    let (mut r_transport, _) = r_hs.e().unwrap().ee().unwrap().se().unwrap().into_parts();

    let msg2 = stream.take_written();

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

#[test]
fn n_hiss_initiator_snow_responder() {
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
    type NoiseSeal = Noise<pattern::N, P256, ChaChaPoly, Blake2b>;

    let stream = PeerStream::new();
    let sealer = SyncHandshake::<NoiseSeal, Initiator, _, _, _, _>::initiate(
        EphemeralOnly::new(StdRng::from_os_rng()),
        &[],
        stream.clone(),
    )
    .set_rs(responder_pub);

    let (mut transport, _) = sealer.e().unwrap().es().unwrap().into_parts();

    let msg = stream.take_written();
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

#[test]
fn kpsk0_hiss_initiator_snow_responder() {
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
    type NoiseKpsk0 = Noise<pattern::Kpsk0, P256, ChaChaPoly, Blake2b>;

    let stream = PeerStream::new();
    let sealer = SyncHandshake::<NoiseKpsk0, Initiator, _, _, _, _>::initiate(
        EphemeralOnly::new(StdRng::from_os_rng()),
        &[],
        stream.clone(),
    )
    .set_s(alice_static)
    .unwrap()
    .set_rs(bob_pub);

    let (mut transport, _) = sealer
        .psk(&psk)
        .unwrap()
        .e()
        .unwrap()
        .es()
        .unwrap()
        .ss()
        .unwrap()
        .into_parts();

    let msg = stream.take_written();
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

#[test]
fn n_with_prologue_hiss_initiator_snow_responder() {
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
    type NoiseSeal = Noise<pattern::N, P256, ChaChaPoly, Blake2b>;

    let stream = PeerStream::new();
    let sealer = SyncHandshake::<NoiseSeal, Initiator, _, _, _, _>::initiate(
        EphemeralOnly::new(StdRng::from_os_rng()),
        prologue,
        stream.clone(),
    )
    .set_rs(responder_pub);

    let (mut transport, _) = sealer.e().unwrap().es().unwrap().into_parts();
    let msg = stream.take_written();

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

#[test]
fn ikpsk1_with_prologue_hiss_initiator_snow_responder() {
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

    type Channel = Noise<pattern::IKpsk1, P256, ChaChaPoly, Blake2b>;

    let stream = PeerStream::new();
    let i_hs = SyncHandshake::<Channel, Initiator, _, _, _, _>::initiate(
        EphemeralOnly::new(StdRng::from_os_rng()),
        prologue,
        stream.clone(),
    )
    .set_rs(responder_pub);

    // msg1: -> e, es, s, ss, psk
    let i_hs = i_hs
        .e()
        .unwrap()
        .es()
        .unwrap()
        .s(initiator_static)
        .unwrap()
        .ss()
        .unwrap()
        .psk(&psk)
        .unwrap();
    let msg1 = stream.take_written();
    let mut buf = [0u8; 256];
    snow_responder.read_message(&msg1, &mut buf).unwrap();

    // msg2: <- e, ee, se
    let mut msg2 = [0u8; 256];
    let msg2_len = snow_responder.write_message(&[], &mut msg2).unwrap();
    stream.feed(&msg2[..msg2_len]);
    let (_, recv) = i_hs.recv().e().unwrap();
    let (mut i_transport, _) = recv.ee().unwrap().se().unwrap().into_parts();

    // Handshake hashes must match.
    assert_eq!(
        i_transport.session_id().as_ref(),
        snow_responder.get_handshake_hash(),
    );

    let mut snow_responder = snow_responder.into_transport_mode().unwrap();

    // Transport round-trip.
    let plaintext = b"prologue interop test";
    let mut ct = [0u8; 256];
    let ct_len = i_transport.send(plaintext, &mut ct).unwrap();
    let mut pt = [0u8; 256];
    let pt_len = snow_responder.read_message(&ct[..ct_len], &mut pt).unwrap();
    assert_eq!(&pt[..pt_len], plaintext);
}

// ── Rekey interop: hiss ↔ snow ─────────────────────────────────

#[test]
fn n_rekey_hiss_initiator_snow_responder() {
    let snow_builder = snow::Builder::new("Noise_N_P256_ChaChaPoly_BLAKE2b".parse().unwrap());
    let snow_keypair = snow_builder.generate_keypair().unwrap();

    let responder_pub = P256::public_key_from_bytes(&snow_keypair.public).unwrap();

    let mut snow_responder = snow::Builder::new("Noise_N_P256_ChaChaPoly_BLAKE2b".parse().unwrap())
        .local_private_key(&snow_keypair.private)
        .unwrap()
        .build_responder()
        .unwrap();

    type NoiseSeal = Noise<pattern::N, P256, ChaChaPoly, Blake2b>;

    let stream = PeerStream::new();
    let sealer = SyncHandshake::<NoiseSeal, Initiator, _, _, _, _>::initiate(
        EphemeralOnly::new(StdRng::from_os_rng()),
        &[],
        stream.clone(),
    )
    .set_rs(responder_pub);

    let (mut transport, _) = sealer.e().unwrap().es().unwrap().into_parts();
    let msg = stream.take_written();

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

#[test]
fn ikpsk1_rekey_hiss_initiator_snow_responder() {
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

    type Channel = Noise<pattern::IKpsk1, P256, ChaChaPoly, Blake2b>;

    let stream = PeerStream::new();
    let i_hs = SyncHandshake::<Channel, Initiator, _, _, _, _>::initiate(
        EphemeralOnly::new(StdRng::from_os_rng()),
        &[],
        stream.clone(),
    )
    .set_rs(responder_pub);

    // Complete handshake.
    // msg1: -> e, es, s, ss, psk
    let i_hs = i_hs
        .e()
        .unwrap()
        .es()
        .unwrap()
        .s(initiator_static)
        .unwrap()
        .ss()
        .unwrap()
        .psk(&psk)
        .unwrap();
    let msg1 = stream.take_written();
    let mut buf = [0u8; 256];
    snow_responder.read_message(&msg1, &mut buf).unwrap();

    // msg2: <- e, ee, se
    let mut msg2 = [0u8; 256];
    let msg2_len = snow_responder.write_message(&[], &mut msg2).unwrap();
    stream.feed(&msg2[..msg2_len]);
    let (_, recv) = i_hs.recv().e().unwrap();
    let (mut i_transport, _) = recv.ee().unwrap().se().unwrap().into_parts();

    let mut snow_responder = snow_responder.into_transport_mode().unwrap();

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

#[test]
fn ik_hiss_initiator_snow_responder() {
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
    type Channel = Noise<pattern::IK, P256, ChaChaPoly, Blake2b>;

    let stream = PeerStream::new();
    let i_hs = SyncHandshake::<Channel, Initiator, _, _, _, _>::initiate(
        EphemeralOnly::new(StdRng::from_os_rng()),
        &[],
        stream.clone(),
    )
    .set_rs(responder_pub);

    // msg1: -> e, es, s, ss (our initiator sends)
    let i_hs = i_hs
        .e()
        .unwrap()
        .es()
        .unwrap()
        .s(initiator_static)
        .unwrap()
        .ss()
        .unwrap();
    let msg1 = stream.take_written();

    let mut buf = [0u8; 256];
    snow_responder.read_message(&msg1, &mut buf).unwrap();

    // msg2: <- e, ee, se (snow responder sends)
    let mut msg2 = [0u8; 256];
    let msg2_len = snow_responder.write_message(&[], &mut msg2).unwrap();
    stream.feed(&msg2[..msg2_len]);
    let (_, recv) = i_hs.recv().e().unwrap();
    let (mut i_transport, _) = recv.ee().unwrap().se().unwrap().into_parts();

    assert_eq!(
        i_transport.session_id().as_ref(),
        snow_responder.get_handshake_hash(),
    );

    let mut snow_responder = snow_responder.into_transport_mode().unwrap();

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

#[test]
fn ik_snow_initiator_hiss_responder() {
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
    type Channel = Noise<pattern::IK, P256, ChaChaPoly, Blake2b>;

    let stream = PeerStream::new();
    let r_hs = SyncHandshake::<Channel, Responder, _, _, _, _>::respond(
        EphemeralOnly::new(StdRng::from_os_rng()),
        &[],
        stream.clone(),
    )
    .set_s(responder_static)
    .unwrap();

    // msg1: -> e, es, s, ss (snow initiator sends)
    let mut msg1 = [0u8; 256];
    let msg1_len = snow_initiator.write_message(&[], &mut msg1).unwrap();
    stream.feed(&msg1[..msg1_len]);

    // Our responder reads msg1.
    let (_, recv) = r_hs.recv().e().unwrap();
    let recv = recv.es().unwrap();
    let (revealed_initiator_pub, recv) = recv.s().unwrap();
    let r_hs = recv.ss().unwrap();

    // The revealed initiator static must match snow's.
    assert_eq!(
        revealed_initiator_pub.to_bytes(),
        snow_initiator_keypair.public.as_slice(),
    );

    // msg2: <- e, ee, se (our responder sends)
    let (mut r_transport, _) = r_hs.e().unwrap().ee().unwrap().se().unwrap().into_parts();
    let msg2 = stream.take_written();

    let mut buf = [0u8; 256];
    snow_initiator.read_message(&msg2, &mut buf).unwrap();

    assert_eq!(
        r_transport.session_id().as_ref(),
        snow_initiator.get_handshake_hash(),
    );

    let mut snow_initiator = snow_initiator.into_transport_mode().unwrap();

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

#[test]
fn k_hiss_initiator_snow_responder() {
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
    type NoiseK = Noise<pattern::K, P256, ChaChaPoly, Blake2b>;

    let stream = PeerStream::new();
    let sealer = SyncHandshake::<NoiseK, Initiator, _, _, _, _>::initiate(
        EphemeralOnly::new(StdRng::from_os_rng()),
        &[],
        stream.clone(),
    )
    .set_s(alice_static)
    .unwrap()
    .set_rs(bob_pub);

    let (mut transport, _) = sealer.e().unwrap().es().unwrap().ss().unwrap().into_parts();

    let msg = stream.take_written();
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

// ── NK: our initiator ↔ snow responder ──────────────────────────

#[test]
fn nk_hiss_initiator_snow_responder() {
    let proto = "Noise_NK_P256_ChaChaPoly_BLAKE2b";

    // ── Snow responder setup ─────────────────────────────────
    let snow_responder_builder = snow::Builder::new(proto.parse().unwrap());
    let snow_responder_keypair = snow_responder_builder.generate_keypair().unwrap();
    let responder_pub = P256::public_key_from_bytes(&snow_responder_keypair.public).unwrap();

    let mut snow_responder = snow_responder_builder
        .local_private_key(&snow_responder_keypair.private)
        .unwrap()
        .build_responder()
        .unwrap();

    // ── Our initiator setup (anonymous: no static) ───────────
    type Channel = Noise<pattern::NK, P256, ChaChaPoly, Blake2b>;

    let stream = PeerStream::new();
    let i_hs = SyncHandshake::<Channel, Initiator, _, _, _, _>::initiate(
        EphemeralOnly::new(StdRng::from_os_rng()),
        &[],
        stream.clone(),
    )
    .set_rs(responder_pub);

    // msg1: -> e, es (our initiator sends)
    let i_hs = i_hs.e().unwrap().es().unwrap();
    let msg1 = stream.take_written();

    let mut buf = [0u8; 256];
    snow_responder.read_message(&msg1, &mut buf).unwrap();

    // msg2: <- e, ee (snow responder sends)
    let mut msg2 = [0u8; 256];
    let msg2_len = snow_responder.write_message(&[], &mut msg2).unwrap();
    stream.feed(&msg2[..msg2_len]);
    let (_, recv) = i_hs.recv().e().unwrap();
    let (mut i_transport, _) = recv.ee().unwrap().into_parts();

    assert_eq!(
        i_transport.session_id().as_ref(),
        snow_responder.get_handshake_hash(),
    );

    let mut snow_responder = snow_responder.into_transport_mode().unwrap();

    // Transport: bidirectional exchange.
    let plaintext = b"hello from hiss NK initiator";
    let mut ct = [0u8; 256];
    let ct_len = i_transport.send(plaintext, &mut ct).unwrap();
    let mut pt = [0u8; 256];
    let pt_len = snow_responder.read_message(&ct[..ct_len], &mut pt).unwrap();
    assert_eq!(&pt[..pt_len], plaintext);

    let reply = b"hello from snow NK responder";
    let mut ct = [0u8; 256];
    let ct_len = snow_responder.write_message(reply, &mut ct).unwrap();
    let mut pt = [0u8; 256];
    let pt_len = i_transport.receive(&ct[..ct_len], &mut pt).unwrap();
    assert_eq!(&pt[..pt_len], reply);
}

// ── NK: snow initiator ↔ our responder ──────────────────────────

#[test]
fn nk_snow_initiator_hiss_responder() {
    let mut provider = EphemeralOnly::new(StdRng::from_os_rng());
    let responder_static = provider.generate::<P256>().unwrap();
    let responder_pub = provider.public(&responder_static).unwrap();

    let proto = "Noise_NK_P256_ChaChaPoly_BLAKE2b";

    // ── Snow initiator setup (anonymous: only knows responder pub) ──
    let snow_initiator_builder = snow::Builder::new(proto.parse().unwrap());

    let mut snow_initiator = snow_initiator_builder
        .remote_public_key(responder_pub.to_bytes())
        .unwrap()
        .build_initiator()
        .unwrap();

    // ── Our responder setup ──────────────────────────────────
    type Channel = Noise<pattern::NK, P256, ChaChaPoly, Blake2b>;

    let stream = PeerStream::new();
    let r_hs = SyncHandshake::<Channel, Responder, _, _, _, _>::respond(
        EphemeralOnly::new(StdRng::from_os_rng()),
        &[],
        stream.clone(),
    )
    .set_s(responder_static)
    .unwrap();

    // msg1: -> e, es (snow initiator sends)
    let mut msg1 = [0u8; 256];
    let msg1_len = snow_initiator.write_message(&[], &mut msg1).unwrap();
    stream.feed(&msg1[..msg1_len]);

    // Our responder reads msg1.
    let (_, recv) = r_hs.recv().e().unwrap();
    let r_hs = recv.es().unwrap();

    // msg2: <- e, ee (our responder sends)
    let (mut r_transport, _) = r_hs.e().unwrap().ee().unwrap().into_parts();
    let msg2 = stream.take_written();

    let mut buf = [0u8; 256];
    snow_initiator.read_message(&msg2, &mut buf).unwrap();

    assert_eq!(
        r_transport.session_id().as_ref(),
        snow_initiator.get_handshake_hash(),
    );

    let mut snow_initiator = snow_initiator.into_transport_mode().unwrap();

    // Transport: bidirectional exchange.
    let plaintext = b"hello from snow NK initiator";
    let mut ct = [0u8; 256];
    let ct_len = snow_initiator.write_message(plaintext, &mut ct).unwrap();
    let mut pt = [0u8; 256];
    let pt_len = r_transport.receive(&ct[..ct_len], &mut pt).unwrap();
    assert_eq!(&pt[..pt_len], plaintext);

    let reply = b"hello from hiss NK responder";
    let mut ct = [0u8; 256];
    let ct_len = r_transport.send(reply, &mut ct).unwrap();
    let mut pt = [0u8; 256];
    let pt_len = snow_initiator.read_message(&ct[..ct_len], &mut pt).unwrap();
    assert_eq!(&pt[..pt_len], reply);
}

// ── IX: our initiator ↔ snow responder ──────────────────────────

#[test]
fn ix_hiss_initiator_snow_responder() {
    let mut provider = EphemeralOnly::new(StdRng::from_os_rng());
    let initiator_static = provider.generate::<P256>().unwrap();
    let initiator_pub = provider.public(&initiator_static).unwrap();

    let proto = "Noise_IX_P256_ChaChaPoly_BLAKE2b";

    // ── Snow responder setup (no remote static pre-known) ────
    let snow_responder_builder = snow::Builder::new(proto.parse().unwrap());
    let snow_responder_keypair = snow_responder_builder.generate_keypair().unwrap();
    let responder_static_pub = snow_responder_keypair.public.clone();

    let mut snow_responder = snow_responder_builder
        .local_private_key(&snow_responder_keypair.private)
        .unwrap()
        .build_responder()
        .unwrap();

    // ── Our initiator setup (no pre-message setters) ─────────
    type Channel = Noise<pattern::IX, P256, ChaChaPoly, Blake2b>;

    let stream = PeerStream::new();
    let i_hs = SyncHandshake::<Channel, Initiator, _, _, _, _>::initiate(
        EphemeralOnly::new(StdRng::from_os_rng()),
        &[],
        stream.clone(),
    );

    // msg1: -> e, s (our initiator sends; its static is in the clear)
    let i_hs = i_hs.e().unwrap().s(initiator_static).unwrap();
    let msg1 = stream.take_written();

    let mut buf = [0u8; 256];
    snow_responder.read_message(&msg1, &mut buf).unwrap();

    // The static snow received must match ours.
    assert_eq!(
        snow_responder.get_remote_static().unwrap(),
        initiator_pub.to_bytes(),
    );

    // msg2: <- e, ee, se, s, es (snow responder sends)
    let mut msg2 = [0u8; 256];
    let msg2_len = snow_responder.write_message(&[], &mut msg2).unwrap();
    stream.feed(&msg2[..msg2_len]);
    let (_, recv) = i_hs.recv().e().unwrap();
    let recv = recv.ee().unwrap().se().unwrap();
    let (revealed_responder_pub, recv) = recv.s().unwrap();
    let (mut i_transport, _) = recv.es().unwrap().into_parts();

    // The revealed responder static must match snow's.
    assert_eq!(
        revealed_responder_pub.to_bytes(),
        responder_static_pub.as_slice(),
    );

    assert_eq!(
        i_transport.session_id().as_ref(),
        snow_responder.get_handshake_hash(),
    );

    let mut snow_responder = snow_responder.into_transport_mode().unwrap();

    // Transport: bidirectional exchange.
    let plaintext = b"hello from hiss IX initiator";
    let mut ct = [0u8; 256];
    let ct_len = i_transport.send(plaintext, &mut ct).unwrap();
    let mut pt = [0u8; 256];
    let pt_len = snow_responder.read_message(&ct[..ct_len], &mut pt).unwrap();
    assert_eq!(&pt[..pt_len], plaintext);

    let reply = b"hello from snow IX responder";
    let mut ct = [0u8; 256];
    let ct_len = snow_responder.write_message(reply, &mut ct).unwrap();
    let mut pt = [0u8; 256];
    let pt_len = i_transport.receive(&ct[..ct_len], &mut pt).unwrap();
    assert_eq!(&pt[..pt_len], reply);
}

// ── IX: snow initiator ↔ our responder ──────────────────────────

#[test]
fn ix_snow_initiator_hiss_responder() {
    let mut provider = EphemeralOnly::new(StdRng::from_os_rng());
    let responder_static = provider.generate::<P256>().unwrap();
    let responder_pub = provider.public(&responder_static).unwrap();

    let proto = "Noise_IX_P256_ChaChaPoly_BLAKE2b";

    // ── Snow initiator setup (no remote static pre-known) ────
    let snow_initiator_builder = snow::Builder::new(proto.parse().unwrap());
    let snow_initiator_keypair = snow_initiator_builder.generate_keypair().unwrap();

    let mut snow_initiator = snow_initiator_builder
        .local_private_key(&snow_initiator_keypair.private)
        .unwrap()
        .build_initiator()
        .unwrap();

    // ── Our responder setup (no pre-message setters) ─────────
    type Channel = Noise<pattern::IX, P256, ChaChaPoly, Blake2b>;

    let stream = PeerStream::new();
    let r_hs = SyncHandshake::<Channel, Responder, _, _, _, _>::respond(
        EphemeralOnly::new(StdRng::from_os_rng()),
        &[],
        stream.clone(),
    );

    // msg1: -> e, s (snow initiator sends)
    let mut msg1 = [0u8; 256];
    let msg1_len = snow_initiator.write_message(&[], &mut msg1).unwrap();
    stream.feed(&msg1[..msg1_len]);

    // Our responder reads msg1; the `s` token reveals the initiator static.
    let (_, recv) = r_hs.recv().e().unwrap();
    let (revealed_initiator_pub, recv) = recv.s().unwrap();

    // The revealed initiator static must match snow's.
    assert_eq!(
        revealed_initiator_pub.to_bytes(),
        snow_initiator_keypair.public.as_slice(),
    );

    // msg2: <- e, ee, se, s, es (our responder sends)
    let (mut r_transport, _) = recv
        .e()
        .unwrap()
        .ee()
        .unwrap()
        .se()
        .unwrap()
        .s(responder_static)
        .unwrap()
        .es()
        .unwrap()
        .into_parts();
    let msg2 = stream.take_written();

    let mut buf = [0u8; 256];
    snow_initiator.read_message(&msg2, &mut buf).unwrap();

    // The static snow received must match ours.
    assert_eq!(
        snow_initiator.get_remote_static().unwrap(),
        responder_pub.to_bytes(),
    );

    assert_eq!(
        r_transport.session_id().as_ref(),
        snow_initiator.get_handshake_hash(),
    );

    let mut snow_initiator = snow_initiator.into_transport_mode().unwrap();

    // Transport: bidirectional exchange.
    let plaintext = b"hello from snow IX initiator";
    let mut ct = [0u8; 256];
    let ct_len = snow_initiator.write_message(plaintext, &mut ct).unwrap();
    let mut pt = [0u8; 256];
    let pt_len = r_transport.receive(&ct[..ct_len], &mut pt).unwrap();
    assert_eq!(&pt[..pt_len], plaintext);

    let reply = b"hello from hiss IX responder";
    let mut ct = [0u8; 256];
    let ct_len = r_transport.send(reply, &mut ct).unwrap();
    let mut pt = [0u8; 256];
    let pt_len = snow_initiator.read_message(&ct[..ct_len], &mut pt).unwrap();
    assert_eq!(&pt[..pt_len], reply);
}

// ── XK: our initiator ↔ snow responder ──────────────────────────

#[test]
fn xk_hiss_initiator_snow_responder() {
    let mut provider = EphemeralOnly::new(StdRng::from_os_rng());
    let initiator_static = provider.generate::<P256>().unwrap();
    let initiator_pub = provider.public(&initiator_static).unwrap();

    let proto = "Noise_XK_P256_ChaChaPoly_BLAKE2b";

    // ── Snow responder setup (responder static is pre-known to peer) ──
    let snow_responder_builder = snow::Builder::new(proto.parse().unwrap());
    let snow_responder_keypair = snow_responder_builder.generate_keypair().unwrap();
    let responder_pub = P256::public_key_from_bytes(&snow_responder_keypair.public).unwrap();

    let mut snow_responder = snow_responder_builder
        .local_private_key(&snow_responder_keypair.private)
        .unwrap()
        .build_responder()
        .unwrap();

    // ── Our initiator setup: pre-message `<- s` via set_rs ────
    type Channel = Noise<pattern::XK, P256, ChaChaPoly, Blake2b>;

    let stream = PeerStream::new();
    let i_hs = SyncHandshake::<Channel, Initiator, _, _, _, _>::initiate(
        EphemeralOnly::new(StdRng::from_os_rng()),
        &[],
        stream.clone(),
    )
    .set_rs(responder_pub);

    // msg1: -> e, es (our initiator sends)
    let i_hs = i_hs.e().unwrap().es().unwrap();
    let msg1 = stream.take_written();

    let mut buf = [0u8; 256];
    snow_responder.read_message(&msg1, &mut buf).unwrap();

    // msg2: <- e, ee (snow responder sends)
    let mut msg2 = [0u8; 256];
    let msg2_len = snow_responder.write_message(&[], &mut msg2).unwrap();
    stream.feed(&msg2[..msg2_len]);
    let (_, recv) = i_hs.recv().e().unwrap();
    let i_hs = recv.ee().unwrap();

    // msg3: -> s, se (our initiator sends; its static is encrypted)
    let (mut i_transport, _) = i_hs.s(initiator_static).unwrap().se().unwrap().into_parts();
    let msg3 = stream.take_written();

    let mut buf = [0u8; 256];
    snow_responder.read_message(&msg3, &mut buf).unwrap();

    // The static snow received (encrypted in msg3) must match ours.
    assert_eq!(
        snow_responder.get_remote_static().unwrap(),
        initiator_pub.to_bytes(),
    );

    assert_eq!(
        i_transport.session_id().as_ref(),
        snow_responder.get_handshake_hash(),
    );

    let mut snow_responder = snow_responder.into_transport_mode().unwrap();

    // Transport: bidirectional exchange.
    let plaintext = b"hello from hiss XK initiator";
    let mut ct = [0u8; 256];
    let ct_len = i_transport.send(plaintext, &mut ct).unwrap();
    let mut pt = [0u8; 256];
    let pt_len = snow_responder.read_message(&ct[..ct_len], &mut pt).unwrap();
    assert_eq!(&pt[..pt_len], plaintext);

    let reply = b"hello from snow XK responder";
    let mut ct = [0u8; 256];
    let ct_len = snow_responder.write_message(reply, &mut ct).unwrap();
    let mut pt = [0u8; 256];
    let pt_len = i_transport.receive(&ct[..ct_len], &mut pt).unwrap();
    assert_eq!(&pt[..pt_len], reply);
}

// ── XK: snow initiator ↔ our responder ──────────────────────────

#[test]
fn xk_snow_initiator_hiss_responder() {
    let mut provider = EphemeralOnly::new(StdRng::from_os_rng());
    let responder_static = provider.generate::<P256>().unwrap();
    let responder_pub = provider.public(&responder_static).unwrap();

    let proto = "Noise_XK_P256_ChaChaPoly_BLAKE2b";

    // ── Snow initiator setup (pre-knows the responder static) ──
    let snow_initiator_builder = snow::Builder::new(proto.parse().unwrap());
    let snow_initiator_keypair = snow_initiator_builder.generate_keypair().unwrap();

    let mut snow_initiator = snow_initiator_builder
        .local_private_key(&snow_initiator_keypair.private)
        .unwrap()
        .remote_public_key(responder_pub.to_bytes())
        .unwrap()
        .build_initiator()
        .unwrap();

    // ── Our responder setup: pre-message `<- s` via set_s ────
    type Channel = Noise<pattern::XK, P256, ChaChaPoly, Blake2b>;

    let stream = PeerStream::new();
    let r_hs = SyncHandshake::<Channel, Responder, _, _, _, _>::respond(
        EphemeralOnly::new(StdRng::from_os_rng()),
        &[],
        stream.clone(),
    )
    .set_s(responder_static)
    .unwrap();

    // msg1: -> e, es (snow initiator sends)
    let mut msg1 = [0u8; 256];
    let msg1_len = snow_initiator.write_message(&[], &mut msg1).unwrap();
    stream.feed(&msg1[..msg1_len]);

    // Our responder reads msg1 (-> e, es).
    let (_, recv) = r_hs.recv().e().unwrap();
    let r_hs = recv.es().unwrap();

    // msg2: <- e, ee (our responder sends)
    let r_hs = r_hs.e().unwrap().ee().unwrap();
    let msg2 = stream.take_written();

    let mut buf = [0u8; 256];
    snow_initiator.read_message(&msg2, &mut buf).unwrap();

    // msg3: -> s, se (snow initiator sends; its static is encrypted)
    let mut msg3 = [0u8; 256];
    let msg3_len = snow_initiator.write_message(&[], &mut msg3).unwrap();
    stream.feed(&msg3[..msg3_len]);

    // Our responder reads msg3; the `s` token reveals the initiator static.
    let (revealed_initiator_pub, recv) = r_hs.recv().s().unwrap();
    let (mut r_transport, _) = recv.se().unwrap().into_parts();

    // The revealed initiator static must match snow's.
    assert_eq!(
        revealed_initiator_pub.to_bytes(),
        snow_initiator_keypair.public.as_slice(),
    );

    assert_eq!(
        r_transport.session_id().as_ref(),
        snow_initiator.get_handshake_hash(),
    );

    let mut snow_initiator = snow_initiator.into_transport_mode().unwrap();

    // Transport: bidirectional exchange.
    let plaintext = b"hello from snow XK initiator";
    let mut ct = [0u8; 256];
    let ct_len = snow_initiator.write_message(plaintext, &mut ct).unwrap();
    let mut pt = [0u8; 256];
    let pt_len = r_transport.receive(&ct[..ct_len], &mut pt).unwrap();
    assert_eq!(&pt[..pt_len], plaintext);

    let reply = b"hello from hiss XK responder";
    let mut ct = [0u8; 256];
    let ct_len = r_transport.send(reply, &mut ct).unwrap();
    let mut pt = [0u8; 256];
    let pt_len = snow_initiator.read_message(&ct[..ct_len], &mut pt).unwrap();
    assert_eq!(&pt[..pt_len], reply);
}

// ── NN: our initiator ↔ snow responder ──────────────────────────

#[test]
fn nn_hiss_initiator_snow_responder() {
    let proto = "Noise_NN_P256_ChaChaPoly_BLAKE2b";

    // ── Snow responder setup (anonymous: no static) ──────────
    let mut snow_responder = snow::Builder::new(proto.parse().unwrap())
        .build_responder()
        .unwrap();

    // ── Our initiator setup (anonymous: no static, no pre-known peer) ──
    type Channel = Noise<pattern::NN, P256, ChaChaPoly, Blake2b>;

    let stream = PeerStream::new();
    let i_hs = SyncHandshake::<Channel, Initiator, _, _, _, _>::initiate(
        EphemeralOnly::new(StdRng::from_os_rng()),
        &[],
        stream.clone(),
    );

    // msg1: -> e (single-`e` send finalizer; 65 bytes, cipher never keyed)
    let i_hs = i_hs.e().unwrap();
    let msg1 = stream.take_written();
    assert_eq!(msg1.len(), 65);

    let mut buf = [0u8; 256];
    snow_responder.read_message(&msg1, &mut buf).unwrap();

    // msg2: <- e, ee (snow responder sends)
    let mut msg2 = [0u8; 256];
    let msg2_len = snow_responder.write_message(&[], &mut msg2).unwrap();
    stream.feed(&msg2[..msg2_len]);
    let (_, recv) = i_hs.recv().e().unwrap();
    let (mut i_transport, _) = recv.ee().unwrap().into_parts();

    assert_eq!(
        i_transport.session_id().as_ref(),
        snow_responder.get_handshake_hash(),
    );

    let mut snow_responder = snow_responder.into_transport_mode().unwrap();

    // Transport: bidirectional exchange.
    let plaintext = b"hello from hiss NN initiator";
    let mut ct = [0u8; 256];
    let ct_len = i_transport.send(plaintext, &mut ct).unwrap();
    let mut pt = [0u8; 256];
    let pt_len = snow_responder.read_message(&ct[..ct_len], &mut pt).unwrap();
    assert_eq!(&pt[..pt_len], plaintext);

    let reply = b"hello from snow NN responder";
    let mut ct = [0u8; 256];
    let ct_len = snow_responder.write_message(reply, &mut ct).unwrap();
    let mut pt = [0u8; 256];
    let pt_len = i_transport.receive(&ct[..ct_len], &mut pt).unwrap();
    assert_eq!(&pt[..pt_len], reply);
}

// ── NN: snow initiator ↔ our responder ──────────────────────────

#[test]
fn nn_snow_initiator_hiss_responder() {
    let proto = "Noise_NN_P256_ChaChaPoly_BLAKE2b";

    // ── Snow initiator setup (anonymous: no static) ──────────
    let mut snow_initiator = snow::Builder::new(proto.parse().unwrap())
        .build_initiator()
        .unwrap();

    // ── Our responder setup (anonymous: no static) ───────────
    type Channel = Noise<pattern::NN, P256, ChaChaPoly, Blake2b>;

    let stream = PeerStream::new();
    let r_hs = SyncHandshake::<Channel, Responder, _, _, _, _>::respond(
        EphemeralOnly::new(StdRng::from_os_rng()),
        &[],
        stream.clone(),
    );

    // msg1: -> e (snow initiator sends)
    let mut msg1 = [0u8; 256];
    let msg1_len = snow_initiator.write_message(&[], &mut msg1).unwrap();
    stream.feed(&msg1[..msg1_len]);

    // Our responder reads msg1.
    let (_, recv) = r_hs.recv().e().unwrap();

    // msg2: <- e, ee (our responder sends)
    let (mut r_transport, _) = recv.e().unwrap().ee().unwrap().into_parts();
    let msg2 = stream.take_written();

    let mut buf = [0u8; 256];
    snow_initiator.read_message(&msg2, &mut buf).unwrap();

    assert_eq!(
        r_transport.session_id().as_ref(),
        snow_initiator.get_handshake_hash(),
    );

    let mut snow_initiator = snow_initiator.into_transport_mode().unwrap();

    // Transport: bidirectional exchange.
    let plaintext = b"hello from snow NN initiator";
    let mut ct = [0u8; 256];
    let ct_len = snow_initiator.write_message(plaintext, &mut ct).unwrap();
    let mut pt = [0u8; 256];
    let pt_len = r_transport.receive(&ct[..ct_len], &mut pt).unwrap();
    assert_eq!(&pt[..pt_len], plaintext);

    let reply = b"hello from hiss NN responder";
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
    let initiator_static = provider.generate::<P256>().unwrap();
    let initiator_pub = provider.public(&initiator_static).unwrap();

    let proto = "Noise_XX_P256_ChaChaPoly_BLAKE2b";

    // ── Snow responder setup: own static, no pre-known peer static ──
    let snow_responder_builder = snow::Builder::new(proto.parse().unwrap());
    let snow_responder_keypair = snow_responder_builder.generate_keypair().unwrap();
    let responder_static_pub = P256::public_key_from_bytes(&snow_responder_keypair.public).unwrap();

    let mut snow_responder = snow_responder_builder
        .local_private_key(&snow_responder_keypair.private)
        .unwrap()
        .build_responder()
        .unwrap();

    // ── Our initiator setup (no pre-messages: neither static pre-known) ──
    type Channel = Noise<pattern::XX, P256, ChaChaPoly, Blake2b>;

    let stream = PeerStream::new();
    let i_hs = SyncHandshake::<Channel, Initiator, _, _, _, _>::initiate(
        EphemeralOnly::new(StdRng::from_os_rng()),
        &[],
        stream.clone(),
    );

    // msg1: -> e (single-`e` send finalizer; 65 bytes, cipher never keyed)
    let i_hs = i_hs.e().unwrap();
    let msg1 = stream.take_written();
    assert_eq!(msg1.len(), 65);

    let mut buf = [0u8; 256];
    snow_responder.read_message(&msg1, &mut buf).unwrap();

    // msg2: <- e, ee, s, es (snow responder sends; its static is encrypted)
    let mut msg2 = [0u8; 256];
    let msg2_len = snow_responder.write_message(&[], &mut msg2).unwrap();
    stream.feed(&msg2[..msg2_len]);
    let (_, recv) = i_hs.recv().e().unwrap();
    let recv = recv.ee().unwrap();
    let (revealed_responder_pub, recv) = recv.s().unwrap();
    // The static snow revealed (encrypted in msg2) must match snow's.
    assert_eq!(
        revealed_responder_pub.to_bytes(),
        responder_static_pub.to_bytes(),
    );
    let i_hs = recv.es().unwrap();

    // msg3: -> s, se (our initiator sends; its static is encrypted)
    let (mut i_transport, _) = i_hs.s(initiator_static).unwrap().se().unwrap().into_parts();
    let msg3 = stream.take_written();

    let mut buf = [0u8; 256];
    snow_responder.read_message(&msg3, &mut buf).unwrap();

    // The static snow received (encrypted in msg3) must match ours.
    assert_eq!(
        snow_responder.get_remote_static().unwrap(),
        initiator_pub.to_bytes(),
    );

    assert_eq!(
        i_transport.session_id().as_ref(),
        snow_responder.get_handshake_hash(),
    );

    let mut snow_responder = snow_responder.into_transport_mode().unwrap();

    // Transport: bidirectional exchange.
    let plaintext = b"hello from hiss XX initiator";
    let mut ct = [0u8; 256];
    let ct_len = i_transport.send(plaintext, &mut ct).unwrap();
    let mut pt = [0u8; 256];
    let pt_len = snow_responder.read_message(&ct[..ct_len], &mut pt).unwrap();
    assert_eq!(&pt[..pt_len], plaintext);

    let reply = b"hello from snow XX responder";
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
    let responder_static = provider.generate::<P256>().unwrap();
    let responder_pub = provider.public(&responder_static).unwrap();

    let proto = "Noise_XX_P256_ChaChaPoly_BLAKE2b";

    // ── Snow initiator setup: own static, no pre-known peer static ──
    let snow_initiator_builder = snow::Builder::new(proto.parse().unwrap());
    let snow_initiator_keypair = snow_initiator_builder.generate_keypair().unwrap();

    let mut snow_initiator = snow_initiator_builder
        .local_private_key(&snow_initiator_keypair.private)
        .unwrap()
        .build_initiator()
        .unwrap();

    // ── Our responder setup (no pre-messages: neither static pre-known) ──
    type Channel = Noise<pattern::XX, P256, ChaChaPoly, Blake2b>;

    let stream = PeerStream::new();
    let r_hs = SyncHandshake::<Channel, Responder, _, _, _, _>::respond(
        EphemeralOnly::new(StdRng::from_os_rng()),
        &[],
        stream.clone(),
    );

    // msg1: -> e (snow initiator sends)
    let mut msg1 = [0u8; 256];
    let msg1_len = snow_initiator.write_message(&[], &mut msg1).unwrap();
    stream.feed(&msg1[..msg1_len]);

    // Our responder reads msg1.
    let (_, recv) = r_hs.recv().e().unwrap();

    // msg2: <- e, ee, s, es (our responder sends; its static is encrypted)
    let r_hs = recv
        .e()
        .unwrap()
        .ee()
        .unwrap()
        .s(responder_static)
        .unwrap()
        .es()
        .unwrap();
    let msg2 = stream.take_written();

    let mut buf = [0u8; 256];
    snow_initiator.read_message(&msg2, &mut buf).unwrap();

    // The static snow received in msg2 (encrypted) must match ours.
    assert_eq!(
        snow_initiator.get_remote_static().unwrap(),
        responder_pub.to_bytes(),
    );

    // msg3: -> s, se (snow initiator sends; its static is encrypted)
    let mut msg3 = [0u8; 256];
    let msg3_len = snow_initiator.write_message(&[], &mut msg3).unwrap();
    stream.feed(&msg3[..msg3_len]);

    // Our responder reads msg3; the `s` token reveals the initiator static.
    let (revealed_initiator_pub, recv) = r_hs.recv().s().unwrap();
    let (mut r_transport, _) = recv.se().unwrap().into_parts();

    // The revealed initiator static must match snow's.
    assert_eq!(
        revealed_initiator_pub.to_bytes(),
        snow_initiator_keypair.public.as_slice(),
    );

    assert_eq!(
        r_transport.session_id().as_ref(),
        snow_initiator.get_handshake_hash(),
    );

    let mut snow_initiator = snow_initiator.into_transport_mode().unwrap();

    // Transport: bidirectional exchange.
    let plaintext = b"hello from snow XX initiator";
    let mut ct = [0u8; 256];
    let ct_len = snow_initiator.write_message(plaintext, &mut ct).unwrap();
    let mut pt = [0u8; 256];
    let pt_len = r_transport.receive(&ct[..ct_len], &mut pt).unwrap();
    assert_eq!(&pt[..pt_len], plaintext);

    let reply = b"hello from hiss XX responder";
    let mut ct = [0u8; 256];
    let ct_len = r_transport.send(reply, &mut ct).unwrap();
    let mut pt = [0u8; 256];
    let pt_len = snow_initiator.read_message(&ct[..ct_len], &mut pt).unwrap();
    assert_eq!(&pt[..pt_len], reply);
}
