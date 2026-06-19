//! Benchmarks comparing our Noise implementation against `snow`.
//!
//! Each benchmark performs a complete handshake (all messages) followed
//! by a transport round-trip, measuring the total wall time. This
//! gives a realistic end-to-end comparison.

use criterion::{Criterion, criterion_group, criterion_main};

use hiss::provider::ProviderExt;
use hiss::provider::EphemeralOnly;
use hiss::noise::*;
use hiss::psk::Psk;

// ── Helpers ─────────────────────────────────────────────────────

/// Tokio runtime shared across benchmarks.
fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
}

// ── N pattern ───────────────────────────────────────────────────

fn bench_n_hiss(c: &mut Criterion) {
    let rt = rt();

    c.bench_function("noise_N_hiss", |b| {
        b.iter(|| {
            rt.block_on(async {
                let provider = EphemeralOnly;

                let responder_static = provider.generate::<P256>().unwrap();
                let responder_pub = provider.public(&responder_static).unwrap();

                type NoiseSeal = Noise<N, P256, ChaChaPoly, Blake2b>;

                // Initiator seals
                let sealer =
                    NoiseSeal::initiate(EphemeralOnly, &[]).set_rs(responder_pub);
                let mut msg_buf = [0u8; 81];
                let (msg, mut i_transport) =
                    sealer.e(&mut msg_buf).await.unwrap().es().await.unwrap();

                // Responder opens
                let opener = NoiseSeal::respond(EphemeralOnly, &[])
                    .set_s(responder_static)
                    .unwrap();
                let (_, recv) = opener.read(msg).unwrap().e().await.unwrap();
                let mut r_transport = recv.es().await.unwrap();

                // Transport round-trip
                let plaintext = b"benchmark payload";
                let mut ct = [0u8; 64];
                let ct_len = i_transport.send(plaintext, &mut ct).unwrap();
                let mut pt = [0u8; 64];
                let pt_len = r_transport.receive(&ct[..ct_len], &mut pt).unwrap();
                assert_eq!(&pt[..pt_len], plaintext);
            });
        });
    });
}

fn bench_n_snow(c: &mut Criterion) {
    let protocol: snow::params::NoiseParams = "Noise_N_P256_ChaChaPoly_BLAKE2b".parse().unwrap();

    c.bench_function("noise_N_snow", |b| {
        b.iter(|| {
            let builder = snow::Builder::new(protocol.clone());
            let responder_kp = builder.generate_keypair().unwrap();

            // Initiator
            let mut initiator = snow::Builder::new(protocol.clone())
                .remote_public_key(&responder_kp.public)
                .unwrap()
                .build_initiator()
                .unwrap();

            let mut msg = [0u8; 256];
            let msg_len = initiator.write_message(&[], &mut msg).unwrap();

            // Responder
            let mut responder = snow::Builder::new(protocol.clone())
                .local_private_key(&responder_kp.private)
                .unwrap()
                .build_responder()
                .unwrap();

            let mut buf = [0u8; 256];
            responder.read_message(&msg[..msg_len], &mut buf).unwrap();

            let mut initiator = initiator.into_transport_mode().unwrap();
            let mut responder = responder.into_transport_mode().unwrap();

            // Transport round-trip
            let plaintext = b"benchmark payload";
            let mut ct = [0u8; 256];
            let ct_len = initiator.write_message(plaintext, &mut ct).unwrap();
            let mut pt = [0u8; 256];
            let pt_len = responder.read_message(&ct[..ct_len], &mut pt).unwrap();
            assert_eq!(&pt[..pt_len], plaintext);
        });
    });
}

// ── IKpsk1 pattern ──────────────────────────────────────────────

fn bench_ikpsk1_hiss(c: &mut Criterion) {
    let rt = rt();

    c.bench_function("noise_IKpsk1_hiss", |b| {
        b.iter(|| {
            rt.block_on(async {
                let provider = EphemeralOnly;

                let i_static = provider.generate::<P256>().unwrap();
                let r_static = provider.generate::<P256>().unwrap();
                let r_pub = provider.public(&r_static).unwrap();
                let psk = Psk::from_bytes([0xAA; 32]);

                type Proto = Noise<IKpsk1, P256, ChaChaPoly, Blake2b>;

                // Message 1: -> e, es, s, ss, psk
                let i_hs = Proto::initiate(EphemeralOnly, &[]).set_rs(r_pub);
                let mut msg1_buf = [0u8; 162];
                let (msg1, i_hs) = i_hs
                    .e(&mut msg1_buf)
                    .await
                    .unwrap()
                    .es()
                    .await
                    .unwrap()
                    .s(i_static)
                    .await
                    .unwrap()
                    .ss()
                    .await
                    .unwrap()
                    .psk(&psk)
                    .await
                    .unwrap();
                let msg1 = msg1.to_vec();

                // Responder reads msg1
                let r_hs = Proto::respond(EphemeralOnly, &[])
                    .set_s(r_static)
                    .unwrap();
                let (_, recv) = r_hs.read(&msg1).unwrap().e().await.unwrap();
                let recv = recv.es().await.unwrap();
                let (_, recv) = recv.s().await.unwrap();
                let recv = recv.ss().await.unwrap();
                let r_hs = recv.psk(&psk).await.unwrap();

                // Message 2: <- e, ee, se
                let mut msg2_buf = [0u8; 81];
                let (msg2, mut r_transport) = r_hs
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

                // Initiator reads msg2
                let (_, recv) = i_hs.read(&msg2).unwrap().e().await.unwrap();
                let mut i_transport = recv.ee().await.unwrap().se().await.unwrap();

                // Transport round-trip
                let plaintext = b"benchmark payload";
                let mut ct = [0u8; 64];
                let ct_len = i_transport.send(plaintext, &mut ct).unwrap();
                let mut pt = [0u8; 64];
                let pt_len = r_transport.receive(&ct[..ct_len], &mut pt).unwrap();
                assert_eq!(&pt[..pt_len], plaintext);
            });
        });
    });
}

fn bench_ikpsk1_snow(c: &mut Criterion) {
    let protocol: snow::params::NoiseParams =
        "Noise_IKpsk1_P256_ChaChaPoly_BLAKE2b".parse().unwrap();

    c.bench_function("noise_IKpsk1_snow", |b| {
        b.iter(|| {
            let builder = snow::Builder::new(protocol.clone());
            let i_kp = builder.generate_keypair().unwrap();
            let r_kp = builder.generate_keypair().unwrap();
            let psk = Psk::from_bytes([0xAA; 32]);

            let mut initiator = snow::Builder::new(protocol.clone())
                .local_private_key(&i_kp.private)
                .unwrap()
                .remote_public_key(&r_kp.public)
                .unwrap()
                .psk(1, psk.as_bytes())
                .unwrap()
                .build_initiator()
                .unwrap();

            let mut responder = snow::Builder::new(protocol.clone())
                .local_private_key(&r_kp.private)
                .unwrap()
                .psk(1, psk.as_bytes())
                .unwrap()
                .build_responder()
                .unwrap();

            let mut buf = [0u8; 512];

            // msg1
            let mut msg1 = [0u8; 512];
            let len1 = initiator.write_message(&[], &mut msg1).unwrap();
            responder.read_message(&msg1[..len1], &mut buf).unwrap();

            // msg2
            let mut msg2 = [0u8; 512];
            let len2 = responder.write_message(&[], &mut msg2).unwrap();
            initiator.read_message(&msg2[..len2], &mut buf).unwrap();

            let mut initiator = initiator.into_transport_mode().unwrap();
            let mut responder = responder.into_transport_mode().unwrap();

            // Transport round-trip
            let plaintext = b"benchmark payload";
            let mut ct = [0u8; 256];
            let ct_len = initiator.write_message(plaintext, &mut ct).unwrap();
            let mut pt = [0u8; 256];
            let pt_len = responder.read_message(&ct[..ct_len], &mut pt).unwrap();
            assert_eq!(&pt[..pt_len], plaintext);
        });
    });
}

// ── Transport throughput ────────────────────────────────────────

fn bench_transport_hiss(c: &mut Criterion) {
    let rt = rt();

    // Set up a completed N handshake, then benchmark transport only.
    let (mut sender, mut receiver) = rt.block_on(async {
        let provider = EphemeralOnly;

        let r_static = provider.generate::<P256>().unwrap();
        let r_pub = provider.public(&r_static).unwrap();

        type NoiseSeal = Noise<N, P256, ChaChaPoly, Blake2b>;

        let sealer = NoiseSeal::initiate(EphemeralOnly, &[]).set_rs(r_pub);
        let mut msg_buf = [0u8; 81];
        let (msg, i_transport) = sealer.e(&mut msg_buf).await.unwrap().es().await.unwrap();

        let opener = NoiseSeal::respond(EphemeralOnly, &[])
            .set_s(r_static)
            .unwrap();
        let (_, recv) = opener.read(msg).unwrap().e().await.unwrap();
        let r_transport = recv.es().await.unwrap();

        (i_transport, r_transport)
    });

    let plaintext = [0x42u8; 1024];
    let mut ct = [0u8; 1056]; // 1024 + 16 tag + headroom
    let mut pt = [0u8; 1024];

    c.bench_function("transport_1KiB_hiss", |b| {
        b.iter(|| {
            let ct_len = sender.send(&plaintext, &mut ct).unwrap();
            let pt_len = receiver.receive(&ct[..ct_len], &mut pt).unwrap();
            assert_eq!(pt_len, 1024);
        });
    });
}

fn bench_transport_snow(c: &mut Criterion) {
    let protocol: snow::params::NoiseParams = "Noise_N_P256_ChaChaPoly_BLAKE2b".parse().unwrap();

    let builder = snow::Builder::new(protocol.clone());
    let r_kp = builder.generate_keypair().unwrap();

    let mut initiator = snow::Builder::new(protocol.clone())
        .remote_public_key(&r_kp.public)
        .unwrap()
        .build_initiator()
        .unwrap();

    let mut responder = snow::Builder::new(protocol.clone())
        .local_private_key(&r_kp.private)
        .unwrap()
        .build_responder()
        .unwrap();

    let mut msg = [0u8; 256];
    let msg_len = initiator.write_message(&[], &mut msg).unwrap();
    let mut buf = [0u8; 256];
    responder.read_message(&msg[..msg_len], &mut buf).unwrap();

    let mut sender = initiator.into_transport_mode().unwrap();
    let mut receiver = responder.into_transport_mode().unwrap();

    let plaintext = [0x42u8; 1024];
    let mut ct = [0u8; 1056];
    let mut pt = [0u8; 1024];

    c.bench_function("transport_1KiB_snow", |b| {
        b.iter(|| {
            let ct_len = sender.write_message(&plaintext, &mut ct).unwrap();
            let pt_len = receiver.read_message(&ct[..ct_len], &mut pt).unwrap();
            assert_eq!(pt_len, 1024);
        });
    });
}

// ── Groups ──────────────────────────────────────────────────────

criterion_group!(handshake_n, bench_n_hiss, bench_n_snow,);

criterion_group!(handshake_ikpsk1, bench_ikpsk1_hiss, bench_ikpsk1_snow,);

criterion_group!(transport, bench_transport_hiss, bench_transport_snow,);

criterion_main!(handshake_n, handshake_ikpsk1, transport);
