//! Benchmarks comparing our Noise implementation against `snow`.
//!
//! Each benchmark performs a complete handshake (all messages) followed
//! by a transport round-trip, measuring the total wall time. This
//! gives a realistic end-to-end comparison.

use criterion::{Criterion, criterion_group, criterion_main};

use hiss::noise::*;
use hiss::provider::EphemeralOnly;
use hiss::provider::ProviderExt;
use hiss::psk::Psk;
use rand::{SeedableRng, rngs::StdRng};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::io::Cursor;
use std::rc::Rc;

// ── In-memory pipe for multi-message handshakes ─────────────────

/// A linked in-memory `Read + Write` endpoint pair; `a`'s writes are
/// `b`'s reads and vice versa. Lets a multi-message hiss↔hiss handshake
/// run interleaved on one thread over the blocking driver.
#[derive(Clone)]
struct BenchPipe {
    inbound: Rc<RefCell<VecDeque<u8>>>,
    outbound: Rc<RefCell<VecDeque<u8>>>,
}

impl BenchPipe {
    fn pair() -> (BenchPipe, BenchPipe) {
        let l = Rc::new(RefCell::new(VecDeque::new()));
        let r = Rc::new(RefCell::new(VecDeque::new()));
        (
            BenchPipe {
                inbound: r.clone(),
                outbound: l.clone(),
            },
            BenchPipe {
                inbound: l,
                outbound: r,
            },
        )
    }
}

impl std::io::Read for BenchPipe {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut q = self.inbound.borrow_mut();
        let n = q.len().min(buf.len());
        for slot in buf.iter_mut().take(n) {
            *slot = q.pop_front().unwrap();
        }
        Ok(n)
    }
}

impl std::io::Write for BenchPipe {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.outbound.borrow_mut().extend(buf.iter().copied());
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

// ── N pattern ───────────────────────────────────────────────────
//
// Driven over the blocking [`SyncHandshake`] driver: `EphemeralOnly` is
// a synchronous `DhProvider`, so the handshake runs with no executor.
// The initiator streams into a `Vec`; the responder reads it back from a
// `Cursor`.

fn bench_n_hiss(c: &mut Criterion) {
    c.bench_function("noise_N_hiss", |b| {
        b.iter(|| {
            let mut provider = EphemeralOnly::new(StdRng::from_os_rng());

            let responder_static = provider.generate::<P256>().unwrap();
            let responder_pub = provider.public(&responder_static).unwrap();

            type NoiseSeal = Noise<pattern::N, P256, ChaChaPoly, Blake2b>;

            // Initiator seals (msg1 → Vec)
            let sealer = SyncHandshake::<NoiseSeal, Initiator, _, _, _, _>::initiate(
                EphemeralOnly::new(StdRng::from_os_rng()),
                &[],
                Vec::new(),
            )
            .set_rs(responder_pub);
            let (mut i_transport, wire) = sealer.e().unwrap().es().unwrap().into_parts();

            // Responder opens (reads msg1 from the captured wire)
            let opener = SyncHandshake::<NoiseSeal, Responder, _, _, _, _>::respond(
                EphemeralOnly::new(StdRng::from_os_rng()),
                &[],
                Cursor::new(wire),
            )
            .set_s(responder_static)
            .unwrap();
            let (_, recv) = opener.recv().e().unwrap();
            let (mut r_transport, _) = recv.es().unwrap().into_parts();

            // Transport round-trip
            let plaintext = b"benchmark payload";
            let mut ct = [0u8; 64];
            let ct_len = i_transport.send(plaintext, &mut ct).unwrap();
            let mut pt = [0u8; 64];
            let pt_len = r_transport.receive(&ct[..ct_len], &mut pt).unwrap();
            assert_eq!(&pt[..pt_len], plaintext);
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
    c.bench_function("noise_IKpsk1_hiss", |b| {
        b.iter(|| {
            let mut provider = EphemeralOnly::new(StdRng::from_os_rng());

            let i_static = provider.generate::<P256>().unwrap();
            let r_static = provider.generate::<P256>().unwrap();
            let r_pub = provider.public(&r_static).unwrap();
            let psk = Psk::from_bytes([0xAA; 32]);

            type Proto = Noise<pattern::IKpsk1, P256, ChaChaPoly, Blake2b>;

            let (i_pipe, r_pipe) = BenchPipe::pair();
            let i_hs = SyncHandshake::<Proto, Initiator, _, _, _, _>::initiate(
                EphemeralOnly::new(StdRng::from_os_rng()),
                &[],
                i_pipe,
            )
            .set_rs(r_pub);
            let r_hs = SyncHandshake::<Proto, Responder, _, _, _, _>::respond(
                EphemeralOnly::new(StdRng::from_os_rng()),
                &[],
                r_pipe,
            )
            .set_s(r_static)
            .unwrap();

            // Message 1: -> e, es, s, ss, psk
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

            // Responder reads msg1
            let (_, recv) = r_hs.recv().e().unwrap();
            let recv = recv.es().unwrap();
            let (_, recv) = recv.s().unwrap();
            let recv = recv.ss().unwrap();
            let r_hs = recv.psk(&psk).unwrap();

            // Message 2: <- e, ee, se
            let (mut r_transport, _) = r_hs.e().unwrap().ee().unwrap().se().unwrap().into_parts();

            // Initiator reads msg2
            let (_, recv) = i_hs.recv().e().unwrap();
            let (mut i_transport, _) = recv.ee().unwrap().se().unwrap().into_parts();

            // Transport round-trip
            let plaintext = b"benchmark payload";
            let mut ct = [0u8; 64];
            let ct_len = i_transport.send(plaintext, &mut ct).unwrap();
            let mut pt = [0u8; 64];
            let pt_len = r_transport.receive(&ct[..ct_len], &mut pt).unwrap();
            assert_eq!(&pt[..pt_len], plaintext);
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
    // Set up a completed N handshake, then benchmark transport only.
    let (mut sender, mut receiver) = {
        let mut provider = EphemeralOnly::new(StdRng::from_os_rng());

        let r_static = provider.generate::<P256>().unwrap();
        let r_pub = provider.public(&r_static).unwrap();

        type NoiseSeal = Noise<pattern::N, P256, ChaChaPoly, Blake2b>;

        let sealer = SyncHandshake::<NoiseSeal, Initiator, _, _, _, _>::initiate(
            EphemeralOnly::new(StdRng::from_os_rng()),
            &[],
            Vec::new(),
        )
        .set_rs(r_pub);
        let (i_transport, wire) = sealer.e().unwrap().es().unwrap().into_parts();

        let opener = SyncHandshake::<NoiseSeal, Responder, _, _, _, _>::respond(
            EphemeralOnly::new(StdRng::from_os_rng()),
            &[],
            Cursor::new(wire),
        )
        .set_s(r_static)
        .unwrap();
        let (_, recv) = opener.recv().e().unwrap();
        let (r_transport, _) = recv.es().unwrap().into_parts();

        (i_transport, r_transport)
    };

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
