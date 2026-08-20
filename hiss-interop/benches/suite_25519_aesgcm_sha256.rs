//! hiss vs `snow` on **one suite, end to end: `Noise_*_25519_AESGCM_SHA256`**.
//!
//! `comparison.rs` spreads its matrix across axes — curves for the handshakes
//! (over ChaChaPoly/BLAKE2b), ciphers for the transport (over P256/BLAKE2b).
//! This bench fixes every axis of the suite at once — X25519, AESGCM, SHA-256
//! — and asks the question the matrix cannot: on *this* suite, handshake and
//! transport, how do the two implementations compare, and how does that
//! comparison move with the message size?
//!
//! # Groups
//!
//! | Group | Arms | What is timed |
//! |---|---|---|
//! | `25519_AESGCM_SHA256/handshake_N` | hiss, snow | a complete `N` handshake, both parties, to transport-ready |
//! | `25519_AESGCM_SHA256/handshake_IK` | hiss, snow | the same for `IK` (two messages, both statics) |
//! | `25519_AESGCM_SHA256/handshake_XX` | hiss, snow | the same for `XX` (three messages, statics in-band) |
//! | `25519_AESGCM_SHA256/transport_round_trip` | hiss, snow × {64 B, 1 KiB, 16 KiB, 65519 B} | one `send` + one `receive` |
//! | `25519_AESGCM_SHA256/transport_encrypt` | same | `send` only |
//! | `25519_AESGCM_SHA256/transport_decrypt` | same | `receive` only; the ciphertext is made in unmeasured setup |
//!
//! The transport groups report throughput in bytes per second as well as
//! time per message. 64 B is where the fixed per-message costs dominate, and
//! is therefore the row that moved most when hiss 0.4.0 hoisted the AES key
//! schedule out of the per-message path into `Cipher::Key` (~117 ns on Apple
//! Silicon; the 64 B round trip went 314 ns → 84 ns, see
//! `src/noise/cipher.rs`). 65519 B is the largest plaintext a Noise record
//! can carry (65535 minus the 16-byte tag, `MAX_MESSAGE_LEN` in hiss, the
//! same cap in `snow`) and is where the bulk AES/GHASH rate is all that is
//! left.
//!
//! # Caveats — the same two as `comparison.rs`, read that file's docs
//!
//! * **RNG.** hiss's ephemerals come from a `StdRng` seeded once in setup;
//!   snow's internal `OsRng` is in its measured region. Slightly in hiss's
//!   favour on the handshake rows only.
//! * **Which AES-GCM you are measuring** depends on the host, on both arms.
//!   On a Mac both stacks run hardware AES + hardware carry-less multiply
//!   (hiss via cryptoxide's `aarch64`+`aes` path, snow via the `aes_armv8` /
//!   `polyval_armv8` cfgs this crate's `.cargo/config.toml` sets); on x86-64
//!   hiss is portable software while snow runtime-detects AES-NI + CLMUL.
//!   State the host beside any number. CI only compiles this (`--no-run`).
//!
//! Neither caveat touches the transport rows' fairness: no ephemeral is
//! generated inside any measured transport routine, and both sides
//! encrypt/decrypt into flat slices with no I/O abstraction.

use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;

use hiss::noise::{AesGcm, Sha256, X25519};
use hiss::provider::EphemeralOnly;
use hiss::provider::ProviderExt;
use rand::rngs::StdRng;

const SUITE: &str = "25519_AESGCM_SHA256";

/// A fresh software provider seeded from OS entropy. Built in unmeasured
/// setup so the `make_rng()` syscall never lands in a timed routine.
fn provider() -> EphemeralOnly<StdRng> {
    EphemeralOnly::new(rand::make_rng::<StdRng>())
}

fn group_name(what: &str) -> String {
    format!("{SUITE}/{what}")
}

fn snow_protocol(pattern: &str) -> snow::params::NoiseParams {
    format!("Noise_{pattern}_{SUITE}").parse().unwrap()
}

// ── Handshakes ──────────────────────────────────────────────────────────
//
// One `noise!` per `bench_function` closure, as in `comparison.rs`; the
// identifier is the canonical pattern name because it becomes the Noise
// protocol name. Static keys and providers are minted in `iter_batched`
// setup (unmeasured); the routine drives the full handshake to
// transport-ready and black-boxes both transports.

fn handshake_n(c: &mut Criterion) {
    let mut g = c.benchmark_group(group_name("handshake_N"));

    g.bench_function(BenchmarkId::new("hiss", "N"), |b| {
        hiss::noise! { pub N<X25519, AesGcm, Sha256> { <- s ... -> e, es } }
        b.iter_batched(
            || {
                let mut p = provider();
                let r_static = p.generate::<X25519>().unwrap();
                let r_pub = p.public(&r_static).unwrap();
                (r_static, r_pub, provider(), provider())
            },
            |(r_static, r_pub, i_provider, r_provider)| {
                let (msg1, i_t) = N::initiator(i_provider, &[], r_pub)
                    .write_message_1()
                    .unwrap();
                let r_t = N::responder(r_provider, &[], r_static)
                    .unwrap()
                    .read_message_1(&msg1)
                    .unwrap();
                black_box((i_t, r_t))
            },
            BatchSize::SmallInput,
        );
    });

    let protocol = snow_protocol("N");
    g.bench_function(BenchmarkId::new("snow", "N"), |b| {
        b.iter_batched(
            || {
                snow::Builder::new(protocol.clone())
                    .generate_keypair()
                    .unwrap()
            },
            |kp| {
                let mut initiator = snow::Builder::new(protocol.clone())
                    .remote_public_key(&kp.public)
                    .unwrap()
                    .build_initiator()
                    .unwrap();
                let mut msg = [0u8; 256];
                let n = initiator.write_message(&[], &mut msg).unwrap();

                let mut responder = snow::Builder::new(protocol.clone())
                    .local_private_key(&kp.private)
                    .unwrap()
                    .build_responder()
                    .unwrap();
                let mut buf = [0u8; 256];
                responder.read_message(&msg[..n], &mut buf).unwrap();

                black_box((
                    initiator.into_transport_mode().unwrap(),
                    responder.into_transport_mode().unwrap(),
                ))
            },
            BatchSize::SmallInput,
        );
    });

    g.finish();
}

/// snow IK / XX: initiator + responder static keypairs, two or three
/// messages. `ik` selects whether the initiator pre-knows the responder's
/// static (IK) or not (XX); `msgs` is the message count.
fn bench_multi_snow(
    g: &mut criterion::BenchmarkGroup<'_, criterion::measurement::WallTime>,
    pattern: &str,
    ik: bool,
    msgs: usize,
) {
    let protocol = snow_protocol(pattern);
    g.bench_function(BenchmarkId::new("snow", pattern), |b| {
        b.iter_batched(
            || {
                let i_kp = snow::Builder::new(protocol.clone())
                    .generate_keypair()
                    .unwrap();
                let r_kp = snow::Builder::new(protocol.clone())
                    .generate_keypair()
                    .unwrap();
                (i_kp, r_kp)
            },
            |(i_kp, r_kp)| {
                let mut ib = snow::Builder::new(protocol.clone())
                    .local_private_key(&i_kp.private)
                    .unwrap();
                if ik {
                    ib = ib.remote_public_key(&r_kp.public).unwrap();
                }
                let mut initiator = ib.build_initiator().unwrap();
                let mut responder = snow::Builder::new(protocol.clone())
                    .local_private_key(&r_kp.private)
                    .unwrap()
                    .build_responder()
                    .unwrap();

                let mut a = [0u8; 512];
                let mut buf = [0u8; 512];
                // Alternate initiator → responder → initiator …
                let (mut sender, mut receiver): (
                    &mut snow::HandshakeState,
                    &mut snow::HandshakeState,
                ) = (&mut initiator, &mut responder);
                for _ in 0..msgs {
                    let n = sender.write_message(&[], &mut a).unwrap();
                    receiver.read_message(&a[..n], &mut buf).unwrap();
                    std::mem::swap(&mut sender, &mut receiver);
                }

                black_box((
                    initiator.into_transport_mode().unwrap(),
                    responder.into_transport_mode().unwrap(),
                ))
            },
            BatchSize::SmallInput,
        );
    });
}

fn handshake_ik(c: &mut Criterion) {
    let mut g = c.benchmark_group(group_name("handshake_IK"));

    g.bench_function(BenchmarkId::new("hiss", "IK"), |b| {
        hiss::noise! { pub IK<X25519, AesGcm, Sha256> { <- s ... -> e, es, s, ss <- e, ee, se } }
        b.iter_batched(
            || {
                let mut p = provider();
                let i_static = p.generate::<X25519>().unwrap();
                let r_static = p.generate::<X25519>().unwrap();
                let r_pub = p.public(&r_static).unwrap();
                (i_static, r_static, r_pub, provider(), provider())
            },
            |(i_static, r_static, r_pub, i_provider, r_provider)| {
                // msg1: -> e, es, s, ss
                let (msg1, i_hs) = IK::initiator(i_provider, &[], r_pub)
                    .write_message_1(i_static)
                    .unwrap();
                let r_hs = IK::responder(r_provider, &[], r_static)
                    .unwrap()
                    .read_message_1(&msg1)
                    .unwrap();

                // msg2: <- e, ee, se
                let (msg2, r_t) = r_hs.write_message_2().unwrap();
                let i_t = i_hs.read_message_2(&msg2).unwrap();
                black_box((i_t, r_t))
            },
            BatchSize::SmallInput,
        );
    });

    bench_multi_snow(&mut g, "IK", true, 2);
    g.finish();
}

fn handshake_xx(c: &mut Criterion) {
    let mut g = c.benchmark_group(group_name("handshake_XX"));

    g.bench_function(BenchmarkId::new("hiss", "XX"), |b| {
        hiss::noise! { pub XX<X25519, AesGcm, Sha256> { -> e <- e, ee, s, es -> s, se } }
        b.iter_batched(
            || {
                let mut p = provider();
                let i_static = p.generate::<X25519>().unwrap();
                let r_static = p.generate::<X25519>().unwrap();
                (i_static, r_static, provider(), provider())
            },
            |(i_static, r_static, i_provider, r_provider)| {
                // msg1: -> e
                let (msg1, i_hs) = XX::initiator(i_provider, &[]).write_message_1().unwrap();
                let r_hs = XX::responder(r_provider, &[])
                    .read_message_1(&msg1)
                    .unwrap();

                // msg2: <- e, ee, s, es
                let (msg2, r_hs) = r_hs.write_message_2(r_static).unwrap();
                let i_hs = i_hs.read_message_2(&msg2).unwrap();

                // msg3: -> s, se
                let (msg3, i_t) = i_hs.write_message_3(i_static).unwrap();
                let r_t = r_hs.read_message_3(&msg3).unwrap();
                black_box((i_t, r_t))
            },
            BatchSize::SmallInput,
        );
    });

    bench_multi_snow(&mut g, "XX", false, 3);
    g.finish();
}

// ── Transport ───────────────────────────────────────────────────────────
//
// The handshake (N) runs once per arm, outside every measured region; the
// timed routines do nothing but encrypt and decrypt. Each (arm, size) cell
// gets its own transport pair so one cell's unmatched sends cannot
// desynchronise another's nonce counters.

/// Plaintext sizes: fixed-cost-dominated, the 1 KiB `comparison.rs` uses,
/// a mid-size, and the largest a Noise record can carry (65535 − 16).
const SIZES: [(usize, &str); 4] = [
    (64, "64B"),
    (1024, "1KiB"),
    (16 * 1024, "16KiB"),
    (65535 - 16, "65519B"),
];

/// One completed `N` handshake over the suite, as hiss's `(sender, receiver)`.
///
/// A macro rather than a function only because the `noise!` invocation has
/// to live somewhere, and its generated `N` must not collide with the
/// handshake group's.
macro_rules! hiss_pair {
    () => {{
        hiss::noise! { pub N<X25519, AesGcm, Sha256> { <- s ... -> e, es } }
        let mut p = provider();
        let r_static = p.generate::<X25519>().unwrap();
        let r_pub = p.public(&r_static).unwrap();
        let (msg1, i_t) = N::initiator(provider(), &[], r_pub)
            .write_message_1()
            .unwrap();
        let r_t = N::responder(provider(), &[], r_static)
            .unwrap()
            .read_message_1(&msg1)
            .unwrap();
        (i_t, r_t)
    }};
}

/// The `snow` equivalent of [`hiss_pair`], same pattern and suite.
fn snow_pair() -> (snow::TransportState, snow::TransportState) {
    let protocol = snow_protocol("N");
    let r_kp = snow::Builder::new(protocol.clone())
        .generate_keypair()
        .unwrap();
    let mut initiator = snow::Builder::new(protocol.clone())
        .remote_public_key(&r_kp.public)
        .unwrap()
        .build_initiator()
        .unwrap();
    let mut msg = [0u8; 256];
    let n = initiator.write_message(&[], &mut msg).unwrap();
    let mut responder = snow::Builder::new(protocol)
        .local_private_key(&r_kp.private)
        .unwrap()
        .build_responder()
        .unwrap();
    let mut buf = [0u8; 256];
    responder.read_message(&msg[..n], &mut buf).unwrap();
    (
        initiator.into_transport_mode().unwrap(),
        responder.into_transport_mode().unwrap(),
    )
}

fn transport_round_trip(c: &mut Criterion) {
    let mut g = c.benchmark_group(group_name("transport_round_trip"));
    for (size, label) in SIZES {
        g.throughput(Throughput::Bytes(size as u64));
        let plaintext = vec![0x42u8; size];

        g.bench_with_input(BenchmarkId::new("hiss", label), &size, |b, &size| {
            let (mut send, mut recv) = hiss_pair!();
            let mut ct = vec![0u8; size + 16];
            let mut pt = vec![0u8; size];
            b.iter(|| {
                let n = send.send(&plaintext, &mut ct).unwrap();
                let m = recv.receive(&ct[..n], &mut pt).unwrap();
                black_box(m)
            });
        });
        g.bench_with_input(BenchmarkId::new("snow", label), &size, |b, &size| {
            let (mut send, mut recv) = snow_pair();
            let mut ct = vec![0u8; size + 16];
            let mut pt = vec![0u8; size];
            b.iter(|| {
                let n = send.write_message(&plaintext, &mut ct).unwrap();
                let m = recv.read_message(&ct[..n], &mut pt).unwrap();
                black_box(m)
            });
        });
    }
    g.finish();
}

fn transport_encrypt(c: &mut Criterion) {
    let mut g = c.benchmark_group(group_name("transport_encrypt"));
    for (size, label) in SIZES {
        g.throughput(Throughput::Bytes(size as u64));
        let plaintext = vec![0x42u8; size];

        g.bench_with_input(BenchmarkId::new("hiss", label), &size, |b, &size| {
            let (mut send, _recv) = hiss_pair!();
            let mut ct = vec![0u8; size + 16];
            b.iter(|| black_box(send.send(&plaintext, &mut ct).unwrap()));
        });
        g.bench_with_input(BenchmarkId::new("snow", label), &size, |b, &size| {
            let (mut send, _recv) = snow_pair();
            let mut ct = vec![0u8; size + 16];
            b.iter(|| black_box(send.write_message(&plaintext, &mut ct).unwrap()));
        });
    }
    g.finish();
}

fn transport_decrypt(c: &mut Criterion) {
    let mut g = c.benchmark_group(group_name("transport_decrypt"));
    for (size, label) in SIZES {
        g.throughput(Throughput::Bytes(size as u64));
        let plaintext = vec![0x42u8; size];

        // `iter_batched`: the setup encrypts (unmeasured) and the routine
        // decrypts. Per iteration, not once: a Noise transport advances its
        // nonce on every message, so the same ciphertext cannot be decrypted
        // twice, and the sender's counter and the receiver's stay in lockstep
        // precisely because setup and routine run one-for-one. The setup
        // returns an owned `Vec` because both closures would otherwise need
        // `&mut` to one buffer; the allocation is in the unmeasured half.
        g.bench_with_input(BenchmarkId::new("hiss", label), &size, |b, &size| {
            let (mut send, mut recv) = hiss_pair!();
            b.iter_batched(
                || {
                    let mut ct = vec![0u8; size + 16];
                    let n = send.send(&plaintext, &mut ct).unwrap();
                    ct.truncate(n);
                    ct
                },
                |ct| {
                    let mut pt = vec![0u8; size];
                    black_box(recv.receive(&ct, &mut pt).unwrap())
                },
                BatchSize::SmallInput,
            );
        });
        g.bench_with_input(BenchmarkId::new("snow", label), &size, |b, &size| {
            let (mut send, mut recv) = snow_pair();
            b.iter_batched(
                || {
                    let mut ct = vec![0u8; size + 16];
                    let n = send.write_message(&plaintext, &mut ct).unwrap();
                    ct.truncate(n);
                    ct
                },
                |ct| {
                    let mut pt = vec![0u8; size];
                    black_box(recv.read_message(&ct, &mut pt).unwrap())
                },
                BatchSize::SmallInput,
            );
        });
    }
    g.finish();
}

criterion_group!(
    benches,
    handshake_n,
    handshake_ik,
    handshake_xx,
    transport_round_trip,
    transport_encrypt,
    transport_decrypt
);
criterion_main!(benches);
