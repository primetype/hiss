//! Noise **transport** throughput with AES-GCM: hiss vs `snow`.
//!
//! Modelled on `hiss-interop/benches/comparison.rs`, deliberately and closely.
//! That bench's `transport_1KiB` group is the established measurement of Noise
//! bulk crypto in this repo; this one reproduces its shape so the two sets of
//! numbers can be read side by side rather than each on its own scale.
//!
//! # What is measured
//!
//! Post-handshake transport only. Each arm's handshake runs once, outside the
//! measured region, leaving a completed `(sender, receiver)` transport pair;
//! the timed routines then do nothing but encrypt and decrypt. This mirrors
//! `comparison.rs`, whose transport section does the same and notes that the
//! result is "curve-independent" — which is why the curve substitution below
//! costs nothing.
//!
//! Three groups:
//!
//! | Group | Routine |
//! |---|---|
//! | `transport_1KiB` | send **and** receive, one round trip per iteration — the exact shape `comparison.rs` uses, so this group is the directly comparable one |
//! | `transport_1KiB_encrypt` | send only |
//! | `transport_1KiB_decrypt` | receive only; the ciphertext is produced in unmeasured `iter_batched` setup |
//!
//! The split exists because a fused round trip cannot tell you which side an
//! AEAD is fast on, and AES-GCM's asymmetry (a per-message key schedule on
//! both sides, GHASH either way) is exactly the sort of thing that hides in a
//! sum. The fused group is kept anyway, unchanged in shape, because dropping
//! it would break comparability with the bench this one mirrors.
//!
//! # Arms
//!
//! 1. **hiss / AESGCM** — this crate's [`AesGcm`] `Cipher`, over cryptoxide
//!    **git master**.
//! 2. **snow / AESGCM** — `snow`'s default resolver, backed by RustCrypto's
//!    `aes_gcm::Aes256Gcm`. An independently written AES-GCM.
//! 3. **hiss / ChaChaPoly** — hiss's shipped cipher, over the **registry**
//!    cryptoxide. A reference arm, so the AEAD-vs-AEAD picture *inside* hiss
//!    is visible in the same run rather than inferred across two.
//!
//! There is deliberately no fourth `snow / ChaChaPoly` arm, tempting as the
//! 2×2 is: this crate's `snow` dependency does not list
//! `use-chacha20poly1305`, on the stated grounds that ChaChaPoly interop is
//! `hiss-interop`'s job. Benchmarking it here would make that statement false
//! in practice while leaving it true in the manifest. `hiss-interop`'s
//! `transport_1KiB` already carries the snow/ChaChaPoly number, and this
//! bench's shape is what makes it readable next to these.
//!
//! # Which AES you are measuring
//!
//! cryptoxide selects its AES backend at compile time —
//! `#[cfg(all(target_arch = "aarch64", target_feature = "aes"))]` picks ARMv8
//! crypto-extension intrinsics, everything else gets the portable
//! constant-time fixslice implementation. Measured: `aes` is a default target
//! feature on **`aarch64-apple-darwin` only** — not on
//! `x86_64-unknown-linux-gnu` and, notably, **not** on
//! `aarch64-unknown-linux-gnu`.
//!
//! So the same command measures different code depending on where it runs:
//!
//! | Where | hiss/AESGCM arm is measuring |
//! |---|---|
//! | a Mac (`aarch64-apple-darwin`) | **hardware** AES intrinsics |
//! | CI's `ubuntu-latest` (x86_64) | **portable** reference AES |
//!
//! `snow`'s RustCrypto `aes-gcm` makes its own runtime/compile-time choice
//! independently, so a hiss-vs-snow gap on one machine does not transfer to
//! the other. **Never compare a number from one row against a number from the
//! other.** Always state the host alongside the result.
//!
//! # Caveat inherited from `comparison.rs`
//!
//! Nothing here is in a handshake, so that bench's RNG caveat does not apply:
//! no ephemeral keys are generated inside any measured region. What does apply
//! is that both sides encrypt and decrypt into flat slices with no I/O
//! abstraction on either — an apples-to-apples symmetric-crypto comparison.

use criterion::{BatchSize, BenchmarkId, Criterion, criterion_group, criterion_main};
use std::hint::black_box;

use hiss::noise::{Blake2b, ChaChaPoly, X25519};
use hiss::provider::{EphemeralOnly, ProviderExt};
use hiss_aesgcm_lab::AesGcm;
use rand::rngs::StdRng;

/// One kibibyte, matching `hiss-interop`'s `transport_1KiB`.
const PLAINTEXT: [u8; 1024] = [0x42u8; 1024];
/// 1024 + 16-byte tag + headroom, as `comparison.rs` sizes it.
const CT_LEN: usize = 1056;

/// A fresh software provider seeded from OS entropy. Built outside every
/// measured region.
fn provider() -> EphemeralOnly<StdRng> {
    EphemeralOnly::new(rand::make_rng::<StdRng>())
}

/// Drive a complete `N` handshake and hand back the two transports.
///
/// `N` is the pattern `comparison.rs`'s transport section uses. The curve is
/// **X25519** where that bench uses P256, for one reason: transport throughput
/// is curve-independent (that bench says so itself), and P256 would oblige this
/// crate's `snow` dependency to carry `use-p256` for something no test needs.
/// The hash is `Blake2b`, as there. Neither choice touches the AEAD, which is
/// the only variable this bench is varying.
///
/// A macro rather than a function because each expansion needs its own
/// `noise!` invocation — the generated `N` types are distinct per cipher, and
/// the identifier must stay `N` since it *is* the protocol name mixed into the
/// handshake hash.
macro_rules! hiss_pair {
    ($cipher:ident) => {{
        let mut p = provider();
        let r_static = p.generate::<X25519>().unwrap();
        let r_pub = p.public(&r_static).unwrap();

        hiss::noise! { pub N<X25519, $cipher, Blake2b> { <- s ... -> e, es } }

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
fn snow_pair(suite: &str) -> (snow::TransportState, snow::TransportState) {
    let protocol: snow::params::NoiseParams = suite.parse().unwrap();
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

const SNOW_AESGCM: &str = "Noise_N_25519_AESGCM_BLAKE2b";

// ── Round trip: the group that mirrors `comparison.rs` ───────────

fn transport_round_trip(c: &mut Criterion) {
    let (mut h_send, mut h_recv) = hiss_pair!(AesGcm);
    let (mut c_send, mut c_recv) = hiss_pair!(ChaChaPoly);
    let (mut s_send, mut s_recv) = snow_pair(SNOW_AESGCM);

    let mut ct = [0u8; CT_LEN];
    let mut pt = [0u8; 1024];

    let mut g = c.benchmark_group("transport_1KiB");

    g.bench_function(BenchmarkId::new("hiss", "AESGCM"), |b| {
        b.iter(|| {
            let n = h_send.send(&PLAINTEXT, &mut ct).unwrap();
            let m = h_recv.receive(&ct[..n], &mut pt).unwrap();
            black_box(m)
        });
    });
    g.bench_function(BenchmarkId::new("snow", "AESGCM"), |b| {
        b.iter(|| {
            let n = s_send.write_message(&PLAINTEXT, &mut ct).unwrap();
            let m = s_recv.read_message(&ct[..n], &mut pt).unwrap();
            black_box(m)
        });
    });
    // Reference arm: hiss's shipped AEAD, same harness, same run.
    g.bench_function(BenchmarkId::new("hiss", "ChaChaPoly"), |b| {
        b.iter(|| {
            let n = c_send.send(&PLAINTEXT, &mut ct).unwrap();
            let m = c_recv.receive(&ct[..n], &mut pt).unwrap();
            black_box(m)
        });
    });

    g.finish();
}

// ── Encrypt side only ────────────────────────────────────────────

fn transport_encrypt(c: &mut Criterion) {
    // Fresh pairs: the groups must not share transports, or one group's
    // unmatched sends would desynchronise another group's nonce counters.
    let (mut h_send, _h_recv) = hiss_pair!(AesGcm);
    let (mut c_send, _c_recv) = hiss_pair!(ChaChaPoly);
    let (mut s_send, _s_recv) = snow_pair(SNOW_AESGCM);

    let mut ct = [0u8; CT_LEN];

    let mut g = c.benchmark_group("transport_1KiB_encrypt");

    g.bench_function(BenchmarkId::new("hiss", "AESGCM"), |b| {
        b.iter(|| black_box(h_send.send(&PLAINTEXT, &mut ct).unwrap()));
    });
    g.bench_function(BenchmarkId::new("snow", "AESGCM"), |b| {
        b.iter(|| black_box(s_send.write_message(&PLAINTEXT, &mut ct).unwrap()));
    });
    g.bench_function(BenchmarkId::new("hiss", "ChaChaPoly"), |b| {
        b.iter(|| black_box(c_send.send(&PLAINTEXT, &mut ct).unwrap()));
    });

    g.finish();
}

// ── Decrypt side only ────────────────────────────────────────────

fn transport_decrypt(c: &mut Criterion) {
    let (mut h_send, mut h_recv) = hiss_pair!(AesGcm);
    let (mut c_send, mut c_recv) = hiss_pair!(ChaChaPoly);
    let (mut s_send, mut s_recv) = snow_pair(SNOW_AESGCM);

    let mut g = c.benchmark_group("transport_1KiB_decrypt");

    // `iter_batched`: the setup encrypts (unmeasured) and the routine
    // decrypts. Doing it per-iteration rather than once is not optional — a
    // Noise transport advances its nonce on every message, so the same
    // ciphertext cannot be decrypted twice, and the sender's counter and the
    // receiver's stay in lockstep precisely because setup and routine run
    // one-for-one.
    //
    // The setup returns an owned `Vec` rather than writing into a shared
    // buffer because the two closures would otherwise both need `&mut` to it.
    // The allocation is in the unmeasured half.
    g.bench_function(BenchmarkId::new("hiss", "AESGCM"), |b| {
        b.iter_batched(
            || {
                let mut ct = vec![0u8; CT_LEN];
                let n = h_send.send(&PLAINTEXT, &mut ct).unwrap();
                ct.truncate(n);
                ct
            },
            |ct| {
                let mut pt = [0u8; 1024];
                black_box(h_recv.receive(&ct, &mut pt).unwrap())
            },
            BatchSize::SmallInput,
        );
    });
    g.bench_function(BenchmarkId::new("snow", "AESGCM"), |b| {
        b.iter_batched(
            || {
                let mut ct = vec![0u8; CT_LEN];
                let n = s_send.write_message(&PLAINTEXT, &mut ct).unwrap();
                ct.truncate(n);
                ct
            },
            |ct| {
                let mut pt = [0u8; 1024];
                black_box(s_recv.read_message(&ct, &mut pt).unwrap())
            },
            BatchSize::SmallInput,
        );
    });
    g.bench_function(BenchmarkId::new("hiss", "ChaChaPoly"), |b| {
        b.iter_batched(
            || {
                let mut ct = vec![0u8; CT_LEN];
                let n = c_send.send(&PLAINTEXT, &mut ct).unwrap();
                ct.truncate(n);
                ct
            },
            |ct| {
                let mut pt = [0u8; 1024];
                black_box(c_recv.receive(&ct, &mut pt).unwrap())
            },
            BatchSize::SmallInput,
        );
    });

    g.finish();
}

criterion_group!(
    benches,
    transport_round_trip,
    transport_encrypt,
    transport_decrypt
);
criterion_main!(benches);
