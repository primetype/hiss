//! Handshake and transport benchmarks for the hiss Noise implementation.
//!
//! hiss-only, by construction: the `snow` comparison lives in
//! `hiss-interop/benches/comparison.rs`, which is where `snow` is a
//! dependency. This bench is the one the release gate runs, so what it has to
//! catch is a perf-shaped compile break or a regression in hiss itself —
//! neither of which needs a second implementation present.
//!
//! # What is measured
//!
//! Each handshake benchmark drives a *complete* handshake (all messages,
//! both parties) to transport-ready state. Everything that is not
//! per-handshake crypto is built in the **unmeasured** `iter_batched` setup:
//! the long-lived static keys and the two providers, so RNG seeding —
//! `rand::make_rng::<StdRng>()`, a kernel-entropy syscall — is *not* timed. The
//! measured routine is therefore the handshake itself: ephemeral key
//! generation, the Diffie–Hellman operations, and the symmetric ratchet. The
//! bulk-transport benchmark is separate.
//!
//! # Matrix
//!
//! Three patterns spanning the cost range — **N** (one-way, one DH), **IK**
//! (mutual, known static), **XX** (mutual, statics exchanged in-band) — each
//! over three DH curves: **P256**, **X25519**, **X448**.
//!
//! Numbers are not comparable across the point where the streaming I/O driver
//! was removed: the `noise!` handshakes below return each message as a
//! fixed-size array and perform no I/O, where the old driver wrote through a
//! `Read`/`Write` pair.

use criterion::{BatchSize, BenchmarkId, Criterion, criterion_group, criterion_main};
use std::hint::black_box;

use hiss::noise::*;
use hiss::provider::EphemeralOnly;
use hiss::provider::ProviderExt;
use rand::rngs::StdRng;

/// A fresh software provider seeded from OS entropy. Built in unmeasured
/// setup so the `make_rng()` syscall never lands in a timed routine.
fn provider() -> EphemeralOnly<StdRng> {
    EphemeralOnly::new(rand::make_rng::<StdRng>())
}

// ── hiss handshake drivers (one macro per pattern, generic over curve) ──
//
// Each expands to a grouped benchmark for one (pattern, curve). Static keys
// and providers are minted in `iter_batched` setup (unmeasured); the routine
// drives the full handshake to transport-ready and black-boxes the two
// transports.
//
// The curve is an `ident` rather than a `ty` because `noise!` parses the
// suite as a `syn::Path`: a `$curve:ty` metavariable arrives as one opaque
// token and will not parse there.
//
// Each `noise!` sits inside its own `bench_function` closure, so the three
// curve instantiations of a pattern do not collide despite sharing a name —
// and the name has to be the canonical pattern name regardless, since it
// becomes the Noise protocol name.

/// N — `-> e, es`. One message, which is also the last, so writing it yields
/// the transport directly. Only the responder has a (pre-known) static.
macro_rules! bench_n_hiss {
    ($group:expr, $curve:ident, $label:expr) => {
        $group.bench_function(BenchmarkId::new("hiss", $label), |b| {
            hiss::noise! { pub N<$curve, ChaChaPoly, Blake2b> { <- s ... -> e, es } }
            b.iter_batched(
                || {
                    let mut p = provider();
                    let r_static = p.generate::<$curve>().unwrap();
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
    };
}

/// IK — msg1 `-> e, es, s, ss`, msg2 `<- e, ee, se`. Both parties hold a
/// static; the initiator knows the responder's up front.
macro_rules! bench_ik_hiss {
    ($group:expr, $curve:ident, $label:expr) => {
        $group.bench_function(BenchmarkId::new("hiss", $label), |b| {
            hiss::noise! {
                pub IK<$curve, ChaChaPoly, Blake2b> { <- s ... -> e, es, s, ss <- e, ee, se }
            }
            b.iter_batched(
                || {
                    let mut p = provider();
                    let i_static = p.generate::<$curve>().unwrap();
                    let r_static = p.generate::<$curve>().unwrap();
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
    };
}

/// XX — msg1 `-> e`, msg2 `<- e, ee, s, es`, msg3 `-> s, se`. Neither static
/// is pre-known; both are sent encrypted in-band.
macro_rules! bench_xx_hiss {
    ($group:expr, $curve:ident, $label:expr) => {
        $group.bench_function(BenchmarkId::new("hiss", $label), |b| {
            hiss::noise! { pub XX<$curve, ChaChaPoly, Blake2b> { -> e <- e, ee, s, es -> s, se } }
            b.iter_batched(
                || {
                    let mut p = provider();
                    let i_static = p.generate::<$curve>().unwrap();
                    let r_static = p.generate::<$curve>().unwrap();
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
    };
}

// ── Benchmark groups: one per pattern, curve × impl matrix ─────────────

fn handshakes_n(c: &mut Criterion) {
    let mut g = c.benchmark_group("handshake_N");
    bench_n_hiss!(g, P256, "P256");
    bench_n_hiss!(g, X25519, "X25519");
    bench_n_hiss!(g, X448, "X448");
    g.finish();
}

fn handshakes_ik(c: &mut Criterion) {
    let mut g = c.benchmark_group("handshake_IK");
    bench_ik_hiss!(g, P256, "P256");
    bench_ik_hiss!(g, X25519, "X25519");
    bench_ik_hiss!(g, X448, "X448");
    g.finish();
}

fn handshakes_xx(c: &mut Criterion) {
    let mut g = c.benchmark_group("handshake_XX");
    bench_xx_hiss!(g, P256, "P256");
    bench_xx_hiss!(g, X25519, "X25519");
    bench_xx_hiss!(g, X448, "X448");
    g.finish();
}

// ── Bulk transport throughput (curve-independent: ChaCha20-Poly1305) ───
//
// Both sides encrypt and decrypt into flat slices, with no I/O abstraction in
// the measured region.

fn transport(c: &mut Criterion) {
    // Set up a completed N/P256 handshake, then measure transport only.
    let (mut h_send, mut h_recv) = {
        let mut p = provider();
        let r_static = p.generate::<P256>().unwrap();
        let r_pub = p.public(&r_static).unwrap();
        hiss::noise! { pub N<P256, ChaChaPoly, Blake2b> { <- s ... -> e, es } }
        let (msg1, i_t) = N::initiator(provider(), &[], r_pub)
            .write_message_1()
            .unwrap();
        let r_t = N::responder(provider(), &[], r_static)
            .unwrap()
            .read_message_1(&msg1)
            .unwrap();
        (i_t, r_t)
    };

    let plaintext = [0x42u8; 1024];
    let mut ct = [0u8; 1056]; // 1024 + 16 tag + headroom
    let mut pt = [0u8; 1024];

    let mut g = c.benchmark_group("transport_1KiB");
    g.bench_function(BenchmarkId::new("hiss", "ChaChaPoly"), |b| {
        b.iter(|| {
            let n = h_send.send(&plaintext, &mut ct).unwrap();
            let m = h_recv.receive(&ct[..n], &mut pt).unwrap();
            black_box(m)
        });
    });
    g.finish();
}

criterion_group!(
    benches,
    handshakes_n,
    handshakes_ik,
    handshakes_xx,
    transport
);
criterion_main!(benches);
