//! Handshake and transport benchmarks comparing hiss against `snow`.
//!
//! This is the *comparison* bench, and it lives in `hiss-interop` because it
//! links `snow`. hiss keeps a hiss-only bench (`benches/noise.rs`) so its
//! `cargo bench` release gate still builds and runs real handshakes; this one
//! carries both arms.
//!
//! **The `*_hiss` macros below are duplicated from that bench, deliberately.**
//! Criterion can only put two implementations in one comparison group if it
//! measures them in one process against one target directory — two runs of two
//! crates is not a comparison. The `push: main` trigger on the Interop
//! workflow is what bounds the drift that duplication invites.
//!
//! # What is measured
//!
//! Each handshake benchmark drives a *complete* handshake (all messages,
//! both parties) to transport-ready state. Everything that is not
//! per-handshake crypto is built in the **unmeasured** `iter_batched` setup:
//! the long-lived static keys and the two providers, so RNG seeding —
//! `StdRng::from_os_rng()`, a kernel-entropy syscall — is *not* timed. The
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
//! `snow` is benchmarked alongside hiss for **P256** and **X25519**. It
//! recognises `448` in the spec but ships **no Curve448 implementation** —
//! its resolver returns `None`, so building a `448` handshake fails with
//! `Init(GetDhImpl)`. X448 is therefore hiss-only: there is no snow row to
//! compare against.
//!
//! # One caveat on the hiss-vs-snow comparison
//!
//! * **RNG strategy.** hiss draws ephemeral randomness from a `StdRng`
//!   (a ChaCha PRNG) seeded *once* in setup, so its measured region performs
//!   no OS-entropy syscalls. snow uses its internal `OsRng` per ephemeral,
//!   which *is* in its measured region — a small, inherent difference in the
//!   two libraries' default RNG handling, slightly in hiss's favour.
//!
//! There used to be a second caveat here, about hiss being driven through a
//! streaming I/O driver while snow wrote into flat buffers. It no longer
//! applies: the `noise!` handshakes below return each message as a
//! fixed-size array and perform no I/O, so both implementations are now
//! measured writing into plain memory. Numbers from before that change are
//! not comparable with numbers after it.

use criterion::{BatchSize, BenchmarkId, Criterion, criterion_group, criterion_main};
use std::hint::black_box;

use hiss::noise::*;
use hiss::provider::EphemeralOnly;
use hiss::provider::ProviderExt;
use rand::{SeedableRng, rngs::StdRng};

/// A fresh software provider seeded from OS entropy. Built in unmeasured
/// setup so the `from_os_rng()` syscall never lands in a timed routine.
fn provider() -> EphemeralOnly<StdRng> {
    EphemeralOnly::new(StdRng::from_os_rng())
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

// ── snow handshake drivers (parameterised by protocol string) ──────────
//
// snow's static keypairs are minted in setup; the routine builds the handshake
// states and drives the messages. snow's ephemeral RNG (`OsRng`) is internal,
// so unlike hiss it stays in the measured region (see the module-level caveat).

/// snow N: one responder static keypair, single message.
macro_rules! bench_n_snow {
    ($group:expr, $proto:expr, $label:expr) => {{
        let protocol: snow::params::NoiseParams = $proto.parse().unwrap();
        $group.bench_function(BenchmarkId::new("snow", $label), |b| {
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
    }};
}

/// snow IK / XX: initiator + responder static keypairs, two or three messages.
/// `$ik` selects whether the initiator pre-knows the responder's static (IK)
/// or not (XX), and `$msgs` is the message count.
macro_rules! bench_multi_snow {
    ($group:expr, $proto:expr, $label:expr, ik = $ik:expr, msgs = $msgs:expr) => {{
        let protocol: snow::params::NoiseParams = $proto.parse().unwrap();
        $group.bench_function(BenchmarkId::new("snow", $label), |b| {
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
                    if $ik {
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
                    for _ in 0..$msgs {
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
    }};
}

// ── Benchmark groups: one per pattern, curve × impl matrix ─────────────

fn handshakes_n(c: &mut Criterion) {
    let mut g = c.benchmark_group("handshake_N");
    bench_n_hiss!(g, P256, "P256");
    bench_n_hiss!(g, X25519, "X25519");
    bench_n_hiss!(g, X448, "X448"); // no snow `448` to compare against
    bench_n_snow!(g, "Noise_N_P256_ChaChaPoly_BLAKE2b", "P256");
    bench_n_snow!(g, "Noise_N_25519_ChaChaPoly_BLAKE2b", "X25519");
    g.finish();
}

fn handshakes_ik(c: &mut Criterion) {
    let mut g = c.benchmark_group("handshake_IK");
    bench_ik_hiss!(g, P256, "P256");
    bench_ik_hiss!(g, X25519, "X25519");
    bench_ik_hiss!(g, X448, "X448");
    bench_multi_snow!(
        g,
        "Noise_IK_P256_ChaChaPoly_BLAKE2b",
        "P256",
        ik = true,
        msgs = 2
    );
    bench_multi_snow!(
        g,
        "Noise_IK_25519_ChaChaPoly_BLAKE2b",
        "X25519",
        ik = true,
        msgs = 2
    );
    g.finish();
}

fn handshakes_xx(c: &mut Criterion) {
    let mut g = c.benchmark_group("handshake_XX");
    bench_xx_hiss!(g, P256, "P256");
    bench_xx_hiss!(g, X25519, "X25519");
    bench_xx_hiss!(g, X448, "X448");
    bench_multi_snow!(
        g,
        "Noise_XX_P256_ChaChaPoly_BLAKE2b",
        "P256",
        ik = false,
        msgs = 3
    );
    bench_multi_snow!(
        g,
        "Noise_XX_25519_ChaChaPoly_BLAKE2b",
        "X25519",
        ik = false,
        msgs = 3
    );
    g.finish();
}

// ── Bulk transport throughput (curve-independent: ChaCha20-Poly1305) ───
//
// Both sides encrypt/decrypt into flat slices — no I/O abstraction on either —
// so this is an apples-to-apples symmetric-crypto comparison.

fn transport(c: &mut Criterion) {
    // hiss: set up a completed N/P256 handshake, then measure transport only.
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

    // snow equivalent.
    let (mut s_send, mut s_recv) = {
        let protocol: snow::params::NoiseParams =
            "Noise_N_P256_ChaChaPoly_BLAKE2b".parse().unwrap();
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
        let mut responder = snow::Builder::new(protocol.clone())
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
    g.bench_function(BenchmarkId::new("snow", "ChaChaPoly"), |b| {
        b.iter(|| {
            let n = s_send.write_message(&plaintext, &mut ct).unwrap();
            let m = s_recv.read_message(&ct[..n], &mut pt).unwrap();
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
