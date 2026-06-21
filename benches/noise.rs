//! Handshake and transport benchmarks for the hiss Noise implementation,
//! compared against `snow` where the curve is supported.
//!
//! # What is measured
//!
//! Each handshake benchmark drives a *complete* handshake (all messages,
//! both parties) to transport-ready state. Everything that is not
//! per-handshake crypto is built in the **unmeasured** `iter_batched` setup:
//! the long-lived static keys, the two providers (so RNG seeding —
//! `StdRng::from_os_rng()`, a kernel-entropy syscall — is *not* timed), and
//! the in-memory I/O endpoints. The measured routine is therefore the
//! handshake itself: ephemeral key generation, the Diffie–Hellman
//! operations, and the symmetric ratchet. The bulk-transport benchmark is
//! separate.
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
//! # Two caveats on the hiss-vs-snow comparison
//!
//! * **RNG strategy.** hiss draws ephemeral randomness from a `StdRng`
//!   (a ChaCha PRNG) seeded *once* in setup, so its measured region performs
//!   no OS-entropy syscalls. snow uses its internal `OsRng` per ephemeral,
//!   which *is* in its measured region — a small, inherent difference in the
//!   two libraries' default RNG handling, slightly in hiss's favour.
//! * **I/O model.** hiss is driven through its *real* blocking
//!   `SyncHandshake` driver, which frames messages and reads/writes them over
//!   an in-memory endpoint ([`Vec`]/[`Cursor`] for one-way N, a bidirectional
//!   [`BenchPipe`] for IK/XX). snow writes/reads messages straight into flat
//!   byte buffers. The in-memory framing is on the order of nanoseconds for
//!   the ~100–200-byte handshake messages, negligible beside the
//!   tens-to-hundreds of microseconds of elliptic-curve work.

use criterion::{BatchSize, BenchmarkId, Criterion, criterion_group, criterion_main};
use std::hint::black_box;

use hiss::noise::*;
use hiss::provider::EphemeralOnly;
use hiss::provider::ProviderExt;
use rand::{SeedableRng, rngs::StdRng};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::io::Cursor;
use std::rc::Rc;

/// A fresh software provider seeded from OS entropy. Built in unmeasured
/// setup so the `from_os_rng()` syscall never lands in a timed routine.
fn provider() -> EphemeralOnly<StdRng> {
    EphemeralOnly::new(StdRng::from_os_rng())
}

// ── In-memory pipe for multi-message handshakes ─────────────────

/// A linked in-memory `Read + Write` endpoint pair; `a`'s writes are `b`'s
/// reads and vice versa. Lets a multi-message hiss↔hiss handshake run
/// interleaved on one thread over the blocking driver. Allocated in setup,
/// so only the reads/writes — not the `Rc`/`RefCell`/`VecDeque` setup — are
/// timed.
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
        // Bulk-drain rather than per-byte pop_front.
        for (slot, byte) in buf.iter_mut().zip(q.drain(..n)) {
            *slot = byte;
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

// ── hiss handshake drivers (one macro per pattern, generic over curve) ──
//
// Each expands to a grouped benchmark for one (pattern, curve). Static keys,
// providers, and I/O endpoints are minted in `iter_batched` setup
// (unmeasured); the routine drives the full handshake to transport-ready and
// black-boxes the two transports.

/// N — `-> e, es`. The initiator seals msg1 into a `Vec`; the responder opens
/// it from a `Cursor`. Only the responder has a (pre-known) static.
macro_rules! bench_n_hiss {
    ($group:expr, $curve:ty, $label:expr) => {
        $group.bench_function(BenchmarkId::new("hiss", $label), |b| {
            b.iter_batched(
                || {
                    let mut p = provider();
                    let r_static = p.generate::<$curve>().unwrap();
                    let r_pub = p.public(&r_static).unwrap();
                    (r_static, r_pub, provider(), provider())
                },
                |(r_static, r_pub, i_provider, r_provider)| {
                    type Proto = Noise<pattern::N, $curve, ChaChaPoly, Blake2b>;
                    let sealer = SyncHandshake::<Proto, Initiator, _, _, _, _>::initiate(
                        i_provider,
                        &[],
                        Vec::new(),
                    )
                    .set_rs(r_pub);
                    let (i_t, wire) = sealer.e().unwrap().es().unwrap().into_parts();

                    let opener = SyncHandshake::<Proto, Responder, _, _, _, _>::respond(
                        r_provider,
                        &[],
                        Cursor::new(wire),
                    )
                    .set_s(r_static)
                    .unwrap();
                    let (_, recv) = opener.recv().e().unwrap();
                    let (r_t, _) = recv.es().unwrap().into_parts();
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
    ($group:expr, $curve:ty, $label:expr) => {
        $group.bench_function(BenchmarkId::new("hiss", $label), |b| {
            b.iter_batched(
                || {
                    let mut p = provider();
                    let i_static = p.generate::<$curve>().unwrap();
                    let r_static = p.generate::<$curve>().unwrap();
                    let r_pub = p.public(&r_static).unwrap();
                    let (i_pipe, r_pipe) = BenchPipe::pair();
                    (
                        i_static,
                        r_static,
                        r_pub,
                        provider(),
                        provider(),
                        i_pipe,
                        r_pipe,
                    )
                },
                |(i_static, r_static, r_pub, i_provider, r_provider, i_pipe, r_pipe)| {
                    type Proto = Noise<pattern::IK, $curve, ChaChaPoly, Blake2b>;
                    let i_hs = SyncHandshake::<Proto, Initiator, _, _, _, _>::initiate(
                        i_provider,
                        &[],
                        i_pipe,
                    )
                    .set_rs(r_pub);
                    let r_hs = SyncHandshake::<Proto, Responder, _, _, _, _>::respond(
                        r_provider,
                        &[],
                        r_pipe,
                    )
                    .set_s(r_static)
                    .unwrap();

                    // msg1: -> e, es, s, ss
                    let i_hs = i_hs
                        .e()
                        .unwrap()
                        .es()
                        .unwrap()
                        .s(i_static)
                        .unwrap()
                        .ss()
                        .unwrap();
                    let (_, recv) = r_hs.recv().e().unwrap();
                    let recv = recv.es().unwrap();
                    let (_, recv) = recv.s().unwrap();
                    let r_hs = recv.ss().unwrap();

                    // msg2: <- e, ee, se
                    let (r_t, _) = r_hs.e().unwrap().ee().unwrap().se().unwrap().into_parts();
                    let (_, recv) = i_hs.recv().e().unwrap();
                    let (i_t, _) = recv.ee().unwrap().se().unwrap().into_parts();
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
    ($group:expr, $curve:ty, $label:expr) => {
        $group.bench_function(BenchmarkId::new("hiss", $label), |b| {
            b.iter_batched(
                || {
                    let mut p = provider();
                    let i_static = p.generate::<$curve>().unwrap();
                    let r_static = p.generate::<$curve>().unwrap();
                    let (i_pipe, r_pipe) = BenchPipe::pair();
                    (i_static, r_static, provider(), provider(), i_pipe, r_pipe)
                },
                |(i_static, r_static, i_provider, r_provider, i_pipe, r_pipe)| {
                    type Proto = Noise<pattern::XX, $curve, ChaChaPoly, Blake2b>;
                    let i_hs = SyncHandshake::<Proto, Initiator, _, _, _, _>::initiate(
                        i_provider,
                        &[],
                        i_pipe,
                    );
                    let r_hs = SyncHandshake::<Proto, Responder, _, _, _, _>::respond(
                        r_provider,
                        &[],
                        r_pipe,
                    );

                    // msg1: -> e
                    let i_hs = i_hs.e().unwrap();
                    let (_, recv) = r_hs.recv().e().unwrap();

                    // msg2: <- e, ee, s, es
                    let r_hs = recv
                        .e()
                        .unwrap()
                        .ee()
                        .unwrap()
                        .s(r_static)
                        .unwrap()
                        .es()
                        .unwrap();
                    let (_, recv) = i_hs.recv().e().unwrap();
                    let recv = recv.ee().unwrap();
                    let (_, recv) = recv.s().unwrap();
                    let i_hs = recv.es().unwrap();

                    // msg3: -> s, se
                    let (i_t, _) = i_hs.s(i_static).unwrap().se().unwrap().into_parts();
                    let (_, recv) = r_hs.recv().s().unwrap();
                    let (r_t, _) = recv.se().unwrap().into_parts();
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
        type Proto = Noise<pattern::N, P256, ChaChaPoly, Blake2b>;
        let sealer =
            SyncHandshake::<Proto, Initiator, _, _, _, _>::initiate(provider(), &[], Vec::new())
                .set_rs(r_pub);
        let (i_t, wire) = sealer.e().unwrap().es().unwrap().into_parts();
        let opener = SyncHandshake::<Proto, Responder, _, _, _, _>::respond(
            provider(),
            &[],
            Cursor::new(wire),
        )
        .set_s(r_static)
        .unwrap();
        let (_, recv) = opener.recv().e().unwrap();
        let (r_t, _) = recv.es().unwrap().into_parts();
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
