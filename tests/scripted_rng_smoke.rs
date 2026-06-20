//! Step-1 smoke test for the deterministic ephemeral-injection harness.
//!
//! Proves that running an `N` handshake over `EphemeralOnly<ScriptedRng>`
//! is byte-for-byte reproducible and that the on-wire ephemeral public key
//! is exactly `d·G` for the injected scalar `d`. This is the mechanism the
//! frozen Noise KAT vectors rely on to assert ciphertexts byte-for-byte.

mod common;
use common::ScriptedRng;

use hiss::noise::*;
use hiss::provider::{EphemeralOnly, ProviderExt};
use rand::{SeedableRng, rngs::StdRng};

type NoiseN = N;

/// A fixed, valid P-256 scalar (`0x1111…11` is nonzero and far below the
/// curve order `n`), used as the injected ephemeral private key.
const EPHEMERAL: [u8; 32] = [0x11; 32];

/// Seal one `N` message-1, injecting `EPHEMERAL` as the ephemeral key. The
/// responder static is derived from a fixed seed so the whole transcript is
/// determined by constants.
///
/// Driven over the blocking [`SyncHandshake`] driver with an in-memory `Vec`
/// sink: `EphemeralOnly` implements the synchronous `DhProvider`, so the
/// whole `N` initiator message (`e, es`) runs without an executor and the
/// captured `Vec` is exactly msg1.
fn seal_n_msg1() -> Vec<u8> {
    let mut responder = EphemeralOnly::new(StdRng::seed_from_u64(7));
    let responder_static = responder.generate::<P256>().unwrap();
    let responder_pub = responder.public(&responder_static).unwrap();

    let initiator = EphemeralOnly::new(ScriptedRng::new(&[&EPHEMERAL]));
    let hs = SyncHandshake::<NoiseN, Initiator, _, _, _, _>::initiate(initiator, &[], Vec::new())
        .set_rs(responder_pub);

    let done = hs.e().unwrap().es().unwrap();
    let (_transport, wire) = done.into_parts();
    wire
}

#[test]
fn scripted_ephemeral_is_byte_reproducible() {
    let a = seal_n_msg1();
    let b = seal_n_msg1();

    assert_eq!(
        a, b,
        "identical inputs (seeded static + scripted ephemeral) must yield identical wire bytes"
    );
    assert_eq!(
        a.len(),
        81,
        "N msg1 = 65-byte ephemeral pubkey + 16-byte tag"
    );
}

#[test]
fn on_wire_ephemeral_is_d_times_g_of_injected_scalar() {
    // Independently derive d·G for the injected scalar via the public API.
    let mut q = EphemeralOnly::new(ScriptedRng::new(&[&EPHEMERAL]));
    let eph = q.generate::<P256>().unwrap();
    let eph_pub = q.public(&eph).unwrap();

    let msg1 = seal_n_msg1();

    // The N message starts with the cleartext ephemeral public key.
    assert_eq!(
        &msg1[..65],
        eph_pub.to_bytes(),
        "wire ephemeral must equal d·G for the injected ephemeral scalar",
    );
}
