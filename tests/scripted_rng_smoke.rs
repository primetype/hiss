//! Step-1 smoke test for the deterministic ephemeral-injection harness.
//!
//! Proves that running an `N` handshake over `EphemeralOnly<ScriptedRng>`
//! is byte-for-byte reproducible and that the on-wire ephemeral public key
//! is exactly `d·G` for the injected scalar `d`. This is the mechanism the
//! frozen Noise KAT vectors rely on to assert ciphertexts byte-for-byte.

mod common;
use common::ScriptedRng;

use hiss::noise::{Blake2b, ChaChaPoly, P256};
use hiss::provider::{EphemeralOnly, ProviderExt};
use rand::{SeedableRng, rngs::StdRng};

// The declared identifier is the Noise pattern name — it reaches the
// protocol name mixed into the initial handshake hash — so it must be `N`.
hiss::noise! { pub N<P256, ChaChaPoly, Blake2b> { <- s ... -> e, es } }

/// A fixed, valid P-256 scalar (`0x1111…11` is nonzero and far below the
/// curve order `n`), used as the injected ephemeral private key.
const EPHEMERAL: [u8; 32] = [0x11; 32];

/// Seal one `N` message-1, injecting `EPHEMERAL` as the ephemeral key. The
/// responder static is derived from a fixed seed so the whole transcript is
/// determined by constants.
///
/// `N`'s single message is also its last, so `write_message_1` hands back
/// the finished message and the transport together. The message is a
/// `[u8; N::MSG1_SIZE]` — no I/O, no sink, and the length is fixed at
/// compile time rather than being whatever the writer happened to emit.
fn seal_n_msg1() -> [u8; N::MSG1_SIZE] {
    let mut responder = EphemeralOnly::new(StdRng::seed_from_u64(7));
    let responder_static = responder.generate::<P256>().unwrap();
    let responder_pub = responder.public(&responder_static).unwrap();

    let initiator = EphemeralOnly::new(ScriptedRng::new(&[&EPHEMERAL]));
    let (msg1, _transport) = N::initiator(initiator, &[], responder_pub)
        .write_message_1()
        .unwrap();
    msg1
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
        N::MSG1_SIZE,
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
