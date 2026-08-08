//! The README quickstart, assembled into one runnable program.
//!
//! The documentation walks this in four steps so each one can be read on its
//! own; this is all of it at once, for copying.
//!
//! Run with:
//!
//! ```text
//! cargo run --example quickstart
//! ```
//!
//! Two peers authenticate each other and exchange one encrypted message in
//! each direction. Neither knows the other's key in advance — they learn it
//! during the handshake, which is what the `XX` shape below buys you. Both
//! sides run in one process here so the example needs no sockets; in a real
//! deployment `msg1`/`msg2`/`msg3` are the bytes you put on the wire.
//!
//! Learning a peer's key is not the same as trusting it. Each side checks the
//! static the handshake reveals — that is what the `read_message_N_with` calls
//! do — and an `Err` from the closure aborts before any `Transport` exists.

use hiss::noise::{Blake2b, ChaChaPoly, HandshakeError, Transport, X25519};
use hiss::provider::{EphemeralOnly, ProviderExt};

hiss::noise! {
    /// Mutual authentication; neither side pre-knows the other's key.
    pub XX<X25519, ChaChaPoly, Blake2b> {
        -> e
        <- e, ee, s, es
        -> s, se
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // One long-term key per side. Nothing is shared beforehand; the public
    // halves are what each side will check the other against.
    let mut alice_keys = EphemeralOnly::new(rand::rng());
    let alice_static = alice_keys.generate::<X25519>()?;
    let alice_pub = alice_keys.public(&alice_static)?;
    let mut bob_keys = EphemeralOnly::new(rand::rng());
    let bob_static = bob_keys.generate::<X25519>()?;
    let bob_pub = bob_keys.public(&bob_static)?;

    // Your trust policy: a pin, an enrolment record, an allow-list. Here, the
    // key we expect. `Ok(())` accepts the peer; `Err` aborts the handshake.
    let accept = |ok: bool| match ok {
        true => Ok(()),
        false => Err(HandshakeError::PeerRejected {
            reason: "unknown peer".into(),
        }),
    };

    // Three messages. hiss hands you bytes; moving them is your job. The `_with`
    // reads are where each side decides the key it just learned is one it trusts.
    let (msg1, alice) = XX::initiator(alice_keys, &[]).write_message_1()?;
    let bob = XX::responder(bob_keys, &[]).read_message_1(&msg1)?;
    let (msg2, bob) = bob.write_message_2(bob_static)?;
    let alice = alice.read_message_2_with(&msg2, |peer| accept(peer == &bob_pub))?;
    let (msg3, mut alice) = alice.write_message_3(alice_static)?;
    let mut bob = bob.read_message_3_with(&msg3, |peer| accept(peer == &alice_pub))?;

    // Encrypted, both directions.
    let mut wire = [0u8; 32 + Transport::<XX>::OVERHEAD];
    let mut got = [0u8; 32];

    let n = alice.send(b"ping", &mut wire)?;
    let m = bob.receive(&wire[..n], &mut got)?;
    assert_eq!(&got[..m], b"ping");
    println!("bob received: {}", String::from_utf8_lossy(&got[..m]));

    let n = bob.send(b"pong", &mut wire)?;
    let m = alice.receive(&wire[..n], &mut got)?;
    assert_eq!(&got[..m], b"pong");
    println!("alice received: {}", String::from_utf8_lossy(&got[..m]));

    Ok(())
}
