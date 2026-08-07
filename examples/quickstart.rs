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

use hiss::noise::{Blake2b, ChaChaPoly, Transport, X25519};
use hiss::provider::{EphemeralOnly, ProviderExt};

hiss::noise! {
    /// Mutual authentication; neither side pre-knows the other's key.
    pub Channel<X25519, ChaChaPoly, Blake2b> {
        -> e
        <- e, ee, s, es
        -> s, se
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // One long-term key per side. Nothing is shared beforehand.
    let mut alice_keys = EphemeralOnly::new(rand::rng());
    let alice_static = alice_keys.generate::<X25519>()?;
    let mut bob_keys = EphemeralOnly::new(rand::rng());
    let bob_static = bob_keys.generate::<X25519>()?;

    // Three messages. hiss hands you bytes; moving them is your job.
    let (msg1, alice) = Channel::initiator(alice_keys, &[]).write_message_1()?;
    let bob = Channel::responder(bob_keys, &[]).read_message_1(&msg1)?;
    let (msg2, bob) = bob.write_message_2(bob_static)?;
    let (msg3, mut alice) = alice.read_message_2(&msg2)?.write_message_3(alice_static)?;
    let mut bob = bob.read_message_3(&msg3)?;

    // Encrypted, both directions.
    let mut wire = [0u8; 32 + Transport::<Channel>::OVERHEAD];
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
