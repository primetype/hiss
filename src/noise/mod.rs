//! Type-level Noise protocol framework.
//!
//! This module implements the [Noise Protocol Framework][noise] entirely
//! at the type level. The protocol descriptor, handshake pattern,
//! message sequence, pre-message requirements, and per-token state
//! transitions are all encoded in Rust's type system — the compiler
//! enforces protocol correctness at build time with zero runtime
//! dispatch.
//!
//! [noise]: https://noiseprotocol.org/noise.html
//!
//! # Architecture
//!
//! The design has four layers, each building on the one below:
//!
//! ## 1. Protocol descriptor — [`Noise<P, Cu, Ci, H>`]
//!
//! A zero-sized struct parameterised over four zero-sized type
//! arguments:
//!
//! | Parameter | Trait    | Example        | What it provides                |
//! |-----------|----------|----------------|---------------------------------|
//! | `P`       | [`Pattern`] | [`IKpsk1`](pattern::IKpsk1) | Token sequences, pre-messages |
//! | `Cu`      | [`Curve`]   | [`P256`]    | Key sizes, DH output length     |
//! | `Ci`      | [`Cipher`]  | [`ChaChaPoly`] | Tag size, AEAD operations    |
//! | `H`       | [`Hash`]    | [`Blake2b`] | Hash length, HMAC, HKDF         |
//!
//! A type alias pins the protocol for an entire application:
//!
//! ```
//! use hiss::noise::*;
//!
//! type Channel = Noise<pattern::IKpsk1, P256, ChaChaPoly, Blake2b>;
//!
//! let proto = Channel::new();
//! assert_eq!(proto.to_string(), "Noise_IKpsk1_P256_ChaChaPoly_BLAKE2b");
//! ```
//!
//! Because every component is a ZST, `Noise` itself is zero-sized and
//! all sizes are available as `const` at compile time:
//!
//! ```
//! # use hiss::noise::*;
//! # type Channel = Noise<pattern::IKpsk1, P256, ChaChaPoly, Blake2b>;
//! assert_eq!(Channel::PUBLIC_KEY_SIZE, 65);   // P-256 SEC1 uncompressed
//! assert_eq!(Channel::TAG_SIZE, 16);           // Poly1305
//! assert_eq!(Channel::HASH_LEN, 64);           // BLAKE2b
//! assert_eq!(std::mem::size_of::<Channel>(), 0);
//! ```
//!
//! ## 2. Token Cons-lists — [`Cons`], [`Nil`], [`Message`]
//!
//! Handshake patterns are expressed as nested type-level linked lists.
//! Each handshake token ([`E`], [`S`], [`Es`], [`Ee`], [`Se`],
//! [`Psk`]) is a ZST. Tokens within a message are chained with
//! [`Cons<Token, Rest>`], terminated by [`Nil`]. Messages carry a
//! direction ([`ToResponder`] or [`ToInitiator`]) and their token
//! list. The full pattern is a Cons-list of Messages.
//!
//! For example, IKpsk1 encodes as:
//!
//! ```text
//! PreMessages:
//!   Cons<Message<ToInitiator, Cons<S, Nil>>, Nil>                          ← s
//!
//! Messages:
//!   Cons<
//!     Message<ToResponder, Cons<E, Cons<Es, Cons<S, Cons<Ss, Cons<Psk, Nil>>>>>>,  → e, es, s, ss, psk
//!     Cons<
//!       Message<ToInitiator, Cons<E, Cons<Ee, Cons<Se, Nil>>>>,                    ← e, ee, se
//!       Nil
//!     >
//!   >
//! ```
//!
//! The compiler monomorphises the handshake state machine over these
//! types. Each token method peels one element from the Cons-list,
//! so the type system tracks exactly where we are in the protocol.
//! Calling tokens out of order, skipping a token, or processing
//! messages in the wrong direction is a compile error.
//!
//! ## 3. Pre-message type state
//!
//! The [`Pattern::PreMessages`] Cons-list drives the prologue. The
//! handshake starts with the full pre-message list as a type
//! parameter. Each call to `set_s()` or `set_rs()` consumes one
//! pre-message entry, advancing the list toward [`Nil`]. The
//! direction of the pre-message combined with the [`Role`]
//! determines which method is available:
//!
//! | Pre-message | Role          | Method     | Meaning                      |
//! |-------------|---------------|------------|------------------------------|
//! | `← s`       | [`Initiator`] | `set_rs()` | Remote party's static known  |
//! | `← s`       | [`Responder`] | `set_s()`  | Our own static is known      |
//! | `→ s`       | [`Initiator`] | `set_s()`  | Our own static is known      |
//! | `→ s`       | [`Responder`] | `set_rs()` | Remote party's static known  |
//!
//! The compiler rejects calling the wrong method for the role. The
//! handshake message processing methods (`e()`, `read()`, etc.) are
//! only available once the pre-message list reaches [`Nil`] — all
//! required keys must be provided first.
//!
//! ## 4. Handshake drivers (the type-state machine)
//!
//! The handshake is driven over an I/O stream by one of two drivers,
//! split on the only irreducible axis — synchronous vs asynchronous I/O:
//!
//! - [`SyncHandshake`] — blocking [`std::io::Read`]/[`std::io::Write`].
//! - `AsyncHandshake` — `tokio` `AsyncRead`/`AsyncWrite` (feature
//!   `async-io`).
//!
//! Each driver is a type-state machine over three states, parameterised
//! by the remaining pre-message / token / message Cons-lists:
//!
//! - **`*Handshake`** — between messages. Offers `e()` / `s()` / `psk()`
//!   (to start sending) or `recv()` (to start receiving), depending on
//!   the next message direction and role.
//! - **`*Sending`** — within a send message. Each token method streams
//!   that token's bytes to the wire and advances the token Cons-list.
//! - **`*Receiving`** — within a receive message. Each token method
//!   reads exactly that token's bytes off the wire and advances the
//!   Cons-list.
//!
//! When the last token of the last message is processed, the chain
//! yields a [`SyncTransport`]/`AsyncTransport` bundling the
//! post-handshake [`Transport`] with the stream it ran over. Revealing
//! tokens (`e`/`s`) additionally hand back the revealed public key.
//!
//! This is encoded via three non-overlapping `impl` blocks per token per
//! context (send/recv), selected by the Cons-list tail. The compiler
//! picks the right one — no `match`, no `if`, no runtime check.
//!
//! The **buffer / no-syscall** use case is just an in-memory `Io`: hand
//! the driver a [`std::io::Cursor`], a `Vec`, or `&mut [u8]` and the
//! whole handshake runs without any actual I/O (this is how the seal
//! helpers and most tests drive it).
//!
//! # Compile-time message sizes
//!
//! Because every component size is a `const` — public key size from
//! the [`Curve`], tag size from the [`Cipher`], hash length from the
//! [`Hash`] — the exact byte size of every handshake message is
//! known at compile time (see [`noise_message_size!`](crate::noise_message_size)).
//! For `Noise_IKpsk1_P256_ChaChaPoly_BLAKE2b`:
//!
//! | Message | Contents                                   | Size (bytes)              |
//! |---------|--------------------------------------------|---------------------------|
//! | msg1    | `e_pub` + `encrypted(s_pub)` + payload tag | 65 + (65 + 16) + 16 = 162 |
//! | msg2    | `e_pub` + payload tag                      | 65 + 16 = 81              |
//!
//! # Pluggable crypto provider
//!
//! The drivers are generic over the crypto provider, so the per-token DH
//! and key generation can use any backend:
//!
//! - **Software** (`eccoxide`/`cryptoxide`) — resolves immediately.
//! - **Secure Enclave** (Apple Security framework) — the blocking
//!   Security-framework calls run on the calling thread for the
//!   [`SyncHandshake`], or are offloaded to a worker for the
//!   `AsyncHandshake`; may prompt for biometric authentication.
//!
//! [`SyncHandshake`] takes a synchronous
//! [`DhProvider`](crate::provider::DhProvider); `AsyncHandshake` takes
//! a [`DhProviderAsync`](crate::provider::DhProviderAsync).
//!
//! # Usage
//!
//! ```ignore
//! use hiss::noise::*;
//!
//! type Channel = Noise<pattern::IKpsk1, P256, ChaChaPoly, Blake2b>;
//!
//! // ── Initiator (blocking) over a stream ───────────────────
//! let i = Channel::sync_initiator(provider, &[], stream)
//!     .set_rs(responder_pub);                     // <- s pre-message
//!
//! let i = i
//!     .e()?                                       // -> e
//!     .es()?                                      //    es
//!     .s(initiator_static)?                       //    s
//!     .ss()?                                      //    ss
//!     .psk(&psk)?;                                //    psk (msg1 streamed)
//!
//! let (re, recv) = i.recv().e()?;                 // <- e, ee, se
//! let transport = recv.ee()?.se()?;               // -> SyncTransport
//!
//! // ── Responder (blocking) over a stream ───────────────────
//! let r = Channel::sync_responder(provider, &[], stream)
//!     .set_s(responder_static)?;                  // <- s pre-message
//!
//! let (re, recv) = r.recv().e()?;                 // -> e, es, s, ss, psk
//! let recv = recv.es()?;
//! let (rs, recv) = recv.s()?;                     // remote static revealed
//! let r = recv.ss()?.psk(&psk)?;
//!
//! let transport = r.e()?.ee()?.se()?;             // <- e, ee, se → SyncTransport
//! ```
//!
//! The `AsyncHandshake` (feature `async-io`) is the identical chain
//! with `async_initiator`/`async_responder` and `.await` on each token.

pub(crate) mod buffers;
pub mod cipher;
pub mod cipher_state;
pub mod curve;
pub mod datagram;
pub mod error;
pub(crate) mod handshake;
pub mod hash;
#[cfg(feature = "async-io")]
#[cfg_attr(docsrs, doc(cfg(feature = "async-io")))]
#[allow(clippy::type_complexity)]
pub mod io_async;
#[allow(clippy::type_complexity)]
pub mod io_sync;
pub mod pattern;
pub(crate) mod process;
pub mod role;
#[cfg(any(target_os = "macos", target_os = "ios", test))]
pub(crate) mod seal;
pub mod session_id;
#[doc(hidden)]
pub mod support;
pub mod symmetric_state;
pub mod tokens;
pub mod transport;
pub mod well_formed;

pub use self::cipher::{ChaChaPoly, Cipher};
pub use self::cipher_state::CipherState;
pub use self::curve::{Curve, DhCurve, P256, X448, X25519};
pub use self::datagram::{DatagramRecv, DatagramSend};
pub use self::error::HandshakeError;
#[cfg(feature = "async-io")]
#[cfg_attr(docsrs, doc(cfg(feature = "async-io")))]
pub use self::io_async::{AsyncHandshake, AsyncReceiving, AsyncSending, AsyncTransport};
pub use self::io_sync::{SyncHandshake, SyncReceiving, SyncSending, SyncTransport};
// Protocol re-exported from this module (defined below on Noise).
pub use self::hash::{Blake2b, Hash};
// Pattern markers stay namespaced under `noise::pattern::{N, K, …}`; only the
// `Pattern` trait is re-exported at the root. There are deliberately no
// suite-bound protocol aliases here: `N`, `XX`, … are Noise *patterns*, not
// whole `Noise<P, Cu, Ci, H>` protocols, so callers spell the protocol out (or
// alias it locally) rather than rely on a root name that conflates the two.
pub use self::pattern::Pattern;
pub use self::role::{Initiator, Responder, Role};
pub use self::session_id::SessionId;
pub use self::symmetric_state::SymmetricState;
pub use self::tokens::*;
pub use self::transport::{Transport, TransportRecv, TransportSend};
pub use self::well_formed::WellFormed;

use std::fmt;
use std::marker::PhantomData;

/// A fully parameterised Noise protocol descriptor.
///
/// Zero-sized — carries no runtime data. All properties are derived
/// from the trait bounds on `P`, `Cu`, `Ci`, and `H`.
pub struct Noise<P, Cu, Ci, H> {
    _pattern: PhantomData<fn() -> P>,
    _curve: PhantomData<fn() -> Cu>,
    _cipher: PhantomData<fn() -> Ci>,
    _hash: PhantomData<fn() -> H>,
}

impl<P, Cu, Ci, H> Noise<P, Cu, Ci, H> {
    /// Create a new protocol descriptor.
    pub const fn new() -> Self {
        Self {
            _pattern: PhantomData,
            _curve: PhantomData,
            _cipher: PhantomData,
            _hash: PhantomData,
        }
    }
}

impl<P: Pattern, Cu: DhCurve, Ci: Cipher, H: Hash> Noise<P, Cu, Ci, H> {
    /// DH output length in bytes.
    pub const DHLEN: usize = Cu::DHLEN;

    /// Serialised public key size in bytes.
    pub const PUBLIC_KEY_SIZE: usize = Cu::PUBLIC_KEY_SIZE;

    /// AEAD authentication tag size in bytes.
    pub const TAG_SIZE: usize = Ci::TAG_SIZE;

    /// Hash output length in bytes (also the chaining key size).
    pub const HASH_LEN: usize = H::HASH_LEN;

    /// Number of handshake messages in the pattern.
    pub const NUM_MESSAGES: usize = P::NUM_MESSAGES;
}

impl<P: Pattern, Cu: Curve, Ci: Cipher, H: Hash> fmt::Display for Noise<P, Cu, Ci, H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Noise_{}_{}_{}_{}", P::NAME, Cu::NAME, Ci::NAME, H::NAME)
    }
}

impl<P, Cu, Ci, H> Default for Noise<P, Cu, Ci, H> {
    fn default() -> Self {
        Self::new()
    }
}

/// A fully specified Noise protocol — pattern, curve, cipher, and hash.
///
/// Implemented by [`Noise<P, Cu, Ci, H>`]. Used as a single type
/// parameter on the [`SyncHandshake`]/`AsyncHandshake` (feature
/// `async-io`) drivers instead of spreading four separate generic
/// parameters.
pub trait Protocol {
    /// The handshake pattern (e.g. [`IKpsk1`](pattern::IKpsk1)).
    type Pattern: Pattern;
    /// The DH curve (e.g. [`P256`]).
    type Curve: DhCurve;
    /// The AEAD cipher (e.g. [`ChaChaPoly`]).
    type Cipher: Cipher;
    /// The hash function (e.g. [`Blake2b`]).
    type Hash: Hash;
}

impl<P: WellFormed, Cu: DhCurve, Ci: Cipher, H: Hash> Protocol for Noise<P, Cu, Ci, H> {
    type Pattern = P;
    type Curve = Cu;
    type Cipher = Ci;
    type Hash = H;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curve::p256::{P256r1PrivateKey, P256r1PublicKey};
    use crate::noise_message_size;
    use crate::provider::EphemeralOnly;
    use crate::provider::ProviderExt;
    use crate::psk::Psk;
    use rand::{SeedableRng, rngs::StdRng};
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::rc::Rc;
    type Channel = Noise<pattern::IKpsk1, P256, ChaChaPoly, Blake2b>;
    type NoiseSeal = Noise<pattern::N, P256, ChaChaPoly, Blake2b>;
    type NoiseK = Noise<pattern::K, P256, ChaChaPoly, Blake2b>;
    type NoiseKpsk0 = Noise<pattern::Kpsk0, P256, ChaChaPoly, Blake2b>;

    /// In-memory `Read + Write` endpoint for driving the blocking
    /// [`SyncHandshake`] in unit tests.
    ///
    /// `EphemeralOnly` is a synchronous `DhProvider`, so the whole
    /// handshake runs without an executor and every byte each side emits
    /// lands in an in-memory queue — byte-identical to the wire. Writes
    /// accumulate on the write side; reads pull from the read side. Pair
    /// two endpoints with their queues swapped for a hiss↔hiss
    /// round-trip, or feed a single endpoint by hand for capture/tamper
    /// tests.
    #[derive(Clone)]
    struct Pipe {
        inbound: Rc<RefCell<VecDeque<u8>>>,
        outbound: Rc<RefCell<VecDeque<u8>>>,
    }

    impl Pipe {
        /// A linked pair `(a, b)` where `a`'s writes are `b`'s reads and
        /// vice versa.
        fn pair() -> (Pipe, Pipe) {
            let l = Rc::new(RefCell::new(VecDeque::new()));
            let r = Rc::new(RefCell::new(VecDeque::new()));
            (
                Pipe {
                    inbound: r.clone(),
                    outbound: l.clone(),
                },
                Pipe {
                    inbound: l,
                    outbound: r,
                },
            )
        }

        /// Drain everything written to this endpoint so far (one or more
        /// completed outgoing handshake messages).
        fn take_written(&self) -> Vec<u8> {
            self.outbound.borrow_mut().drain(..).collect()
        }

        /// Push bytes onto this endpoint's read side.
        fn feed(&self, bytes: &[u8]) {
            self.inbound.borrow_mut().extend(bytes.iter().copied());
        }
    }

    impl std::io::Read for Pipe {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let mut q = self.inbound.borrow_mut();
            let n = q.len().min(buf.len());
            for slot in buf.iter_mut().take(n) {
                *slot = q.pop_front().unwrap();
            }
            Ok(n)
        }
    }

    impl std::io::Write for Pipe {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.outbound.borrow_mut().extend(buf.iter().copied());
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn descriptor_string() {
        let proto = Channel::new();
        assert_eq!(proto.to_string(), "Noise_IKpsk1_P256_ChaChaPoly_BLAKE2b");
    }

    #[test]
    fn n_descriptor_string() {
        let proto = NoiseSeal::new();
        assert_eq!(proto.to_string(), "Noise_N_P256_ChaChaPoly_BLAKE2b");
    }

    #[test]
    fn sizes() {
        assert_eq!(Channel::DHLEN, 32);
        assert_eq!(Channel::PUBLIC_KEY_SIZE, 65);
        assert_eq!(Channel::TAG_SIZE, 16);
        assert_eq!(Channel::HASH_LEN, 64);
        assert_eq!(Channel::NUM_MESSAGES, 2);
    }

    #[test]
    fn n_sizes() {
        assert_eq!(NoiseSeal::NUM_MESSAGES, 1);
        assert_eq!(size_of::<NoiseSeal>(), 0);
    }

    #[test]
    fn zero_sized() {
        assert_eq!(size_of::<Channel>(), 0);
    }

    // ── Noise N seal/open test ────────────────────────────────────

    /// Noise N one-way seal: encrypt data to a known public key,
    /// then open it with the corresponding private key.
    #[test]
    fn noise_n_seal_open() {
        let mut provider = EphemeralOnly::new(StdRng::from_os_rng());

        // The "recipient" — in practice, the device's own Secure Enclave key.
        let recipient_static = provider.generate::<P256>().unwrap();
        let recipient_pub = provider.public(&recipient_static).unwrap();

        let psk_to_seal = Psk::from_bytes([0x42; 32]);

        let (i_pipe, r_pipe) = Pipe::pair();

        // ── Seal (initiator side) ─────────────────────────────────
        let sealer = SyncHandshake::<NoiseSeal, Initiator, _, _, _, _>::initiate(
            EphemeralOnly::new(StdRng::from_os_rng()),
            &[],
            i_pipe.clone(),
        )
        .set_rs(recipient_pub);

        // -> e, es streams the message into the pipe and finalizes to transport.
        let (mut transport, _) = sealer.e().unwrap().es().unwrap().into_parts();

        // msg = ephemeral public key (65) + payload tag (16) = 81 bytes
        let msg = i_pipe.take_written();
        assert_eq!(msg.len(), 81);

        // Encrypt the PSK as a transport payload.
        let mut sealed = [0u8; 64]; // 32 + 16 tag
        let sealed_len = transport.send(psk_to_seal.as_bytes(), &mut sealed).unwrap();

        // ── Open (responder side) ─────────────────────────────────
        r_pipe.feed(&msg);
        let opener = SyncHandshake::<NoiseSeal, Responder, _, _, _, _>::respond(
            EphemeralOnly::new(StdRng::from_os_rng()),
            &[],
            r_pipe.clone(),
        )
        .set_s(recipient_static)
        .unwrap();

        let (_, recv) = opener.recv().e().unwrap();
        let (mut transport, _) = recv.es().unwrap().into_parts();

        let mut opened = [0u8; 32];
        let opened_len = transport
            .receive(&sealed[..sealed_len], &mut opened)
            .unwrap();

        assert_eq!(opened_len, 32);
        assert_eq!(opened, *psk_to_seal.as_bytes());
    }

    // ── Noise N tampered handshake ─────────────────────────────────

    #[test]
    fn noise_n_tampered_ephemeral_rejected() {
        let mut provider = EphemeralOnly::new(StdRng::from_os_rng());

        let recipient_static = provider.generate::<P256>().unwrap();
        let recipient_pub = provider.public(&recipient_static).unwrap();

        let (i_pipe, r_pipe) = Pipe::pair();

        let sealer = SyncHandshake::<NoiseSeal, Initiator, _, _, _, _>::initiate(
            EphemeralOnly::new(StdRng::from_os_rng()),
            &[],
            i_pipe.clone(),
        )
        .set_rs(recipient_pub);
        // `take_written` drains the linked queue so the genuine bytes never
        // reach the responder; only the tampered copy is fed in.
        let (_transport, _) = sealer.e().unwrap().es().unwrap().into_parts();
        let mut tampered = i_pipe.take_written();
        // Flip a byte in the ephemeral public key.
        tampered[1] ^= 0xFF;

        r_pipe.feed(&tampered);
        let opener = SyncHandshake::<NoiseSeal, Responder, _, _, _, _>::respond(
            EphemeralOnly::new(StdRng::from_os_rng()),
            &[],
            r_pipe.clone(),
        )
        .set_s(recipient_static)
        .unwrap();

        // The tampered ephemeral key causes either an invalid public key
        // error or a DH mismatch leading to payload tag failure.
        let (_, recv) = match opener.recv().e() {
            Err(_) => return, // invalid ephemeral key (or short read)
            Ok(result) => result,
        };
        // DH produces wrong shared secret → tag fails.
        assert!(recv.es().is_err());
    }

    #[test]
    fn noise_n_tampered_tag_rejected() {
        let mut provider = EphemeralOnly::new(StdRng::from_os_rng());

        let recipient_static = provider.generate::<P256>().unwrap();
        let recipient_pub = provider.public(&recipient_static).unwrap();

        let (i_pipe, r_pipe) = Pipe::pair();

        let sealer = SyncHandshake::<NoiseSeal, Initiator, _, _, _, _>::initiate(
            EphemeralOnly::new(StdRng::from_os_rng()),
            &[],
            i_pipe.clone(),
        )
        .set_rs(recipient_pub);
        let (_transport, _) = sealer.e().unwrap().es().unwrap().into_parts();

        let mut tampered = i_pipe.take_written();
        // Flip a byte in the payload tag (last 16 bytes).
        let len = tampered.len();
        tampered[len - 1] ^= 0xFF;

        r_pipe.feed(&tampered);
        let opener = SyncHandshake::<NoiseSeal, Responder, _, _, _, _>::respond(
            EphemeralOnly::new(StdRng::from_os_rng()),
            &[],
            r_pipe.clone(),
        )
        .set_s(recipient_static)
        .unwrap();

        let (_, recv) = opener.recv().e().unwrap();
        // The tag is corrupted, so es must fail at DecryptAndHash.
        assert!(recv.es().is_err());
    }

    // ── Noise K / Kpsk0 tests ─────────────────────────────────────

    #[test]
    fn k_descriptor_string() {
        let proto = NoiseK::new();
        assert_eq!(proto.to_string(), "Noise_K_P256_ChaChaPoly_BLAKE2b");
    }

    #[test]
    fn kpsk0_descriptor_string() {
        let proto = NoiseKpsk0::new();
        assert_eq!(proto.to_string(), "Noise_Kpsk0_P256_ChaChaPoly_BLAKE2b");
    }

    #[test]
    fn k_sizes() {
        assert_eq!(NoiseK::NUM_MESSAGES, 1);
        assert_eq!(size_of::<NoiseK>(), 0);
    }

    #[test]
    fn kpsk0_sizes() {
        assert_eq!(NoiseKpsk0::NUM_MESSAGES, 1);
        assert_eq!(size_of::<NoiseKpsk0>(), 0);
    }

    /// Noise K authenticated seal: encrypt data from Alice to Bob,
    /// where both static keys are known. Open with Bob's key.
    #[test]
    fn noise_k_seal_open() {
        let mut provider = EphemeralOnly::new(StdRng::from_os_rng());

        // Alice (sender) and Bob (recipient) each have static keys.
        let alice_static = provider.generate::<P256>().unwrap();
        let alice_pub = provider.public(&alice_static).unwrap();

        let bob_static = provider.generate::<P256>().unwrap();
        let bob_pub = provider.public(&bob_static).unwrap();

        let payload: [u8; 32] = [0x42; 32];

        let (i_pipe, r_pipe) = Pipe::pair();

        // ── Seal (Alice → Bob) ──────────────────────────────────
        // Pre-messages: -> s (Alice), <- s (Bob)
        let sealer = SyncHandshake::<NoiseK, Initiator, _, _, _, _>::initiate(
            EphemeralOnly::new(StdRng::from_os_rng()),
            &[],
            i_pipe.clone(),
        )
        .set_s(alice_static)
        .unwrap()
        .set_rs(bob_pub);

        // -> e, es, ss
        let (mut transport, _) = sealer.e().unwrap().es().unwrap().ss().unwrap().into_parts();

        // msg = ephemeral public key (65) + payload tag (16) = 81 bytes
        let msg = i_pipe.take_written();
        assert_eq!(msg.len(), 81);

        let mut sealed = [0u8; 64]; // 32 + 16 tag
        let sealed_len = transport.send(&payload, &mut sealed).unwrap();

        // ── Open (Bob) ──────────────────────────────────────────
        // Pre-messages: -> s (Alice), <- s (Bob)
        r_pipe.feed(&msg);
        let opener = SyncHandshake::<NoiseK, Responder, _, _, _, _>::respond(
            EphemeralOnly::new(StdRng::from_os_rng()),
            &[],
            r_pipe.clone(),
        )
        .set_rs(alice_pub)
        .set_s(bob_static)
        .unwrap();

        let (_, recv) = opener.recv().e().unwrap();
        let recv = recv.es().unwrap();
        let (mut transport, _) = recv.ss().unwrap().into_parts();

        let mut opened = [0u8; 32];
        let opened_len = transport
            .receive(&sealed[..sealed_len], &mut opened)
            .unwrap();

        assert_eq!(opened_len, 32);
        assert_eq!(opened, payload);
    }

    /// Noise Kpsk0 authenticated seal with PSK binding.
    #[test]
    fn noise_kpsk0_seal_open() {
        let mut provider = EphemeralOnly::new(StdRng::from_os_rng());

        let alice_static = provider.generate::<P256>().unwrap();
        let alice_pub = provider.public(&alice_static).unwrap();

        let bob_static = provider.generate::<P256>().unwrap();
        let bob_pub = provider.public(&bob_static).unwrap();

        let psk = Psk::from_bytes([0xBB; 32]);
        let payload: [u8; 32] = [0x42; 32];

        let (i_pipe, r_pipe) = Pipe::pair();

        // ── Seal (Alice → Bob) ──────────────────────────────────
        let sealer = SyncHandshake::<NoiseKpsk0, Initiator, _, _, _, _>::initiate(
            EphemeralOnly::new(StdRng::from_os_rng()),
            &[],
            i_pipe.clone(),
        )
        .set_s(alice_static)
        .unwrap()
        .set_rs(bob_pub);

        // -> psk, e, es, ss
        let (mut transport, _) = sealer
            .psk(&psk)
            .unwrap()
            .e()
            .unwrap()
            .es()
            .unwrap()
            .ss()
            .unwrap()
            .into_parts();

        let msg = i_pipe.take_written();
        assert_eq!(msg.len(), 81);

        let mut sealed = [0u8; 64];
        let sealed_len = transport.send(&payload, &mut sealed).unwrap();

        // ── Open (Bob) ──────────────────────────────────────────
        r_pipe.feed(&msg);
        let opener = SyncHandshake::<NoiseKpsk0, Responder, _, _, _, _>::respond(
            EphemeralOnly::new(StdRng::from_os_rng()),
            &[],
            r_pipe.clone(),
        )
        .set_rs(alice_pub)
        .set_s(bob_static)
        .unwrap();

        let recv = opener.recv();
        let recv = recv.psk(&psk).unwrap();
        let (_, recv) = recv.e().unwrap();
        let recv = recv.es().unwrap();
        let (mut transport, _) = recv.ss().unwrap().into_parts();

        let mut opened = [0u8; 32];
        let opened_len = transport
            .receive(&sealed[..sealed_len], &mut opened)
            .unwrap();

        assert_eq!(opened_len, 32);
        assert_eq!(opened, payload);
    }

    /// Kpsk0 with wrong PSK fails to decrypt.
    #[test]
    fn noise_kpsk0_wrong_psk_fails() {
        let mut provider = EphemeralOnly::new(StdRng::from_os_rng());

        let alice_static = provider.generate::<P256>().unwrap();
        let alice_pub = provider.public(&alice_static).unwrap();

        let bob_static = provider.generate::<P256>().unwrap();
        let bob_pub = provider.public(&bob_static).unwrap();

        let psk = Psk::from_bytes([0xBB; 32]);
        let wrong_psk = Psk::from_bytes([0xCC; 32]);
        let payload: [u8; 32] = [0x42; 32];

        let (i_pipe, r_pipe) = Pipe::pair();

        // Seal with correct PSK
        let sealer = SyncHandshake::<NoiseKpsk0, Initiator, _, _, _, _>::initiate(
            EphemeralOnly::new(StdRng::from_os_rng()),
            &[],
            i_pipe.clone(),
        )
        .set_s(alice_static)
        .unwrap()
        .set_rs(bob_pub);

        let (mut transport, _) = sealer
            .psk(&psk)
            .unwrap()
            .e()
            .unwrap()
            .es()
            .unwrap()
            .ss()
            .unwrap()
            .into_parts();

        let msg = i_pipe.take_written();

        let mut sealed = [0u8; 64];
        let _sealed_len = transport.send(&payload, &mut sealed).unwrap();

        // Open with wrong PSK — the empty payload tag verification at
        // the end of the message catches the key divergence immediately.
        r_pipe.feed(&msg);
        let opener = SyncHandshake::<NoiseKpsk0, Responder, _, _, _, _>::respond(
            EphemeralOnly::new(StdRng::from_os_rng()),
            &[],
            r_pipe.clone(),
        )
        .set_rs(alice_pub)
        .set_s(bob_static)
        .unwrap();

        let recv = opener.recv();
        let recv = recv.psk(&wrong_psk).unwrap();
        let (_, recv) = recv.e().unwrap();
        let recv = recv.es().unwrap();
        // ss is the last token — payload tag verification fails because
        // the wrong PSK produced different derived keys.
        let result = recv.ss();
        assert!(result.is_err());
    }

    // ── IKpsk1 handshake flow tests ───────────────────────────────
    //
    // Full round-trip test that runs both initiator and responder
    // against each other with real keys and real crypto operations.

    /// IKpsk1 full round-trip handshake.
    ///
    /// ```text
    /// IKpsk1:
    ///   <- s                         (pre-message: responder's static known)
    ///   ...
    ///   -> e, es, s, ss, psk         (msg1: initiator → responder)
    ///   <- e, ee, se                 (msg2: responder → initiator)
    /// ```
    #[test]
    fn ikpsk1_round_trip() {
        let mut provider = EphemeralOnly::new(StdRng::from_os_rng());

        // ── Key generation ──────────────────────────────────────
        let initiator_static = provider.generate::<P256>().unwrap();
        let initiator_pub = provider.public(&initiator_static).unwrap();

        let responder_static = provider.generate::<P256>().unwrap();
        let responder_pub = provider.public(&responder_static).unwrap();

        // PSK established during the QR ceremony.
        let psk = Psk::from_bytes([0xAA; 32]);

        // The handshake is driven over a linked pipe pair, but each message
        // is captured off the wire (`take_written`) and fed to the peer so
        // the test can inspect the on-wire ephemeral keys and lengths.
        let (i_pipe, r_pipe) = Pipe::pair();

        // ── Construction ────────────────────────────────────────
        let i_hs = SyncHandshake::<Channel, Initiator, _, _, _, _>::initiate(
            EphemeralOnly::new(StdRng::from_os_rng()),
            &[],
            i_pipe.clone(),
        )
        .set_rs(responder_pub);

        let r_hs = SyncHandshake::<Channel, Responder, _, _, _, _>::respond(
            EphemeralOnly::new(StdRng::from_os_rng()),
            &[],
            r_pipe.clone(),
        )
        .set_s(responder_static)
        .unwrap();

        // ── Message 1: -> e, es, s, ss, psk (initiator sends) ──
        let i_hs = i_hs
            .e()
            .unwrap()
            .es()
            .unwrap()
            .s(initiator_static)
            .unwrap()
            .ss()
            .unwrap()
            .psk(&psk)
            .unwrap();

        // msg1 = ephemeral (65) + encrypted static (65+16) + payload tag (16) = 162 bytes
        let msg1 = i_pipe.take_written();
        assert_eq!(msg1.len(), 162);

        // ── Message 1 (responder receives) ──────────────────────
        r_pipe.feed(&msg1);

        // The first 65 bytes of msg1 are the initiator's ephemeral
        // public key (SEC1 uncompressed P-256).
        let initiator_e_from_wire =
            P256r1PublicKey::from_bytes(&msg1[..65]).expect("valid ephemeral in msg1");

        let (initiator_ephemeral, recv) = r_hs.recv().e().unwrap();

        // The ephemeral key revealed by recv matches what was on the wire.
        assert_eq!(initiator_ephemeral, initiator_e_from_wire);

        let recv = recv.es().unwrap();
        let (revealed_initiator_pub, recv) = recv.s().unwrap();
        let recv = recv.ss().unwrap();
        let r_hs = recv.psk(&psk).unwrap();

        // The responder now knows the initiator's static key.
        assert_eq!(revealed_initiator_pub, initiator_pub);

        // ── Message 2: <- e, ee, se (responder sends) ──────────
        let (r_transport, _) = r_hs.e().unwrap().ee().unwrap().se().unwrap().into_parts();

        // msg2 = ephemeral (65) + payload tag (16) = 81 bytes
        let msg2 = r_pipe.take_written();
        assert_eq!(msg2.len(), 81);

        // ── Message 2 (initiator receives) ──────────────────────
        i_pipe.feed(&msg2);

        // The first 65 bytes of msg2 are the responder's ephemeral
        // public key (SEC1 uncompressed P-256).
        let responder_e_from_wire =
            P256r1PublicKey::from_bytes(&msg2[..65]).expect("valid ephemeral in msg2");

        let (responder_ephemeral, recv) = i_hs.recv().e().unwrap();

        // The ephemeral key revealed by recv matches what was on the wire.
        assert_eq!(responder_ephemeral, responder_e_from_wire);

        let (i_transport, _) = recv.ee().unwrap().se().unwrap().into_parts();

        // ── Verify: both sides derived the same handshake hash ──
        assert_eq!(i_transport.session_id(), r_transport.session_id());

        // ── Verify: transport encryption works bidirectionally ──
        let mut i_transport = i_transport;
        let mut r_transport = r_transport;

        let plaintext = b"hello from initiator";
        let mut ct_buf = [0u8; 256];
        let ct_len = i_transport.send(plaintext, &mut ct_buf).unwrap();
        let mut pt_buf = [0u8; 256];
        let pt_len = r_transport.receive(&ct_buf[..ct_len], &mut pt_buf).unwrap();
        assert_eq!(&pt_buf[..pt_len], plaintext);

        let plaintext = b"hello from responder";
        let ct_len = r_transport.send(plaintext, &mut ct_buf).unwrap();
        let pt_len = i_transport.receive(&ct_buf[..ct_len], &mut pt_buf).unwrap();
        assert_eq!(&pt_buf[..pt_len], plaintext);
    }

    // ── ChaChaPoly AEAD unit tests ────────────────────────────────

    #[test]
    fn chacha_encrypt_decrypt_round_trip() {
        let key = [0x42u8; 32];
        let plaintext = b"the quick brown fox";
        let ad = b"associated data";

        let mut ct = [0u8; 128];
        let ct_len = ChaChaPoly::encrypt(&key, 0, ad, plaintext, &mut ct).unwrap();
        assert_eq!(ct_len, plaintext.len() + 16);

        let mut pt = [0u8; 128];
        let pt_len = ChaChaPoly::decrypt(&key, 0, ad, &ct[..ct_len], &mut pt).unwrap();
        assert_eq!(&pt[..pt_len], plaintext);
    }

    #[test]
    fn chacha_decrypt_corrupted_tag() {
        let key = [0x42u8; 32];
        let plaintext = b"test data";

        let mut ct = [0u8; 64];
        let ct_len = ChaChaPoly::encrypt(&key, 0, &[], plaintext, &mut ct).unwrap();

        // Corrupt the last byte (part of the tag).
        ct[ct_len - 1] ^= 0xFF;

        let mut pt = [0u8; 64];
        let err = ChaChaPoly::decrypt(&key, 0, &[], &ct[..ct_len], &mut pt).unwrap_err();
        assert!(
            matches!(err, error::HandshakeError::DecryptionFailed),
            "expected DecryptionFailed, got {err:?}"
        );
    }

    #[test]
    fn chacha_decrypt_too_short() {
        let key = [0u8; 32];
        let mut pt = [0u8; 64];
        // Less than TAG_SIZE bytes — must fail.
        let err = ChaChaPoly::decrypt(&key, 0, &[], &[0u8; 15], &mut pt).unwrap_err();
        assert!(matches!(err, error::HandshakeError::DecryptionFailed));
    }

    #[test]
    fn chacha_wrong_nonce_fails() {
        let key = [0x42u8; 32];
        let plaintext = b"nonce matters";

        let mut ct = [0u8; 64];
        let ct_len = ChaChaPoly::encrypt(&key, 0, &[], plaintext, &mut ct).unwrap();

        // Decrypt with nonce 1 instead of 0.
        let mut pt = [0u8; 64];
        let err = ChaChaPoly::decrypt(&key, 1, &[], &ct[..ct_len], &mut pt).unwrap_err();
        assert!(matches!(err, error::HandshakeError::DecryptionFailed));
    }

    #[test]
    fn chacha_wrong_key_fails() {
        let key = [0x42u8; 32];
        let wrong_key = [0x43u8; 32];
        let plaintext = b"key matters";

        let mut ct = [0u8; 64];
        let ct_len = ChaChaPoly::encrypt(&key, 0, &[], plaintext, &mut ct).unwrap();

        let mut pt = [0u8; 64];
        let err = ChaChaPoly::decrypt(&wrong_key, 0, &[], &ct[..ct_len], &mut pt).unwrap_err();
        assert!(matches!(err, error::HandshakeError::DecryptionFailed));
    }

    #[test]
    fn chacha_wrong_ad_fails() {
        let key = [0x42u8; 32];
        let plaintext = b"ad matters";

        let mut ct = [0u8; 64];
        let ct_len = ChaChaPoly::encrypt(&key, 0, b"correct", plaintext, &mut ct).unwrap();

        let mut pt = [0u8; 64];
        let err = ChaChaPoly::decrypt(&key, 0, b"wrong", &ct[..ct_len], &mut pt).unwrap_err();
        assert!(matches!(err, error::HandshakeError::DecryptionFailed));
    }

    #[test]
    fn chacha_empty_plaintext() {
        let key = [0x42u8; 32];
        let mut ct = [0u8; 16]; // tag only
        let ct_len = ChaChaPoly::encrypt(&key, 0, &[], &[], &mut ct).unwrap();
        assert_eq!(ct_len, 16);

        let mut pt = [0u8; 0];
        let pt_len = ChaChaPoly::decrypt(&key, 0, &[], &ct[..ct_len], &mut pt).unwrap();
        assert_eq!(pt_len, 0);
    }

    // ── CipherState unit tests ────────────────────────────────────

    #[test]
    fn cipher_state_unkeyed_passthrough() {
        let mut cs = cipher_state::CipherState::<ChaChaPoly>::empty();
        assert!(!cs.has_key());

        let plaintext = b"plaintext passthrough";
        let mut out = [0u8; 64];
        let len = cs.encrypt_with_ad(b"ad", plaintext, &mut out).unwrap();
        assert_eq!(&out[..len], plaintext);

        let mut pt = [0u8; 64];
        let len = cs.decrypt_with_ad(b"ad", &out[..len], &mut pt).unwrap();
        assert_eq!(&pt[..len], plaintext);
    }

    // ── Hash trait unit tests ─────────────────────────────────────

    #[test]
    fn blake2b_hash_deterministic() {
        let a = Blake2b::hash(b"test data");
        let b = Blake2b::hash(b"test data");
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn blake2b_hash_different_inputs() {
        let a = Blake2b::hash(b"input one");
        let b = Blake2b::hash(b"input two");
        assert_ne!(a, b);
    }

    #[test]
    fn blake2b_hash_two_equals_concat() {
        // hash_two(a, b) should equal hash(a || b)
        let a = b"first part";
        let b = b"second part";
        let h1 = Blake2b::hash_two(a, b);
        let mut concat = a.to_vec();
        concat.extend_from_slice(b);
        let h2 = Blake2b::hash(&concat);
        assert_eq!(h1, h2);
    }

    #[test]
    fn blake2b_hmac_deterministic() {
        let a = Blake2b::hmac(b"key", b"data");
        let b = Blake2b::hmac(b"key", b"data");
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn blake2b_hmac_different_keys() {
        let a = Blake2b::hmac(b"key1", b"data");
        let b = Blake2b::hmac(b"key2", b"data");
        assert_ne!(a, b);
    }

    // ── Handshake error path tests ────────────────────────────────

    #[test]
    fn wrong_message_length_rejected() {
        let mut provider = EphemeralOnly::new(StdRng::from_os_rng());
        let responder_static = provider.generate::<P256>().unwrap();

        // msg1 should be 162 bytes (65 ephemeral + 65 encrypted static + 16 tag + 16 payload tag) — feed 64 instead.
        let (_unused, r_pipe) = Pipe::pair();
        let bad_msg = [0u8; 64];
        r_pipe.feed(&bad_msg);

        let r_hs = SyncHandshake::<Channel, Responder, _, _, _, _>::respond(
            EphemeralOnly::new(StdRng::from_os_rng()),
            &[],
            r_pipe.clone(),
        )
        .set_s(responder_static)
        .unwrap();

        // The streaming driver has no length pre-check: a too-short message
        // makes a token's `read_exact` run out of bytes, so the responder
        // rejects it with a short-read IO error at the first token.
        assert!(r_hs.recv().e().is_err());
    }

    #[test]
    fn expected_message_size_reports_correctly() {
        // The streaming driver removed the runtime `expected_message_size`
        // query; the same value is available at compile time from the
        // message-size macro. msg1 (-> e, es, s, ss, psk):
        // 65 (ephemeral) + 65 (encrypted static) + 16 (tag) + 16 (payload tag) = 162
        assert_eq!(
            noise_message_size!(curve: P256, cipher: ChaChaPoly, has_psk: true, keyed: false, tokens: [E, Es, S, Ss, Psk],),
            162
        );
    }

    #[test]
    fn corrupted_encrypted_static_in_msg1_rejected() {
        let mut provider = EphemeralOnly::new(StdRng::from_os_rng());

        let initiator_static = provider.generate::<P256>().unwrap();
        let responder_static = provider.generate::<P256>().unwrap();
        let responder_pub = provider.public(&responder_static).unwrap();

        let psk = Psk::from_bytes([0xBB; 32]);

        let (i_pipe, r_pipe) = Pipe::pair();

        // Initiator constructs msg1 normally.
        let i_hs = SyncHandshake::<Channel, Initiator, _, _, _, _>::initiate(
            EphemeralOnly::new(StdRng::from_os_rng()),
            &[],
            i_pipe.clone(),
        )
        .set_rs(responder_pub);

        let _i_hs = i_hs
            .e()
            .unwrap()
            .es()
            .unwrap()
            .s(initiator_static)
            .unwrap()
            .ss()
            .unwrap()
            .psk(&psk)
            .unwrap();

        // Corrupt a byte in the encrypted static key area (after the 65-byte ephemeral).
        // `take_written` drains the linked queue, so only the tampered copy
        // reaches the responder.
        let mut corrupted = i_pipe.take_written();
        corrupted[70] ^= 0xFF;

        // Responder reads msg1 — corruption in the encrypted static key
        // area causes decryption failure at the `s` token.
        r_pipe.feed(&corrupted);
        let r_hs = SyncHandshake::<Channel, Responder, _, _, _, _>::respond(
            EphemeralOnly::new(StdRng::from_os_rng()),
            &[],
            r_pipe.clone(),
        )
        .set_s(responder_static)
        .unwrap();

        let (_, recv) = r_hs.recv().e().unwrap();
        let recv = recv.es().unwrap();
        // The `s` token decrypts the static key — corruption causes tag failure.
        assert!(recv.s().is_err());
    }

    #[test]
    fn mismatched_psk_fails() {
        let mut provider = EphemeralOnly::new(StdRng::from_os_rng());

        let initiator_static = provider.generate::<P256>().unwrap();
        let responder_static = provider.generate::<P256>().unwrap();
        let responder_pub = provider.public(&responder_static).unwrap();

        let i_psk = Psk::from_bytes([0xAA; 32]);
        let r_psk = Psk::from_bytes([0xBB; 32]); // different!

        let (i_pipe, r_pipe) = Pipe::pair();

        // Initiator sends msg1 with i_psk.
        let i_hs = SyncHandshake::<Channel, Initiator, _, _, _, _>::initiate(
            EphemeralOnly::new(StdRng::from_os_rng()),
            &[],
            i_pipe.clone(),
        )
        .set_rs(responder_pub);

        let _i_hs = i_hs
            .e()
            .unwrap()
            .es()
            .unwrap()
            .s(initiator_static)
            .unwrap()
            .ss()
            .unwrap()
            .psk(&i_psk)
            .unwrap();
        let msg1 = i_pipe.take_written();

        // Responder reads msg1 with r_psk — mismatch.
        r_pipe.feed(&msg1);
        let r_hs = SyncHandshake::<Channel, Responder, _, _, _, _>::respond(
            EphemeralOnly::new(StdRng::from_os_rng()),
            &[],
            r_pipe.clone(),
        )
        .set_s(responder_static)
        .unwrap();

        let (_, recv) = r_hs.recv().e().unwrap();
        let recv = recv.es().unwrap();
        let (_, recv) = recv.s().unwrap();
        let recv = recv.ss().unwrap();

        // The psk token is the last in msg1 — the payload tag
        // verification catches the PSK mismatch immediately.
        let result = recv.psk(&r_psk);
        assert!(result.is_err());
    }

    #[test]
    fn transport_corrupted_ciphertext_rejected() {
        let mut provider = EphemeralOnly::new(StdRng::from_os_rng());

        let initiator_static = provider.generate::<P256>().unwrap();
        let responder_static = provider.generate::<P256>().unwrap();
        let responder_pub = provider.public(&responder_static).unwrap();
        let psk = Psk::from_bytes([0xCC; 32]);

        // Complete handshake.
        let (i_pipe, r_pipe) = Pipe::pair();
        let i_hs = SyncHandshake::<Channel, Initiator, _, _, _, _>::initiate(
            EphemeralOnly::new(StdRng::from_os_rng()),
            &[],
            i_pipe.clone(),
        )
        .set_rs(responder_pub);
        let r_hs = SyncHandshake::<Channel, Responder, _, _, _, _>::respond(
            EphemeralOnly::new(StdRng::from_os_rng()),
            &[],
            r_pipe.clone(),
        )
        .set_s(responder_static)
        .unwrap();

        let i_hs = i_hs
            .e()
            .unwrap()
            .es()
            .unwrap()
            .s(initiator_static)
            .unwrap()
            .ss()
            .unwrap()
            .psk(&psk)
            .unwrap();
        let (_, recv) = r_hs.recv().e().unwrap();
        let recv = recv.es().unwrap();
        let (_, recv) = recv.s().unwrap();
        let recv = recv.ss().unwrap();
        let r_hs = recv.psk(&psk).unwrap();

        let (r_transport, _) = r_hs.e().unwrap().ee().unwrap().se().unwrap().into_parts();
        let (_, recv) = i_hs.recv().e().unwrap();
        let (i_transport, _) = recv.ee().unwrap().se().unwrap().into_parts();

        let mut i_transport = i_transport;
        let mut r_transport = r_transport;

        // Encrypt a message, then corrupt it.
        let mut ct_buf = [0u8; 256];
        let ct_len = i_transport.send(b"secret", &mut ct_buf).unwrap();
        ct_buf[0] ^= 0xFF;

        let mut pt_buf = [0u8; 256];
        let err = r_transport
            .receive(&ct_buf[..ct_len], &mut pt_buf)
            .unwrap_err();
        assert!(matches!(err, error::HandshakeError::DecryptionFailed));
    }

    #[test]
    fn transport_multiple_messages_nonce_advances() {
        let mut provider = EphemeralOnly::new(StdRng::from_os_rng());

        let initiator_static = provider.generate::<P256>().unwrap();
        let responder_static = provider.generate::<P256>().unwrap();
        let responder_pub = provider.public(&responder_static).unwrap();
        let psk = Psk::from_bytes([0xDD; 32]);

        // Complete handshake.
        let (i_pipe, r_pipe) = Pipe::pair();
        let i_hs = SyncHandshake::<Channel, Initiator, _, _, _, _>::initiate(
            EphemeralOnly::new(StdRng::from_os_rng()),
            &[],
            i_pipe.clone(),
        )
        .set_rs(responder_pub);
        let r_hs = SyncHandshake::<Channel, Responder, _, _, _, _>::respond(
            EphemeralOnly::new(StdRng::from_os_rng()),
            &[],
            r_pipe.clone(),
        )
        .set_s(responder_static)
        .unwrap();

        let i_hs = i_hs
            .e()
            .unwrap()
            .es()
            .unwrap()
            .s(initiator_static)
            .unwrap()
            .ss()
            .unwrap()
            .psk(&psk)
            .unwrap();
        let (_, recv) = r_hs.recv().e().unwrap();
        let recv = recv.es().unwrap();
        let (_, recv) = recv.s().unwrap();
        let recv = recv.ss().unwrap();
        let r_hs = recv.psk(&psk).unwrap();

        let (r_transport, _) = r_hs.e().unwrap().ee().unwrap().se().unwrap().into_parts();
        let (_, recv) = i_hs.recv().e().unwrap();
        let (i_transport, _) = recv.ee().unwrap().se().unwrap().into_parts();

        let mut i_transport = i_transport;
        let mut r_transport = r_transport;

        // Send 10 messages in each direction — nonce must advance correctly.
        let mut ct_buf = [0u8; 256];
        let mut pt_buf = [0u8; 256];
        for i in 0u32..10 {
            let msg = format!("message {i}");
            let ct_len = i_transport.send(msg.as_bytes(), &mut ct_buf).unwrap();
            let pt_len = r_transport.receive(&ct_buf[..ct_len], &mut pt_buf).unwrap();
            assert_eq!(&pt_buf[..pt_len], msg.as_bytes());

            let reply = format!("reply {i}");
            let ct_len = r_transport.send(reply.as_bytes(), &mut ct_buf).unwrap();
            let pt_len = i_transport.receive(&ct_buf[..ct_len], &mut pt_buf).unwrap();
            assert_eq!(&pt_buf[..pt_len], reply.as_bytes());
        }
    }

    // ── SymmetricState long protocol name hashing ─────────────────

    #[test]
    fn symmetric_state_long_protocol_name() {
        // A protocol name longer than HASHLEN (64) should be hashed.
        let long_name = "A".repeat(100);
        let ss = symmetric_state::SymmetricState::<ChaChaPoly, Blake2b>::initialize(&long_name);
        // Just verify it doesn't panic and the hash is 64 bytes.
        assert_eq!(ss.handshake_hash().len(), 64);
    }

    // ── Wrong responder static key ──────────────────────────────────

    #[test]
    fn ikpsk1_wrong_responder_key_rejected() {
        let mut provider = EphemeralOnly::new(StdRng::from_os_rng());

        let initiator_static = provider.generate::<P256>().unwrap();
        let responder_static = provider.generate::<P256>().unwrap();
        let wrong_static = provider.generate::<P256>().unwrap();
        let wrong_pub = provider.public(&wrong_static).unwrap();
        let psk = Psk::from_bytes([0xCC; 32]);

        let (i_pipe, r_pipe) = Pipe::pair();

        // Initiator targets the wrong responder public key.
        let i_hs = SyncHandshake::<Channel, Initiator, _, _, _, _>::initiate(
            EphemeralOnly::new(StdRng::from_os_rng()),
            &[],
            i_pipe.clone(),
        )
        .set_rs(wrong_pub);

        // Initiator sends msg1 with es DH against the wrong key.
        let _i_hs = i_hs
            .e()
            .unwrap()
            .es()
            .unwrap()
            .s(initiator_static)
            .unwrap()
            .ss()
            .unwrap()
            .psk(&psk)
            .unwrap();
        let msg1 = i_pipe.take_written();

        // Actual responder holds a different static key.
        r_pipe.feed(&msg1);
        let r_hs = SyncHandshake::<Channel, Responder, _, _, _, _>::respond(
            EphemeralOnly::new(StdRng::from_os_rng()),
            &[],
            r_pipe.clone(),
        )
        .set_s(responder_static)
        .unwrap();

        // Responder reads msg1. The es DH produces a different shared
        // secret because the initiator used the wrong responder key.
        // The `es` token itself succeeds (it just mixes in the DH result),
        // but the `s` token fails because the derived cipher key is wrong
        // and cannot decrypt the initiator's encrypted static key.
        let (_, recv) = r_hs.recv().e().unwrap();
        let recv = recv.es().unwrap();
        let result = recv.s();
        assert!(result.is_err());
    }

    // ── Transport direction isolation ───────────────────────────────

    #[test]
    fn transport_keys_are_directional() {
        let mut provider = EphemeralOnly::new(StdRng::from_os_rng());

        let initiator_static = provider.generate::<P256>().unwrap();
        let responder_static = provider.generate::<P256>().unwrap();
        let responder_pub = provider.public(&responder_static).unwrap();
        let psk = Psk::from_bytes([0xFF; 32]);

        // Complete handshake.
        let (i_pipe, r_pipe) = Pipe::pair();
        let i_hs = SyncHandshake::<Channel, Initiator, _, _, _, _>::initiate(
            EphemeralOnly::new(StdRng::from_os_rng()),
            &[],
            i_pipe.clone(),
        )
        .set_rs(responder_pub);
        let r_hs = SyncHandshake::<Channel, Responder, _, _, _, _>::respond(
            EphemeralOnly::new(StdRng::from_os_rng()),
            &[],
            r_pipe.clone(),
        )
        .set_s(responder_static)
        .unwrap();

        let i_hs = i_hs
            .e()
            .unwrap()
            .es()
            .unwrap()
            .s(initiator_static)
            .unwrap()
            .ss()
            .unwrap()
            .psk(&psk)
            .unwrap();
        let (_, recv) = r_hs.recv().e().unwrap();
        let recv = recv.es().unwrap();
        let (_, recv) = recv.s().unwrap();
        let recv = recv.ss().unwrap();
        let r_hs = recv.psk(&psk).unwrap();

        let (r_transport, _) = r_hs.e().unwrap().ee().unwrap().se().unwrap().into_parts();
        let (_, recv) = i_hs.recv().e().unwrap();
        let (i_transport, _) = recv.ee().unwrap().se().unwrap().into_parts();

        let mut i_transport = i_transport;

        // Initiator sends a message.
        let mut ct_buf = [0u8; 256];
        let ct_len = i_transport.send(b"hello", &mut ct_buf).unwrap();

        // Trying to decrypt with the initiator's own receive channel
        // must fail — transport keys are directional.
        let mut pt_buf = [0u8; 256];
        let err = i_transport
            .receive(&ct_buf[..ct_len], &mut pt_buf)
            .unwrap_err();
        assert!(matches!(err, error::HandshakeError::DecryptionFailed));

        // But the responder can decrypt it.
        let mut r_transport = r_transport;
        let pt_len = r_transport.receive(&ct_buf[..ct_len], &mut pt_buf).unwrap();
        assert_eq!(&pt_buf[..pt_len], b"hello");
    }

    // ── Session uniqueness (different ephemeral keys) ───────────────

    #[test]
    fn two_sessions_produce_different_handshake_hashes() {
        // Use a fixed responder key so both sessions share the same
        // responder identity — only ephemeral keys differ.
        let responder_bytes = [0xBB_u8; 32];
        let psk = Psk::from_bytes([0xAA; 32]);

        let mut hashes = Vec::new();

        for _ in 0..2 {
            let responder_static =
                P256r1PrivateKey::from_bytes(responder_bytes).expect("valid test scalar");
            let responder_pub = responder_static.public();

            let initiator_static = EphemeralOnly::new(StdRng::from_os_rng())
                .generate::<P256>()
                .unwrap();

            let (i_pipe, r_pipe) = Pipe::pair();
            let i_hs = SyncHandshake::<Channel, Initiator, _, _, _, _>::initiate(
                EphemeralOnly::new(StdRng::from_os_rng()),
                &[],
                i_pipe.clone(),
            )
            .set_rs(responder_pub);

            let i_hs = i_hs
                .e()
                .unwrap()
                .es()
                .unwrap()
                .s(initiator_static)
                .unwrap()
                .ss()
                .unwrap()
                .psk(&psk)
                .unwrap();

            let r_hs = SyncHandshake::<Channel, Responder, _, _, _, _>::respond(
                EphemeralOnly::new(StdRng::from_os_rng()),
                &[],
                r_pipe.clone(),
            )
            .set_s(responder_static)
            .unwrap();

            let (_, recv) = r_hs.recv().e().unwrap();
            let recv = recv.es().unwrap();
            let (_, recv) = recv.s().unwrap();
            let recv = recv.ss().unwrap();
            let r_hs = recv.psk(&psk).unwrap();

            let (r_transport, _) = r_hs.e().unwrap().ee().unwrap().se().unwrap().into_parts();
            let (_, recv) = i_hs.recv().e().unwrap();
            let (i_transport, _) = recv.ee().unwrap().se().unwrap().into_parts();

            assert_eq!(i_transport.session_id(), r_transport.session_id());
            hashes.push(i_transport.session_id().as_ref().to_vec());
        }

        // Two sessions with different ephemeral keys must produce
        // different handshake hashes.
        assert_ne!(hashes[0], hashes[1]);
    }

    // ── IKpsk1: wrong initiator static key in msg1 ──────────────────

    #[tokio::test]
    async fn ikpsk1_wrong_initiator_static_in_msg1() {
        let mut provider = EphemeralOnly::new(StdRng::from_os_rng());

        let initiator_static = provider.generate::<P256>().unwrap();
        let initiator_pub = provider.public(&initiator_static).unwrap();
        let responder_static = provider.generate::<P256>().unwrap();
        let responder_pub = provider.public(&responder_static).unwrap();
        let psk = Psk::from_bytes([0xCC; 32]);

        // Initiator sends msg1 with the WRONG static key.
        // In IKpsk1 msg1 (-> e, es, s, ss, psk), the `ss` token is
        // DH(wrong_s, responder_s). Since the responder decrypts the
        // wrong key from the `s` token and computes the same ECDH result,
        // the handshake completes — but the responder sees a different
        // initiator identity. The application layer must verify the
        // revealed static key matches the expected peer.
        let wrong_static = provider.generate::<P256>().unwrap();

        let (i_pipe, r_pipe) = Pipe::pair();
        let i_hs = SyncHandshake::<Channel, Initiator, _, _, _, _>::initiate(
            EphemeralOnly::new(StdRng::from_os_rng()),
            &[],
            i_pipe.clone(),
        )
        .set_rs(responder_pub);

        let i_hs = i_hs
            .e()
            .unwrap()
            .es()
            .unwrap()
            .s(wrong_static)
            .unwrap()
            .ss()
            .unwrap()
            .psk(&psk)
            .unwrap();

        let r_hs = SyncHandshake::<Channel, Responder, _, _, _, _>::respond(
            EphemeralOnly::new(StdRng::from_os_rng()),
            &[],
            r_pipe.clone(),
        )
        .set_s(responder_static)
        .unwrap();

        let (_, recv) = r_hs.recv().e().unwrap();
        let recv = recv.es().unwrap();
        let (revealed_pub, recv) = recv.s().unwrap();
        let recv = recv.ss().unwrap();
        let r_hs = recv.psk(&psk).unwrap();

        // The responder decrypted the wrong initiator static key.
        assert_ne!(revealed_pub, initiator_pub);

        // Complete the handshake — msg2 still works because the `se`
        // token uses DH(wrong_s, responder_e), which both sides compute
        // consistently.
        let (r_transport, _) = r_hs.e().unwrap().ee().unwrap().se().unwrap().into_parts();
        let (_, recv) = i_hs.recv().e().unwrap();
        let (i_transport, _) = recv.ee().unwrap().se().unwrap().into_parts();

        // Transport works — keys are derived consistently from the wrong
        // static key. The responder must reject this identity at the
        // application layer. The handshake hash also differs from what
        // the real initiator would produce, so channel binding catches it.
        assert_eq!(i_transport.session_id(), r_transport.session_id());
        drop(i_transport);
        drop(r_transport);
    }

    // ── Corrupted msg1 (tampered ephemeral in IKpsk1) ─────────────────

    #[test]
    fn ikpsk1_corrupted_msg1_rejected() {
        let mut provider = EphemeralOnly::new(StdRng::from_os_rng());

        let initiator_static = provider.generate::<P256>().unwrap();
        let responder_static = provider.generate::<P256>().unwrap();
        let responder_pub = provider.public(&responder_static).unwrap();
        let psk = Psk::from_bytes([0xDD; 32]);

        let (i_pipe, r_pipe) = Pipe::pair();
        let i_hs = SyncHandshake::<Channel, Initiator, _, _, _, _>::initiate(
            EphemeralOnly::new(StdRng::from_os_rng()),
            &[],
            i_pipe.clone(),
        )
        .set_rs(responder_pub);

        let _i_hs = i_hs
            .e()
            .unwrap()
            .es()
            .unwrap()
            .s(initiator_static)
            .unwrap()
            .ss()
            .unwrap()
            .psk(&psk)
            .unwrap();
        // `take_written` drains the linked queue so only the tampered copy
        // reaches the responder.
        let mut corrupted = i_pipe.take_written();
        // Corrupt a byte in the ephemeral public key.
        corrupted[5] ^= 0xFF;

        r_pipe.feed(&corrupted);
        let r_hs = SyncHandshake::<Channel, Responder, _, _, _, _>::respond(
            EphemeralOnly::new(StdRng::from_os_rng()),
            &[],
            r_pipe.clone(),
        )
        .set_s(responder_static)
        .unwrap();

        // Responder reads msg1 — corruption may produce an invalid curve
        // point (caught at `e()`) or a valid but wrong point (caught at
        // `es()` when the payload tag fails). Either way, the handshake
        // must not complete.
        match r_hs.recv().e() {
            Err(_) => {} // invalid point — rejected at e() token
            Ok((_, recv)) => {
                // Valid point but wrong — es DH + payload tag catches it.
                assert!(recv.es().is_err());
            }
        }
    }

    // ── Corrupted msg2 (tampered ephemeral in IKpsk1) ─────────────────

    #[test]
    fn ikpsk1_corrupted_msg2_rejected() {
        let mut provider = EphemeralOnly::new(StdRng::from_os_rng());

        let initiator_static = provider.generate::<P256>().unwrap();
        let responder_static = provider.generate::<P256>().unwrap();
        let responder_pub = provider.public(&responder_static).unwrap();
        let psk = Psk::from_bytes([0xDD; 32]);

        let (i_pipe, r_pipe) = Pipe::pair();
        let i_hs = SyncHandshake::<Channel, Initiator, _, _, _, _>::initiate(
            EphemeralOnly::new(StdRng::from_os_rng()),
            &[],
            i_pipe.clone(),
        )
        .set_rs(responder_pub);
        let r_hs = SyncHandshake::<Channel, Responder, _, _, _, _>::respond(
            EphemeralOnly::new(StdRng::from_os_rng()),
            &[],
            r_pipe.clone(),
        )
        .set_s(responder_static)
        .unwrap();

        // msg1 flows through cleanly so the responder can produce msg2.
        let i_hs = i_hs
            .e()
            .unwrap()
            .es()
            .unwrap()
            .s(initiator_static)
            .unwrap()
            .ss()
            .unwrap()
            .psk(&psk)
            .unwrap();
        let (_, recv) = r_hs.recv().e().unwrap();
        let recv = recv.es().unwrap();
        let (_, recv) = recv.s().unwrap();
        let recv = recv.ss().unwrap();
        let r_hs = recv.psk(&psk).unwrap();

        // msg2 is captured off the responder's wire, tampered, then fed to
        // the initiator. `take_written` drains the linked queue so only the
        // tampered copy reaches the initiator.
        let (_r_transport, _) = r_hs.e().unwrap().ee().unwrap().se().unwrap().into_parts();
        let mut corrupted = r_pipe.take_written();
        // Corrupt a byte in the responder's ephemeral public key.
        corrupted[3] ^= 0xFF;

        i_pipe.feed(&corrupted);

        // Corruption may produce an invalid curve point (caught at `e()`)
        // or a valid but wrong point (caught at `ee()` payload tag).
        match i_hs.recv().e() {
            Err(_) => {} // invalid point — rejected at e() token
            Ok((_, recv)) => {
                assert!(recv.ee().is_err());
            }
        }
    }

    // ── Transport replay detection (nonce desync) ─────────────────────

    #[test]
    fn transport_replayed_message_rejected() {
        let mut provider = EphemeralOnly::new(StdRng::from_os_rng());

        let initiator_static = provider.generate::<P256>().unwrap();
        let responder_static = provider.generate::<P256>().unwrap();
        let responder_pub = provider.public(&responder_static).unwrap();
        let psk = Psk::from_bytes([0xEE; 32]);

        // Complete handshake.
        let (i_pipe, r_pipe) = Pipe::pair();
        let i_hs = SyncHandshake::<Channel, Initiator, _, _, _, _>::initiate(
            EphemeralOnly::new(StdRng::from_os_rng()),
            &[],
            i_pipe.clone(),
        )
        .set_rs(responder_pub);
        let r_hs = SyncHandshake::<Channel, Responder, _, _, _, _>::respond(
            EphemeralOnly::new(StdRng::from_os_rng()),
            &[],
            r_pipe.clone(),
        )
        .set_s(responder_static)
        .unwrap();

        let i_hs = i_hs
            .e()
            .unwrap()
            .es()
            .unwrap()
            .s(initiator_static)
            .unwrap()
            .ss()
            .unwrap()
            .psk(&psk)
            .unwrap();
        let (_, recv) = r_hs.recv().e().unwrap();
        let recv = recv.es().unwrap();
        let (_, recv) = recv.s().unwrap();
        let recv = recv.ss().unwrap();
        let r_hs = recv.psk(&psk).unwrap();

        let (r_transport, _) = r_hs.e().unwrap().ee().unwrap().se().unwrap().into_parts();
        let (_, recv) = i_hs.recv().e().unwrap();
        let (i_transport, _) = recv.ee().unwrap().se().unwrap().into_parts();

        let mut i_transport = i_transport;
        let mut r_transport = r_transport;

        // Send a message and receive it normally.
        let mut ct_buf = [0u8; 256];
        let ct_len = i_transport.send(b"first message", &mut ct_buf).unwrap();
        let captured = ct_buf[..ct_len].to_vec();

        let mut pt_buf = [0u8; 256];
        let pt_len = r_transport.receive(&captured, &mut pt_buf).unwrap();
        assert_eq!(&pt_buf[..pt_len], b"first message");

        // Replay the same ciphertext — nonce has advanced, so it must fail.
        let err = r_transport.receive(&captured, &mut pt_buf).unwrap_err();
        assert!(matches!(err, error::HandshakeError::DecryptionFailed));
    }

    // ── Large payload transport ───────────────────────────────────────

    #[test]
    fn transport_enforces_max_message_length() {
        let mut provider = EphemeralOnly::new(StdRng::from_os_rng());

        let initiator_static = provider.generate::<P256>().unwrap();
        let responder_static = provider.generate::<P256>().unwrap();
        let responder_pub = provider.public(&responder_static).unwrap();
        let psk = Psk::from_bytes([0xFF; 32]);

        // Complete handshake.
        let (i_pipe, r_pipe) = Pipe::pair();
        let i_hs = SyncHandshake::<Channel, Initiator, _, _, _, _>::initiate(
            EphemeralOnly::new(StdRng::from_os_rng()),
            &[],
            i_pipe.clone(),
        )
        .set_rs(responder_pub);
        let r_hs = SyncHandshake::<Channel, Responder, _, _, _, _>::respond(
            EphemeralOnly::new(StdRng::from_os_rng()),
            &[],
            r_pipe.clone(),
        )
        .set_s(responder_static)
        .unwrap();

        let i_hs = i_hs
            .e()
            .unwrap()
            .es()
            .unwrap()
            .s(initiator_static)
            .unwrap()
            .ss()
            .unwrap()
            .psk(&psk)
            .unwrap();
        let (_, recv) = r_hs.recv().e().unwrap();
        let recv = recv.es().unwrap();
        let (_, recv) = recv.s().unwrap();
        let recv = recv.ss().unwrap();
        let r_hs = recv.psk(&psk).unwrap();

        let (r_transport, _) = r_hs.e().unwrap().ee().unwrap().se().unwrap().into_parts();
        let (_, recv) = i_hs.recv().e().unwrap();
        let (i_transport, _) = recv.ee().unwrap().se().unwrap().into_parts();

        let mut i_transport = i_transport;
        let mut r_transport = r_transport;

        // Largest payload whose on-wire message (ciphertext + 16-byte tag)
        // still fits the 65535-byte Noise cap: 65535 - 16 = 65519.
        let max_payload: Vec<u8> = (0..65519).map(|i| (i % 256) as u8).collect();
        let mut ct_buf = vec![0u8; max_payload.len() + 16];
        let ct_len = i_transport.send(&max_payload, &mut ct_buf).unwrap();
        assert_eq!(ct_len, 65535); // exactly the cap

        let mut pt_buf = vec![0u8; max_payload.len()];
        let pt_len = r_transport.receive(&ct_buf[..ct_len], &mut pt_buf).unwrap();
        assert_eq!(&pt_buf[..pt_len], &max_payload[..]);

        // One byte more overflows the cap (message would be 65536) and must
        // be rejected, not emitted as a non-conformant message.
        let over_payload = vec![0u8; 65520];
        let mut ct_buf = vec![0u8; over_payload.len() + 16];
        let err = i_transport.send(&over_payload, &mut ct_buf).unwrap_err();
        assert!(matches!(
            err,
            error::HandshakeError::MessageTooLong { len: 65536 }
        ));

        // The receive side likewise rejects an over-cap incoming message
        // before attempting any decryption.
        let oversize = vec![0u8; 65536];
        let mut pt_buf = vec![0u8; oversize.len()];
        let err = r_transport.receive(&oversize, &mut pt_buf).unwrap_err();
        assert!(matches!(
            err,
            error::HandshakeError::MessageTooLong { len: 65536 }
        ));
    }

    // ── Rekey tests ────────────────────────────────────────────────

    #[test]
    fn transport_rekey_then_communicate() {
        let mut provider = EphemeralOnly::new(StdRng::from_os_rng());

        let initiator_static = provider.generate::<P256>().unwrap();
        let responder_static = provider.generate::<P256>().unwrap();
        let responder_pub = provider.public(&responder_static).unwrap();
        let psk = Psk::from_bytes([0x11; 32]);

        // Complete handshake.
        let (i_pipe, r_pipe) = Pipe::pair();
        let i_hs = SyncHandshake::<Channel, Initiator, _, _, _, _>::initiate(
            EphemeralOnly::new(StdRng::from_os_rng()),
            &[],
            i_pipe.clone(),
        )
        .set_rs(responder_pub);
        let r_hs = SyncHandshake::<Channel, Responder, _, _, _, _>::respond(
            EphemeralOnly::new(StdRng::from_os_rng()),
            &[],
            r_pipe.clone(),
        )
        .set_s(responder_static)
        .unwrap();

        let i_hs = i_hs
            .e()
            .unwrap()
            .es()
            .unwrap()
            .s(initiator_static)
            .unwrap()
            .ss()
            .unwrap()
            .psk(&psk)
            .unwrap();
        let (_, recv) = r_hs.recv().e().unwrap();
        let recv = recv.es().unwrap();
        let (_, recv) = recv.s().unwrap();
        let recv = recv.ss().unwrap();
        let r_hs = recv.psk(&psk).unwrap();

        let (r_transport, _) = r_hs.e().unwrap().ee().unwrap().se().unwrap().into_parts();
        let (_, recv) = i_hs.recv().e().unwrap();
        let (i_transport, _) = recv.ee().unwrap().se().unwrap().into_parts();

        let mut i_transport = i_transport;
        let mut r_transport = r_transport;

        // Send a message before rekey.
        let mut ct = [0u8; 256];
        let mut pt = [0u8; 256];
        let ct_len = i_transport.send(b"before rekey", &mut ct).unwrap();
        let pt_len = r_transport.receive(&ct[..ct_len], &mut pt).unwrap();
        assert_eq!(&pt[..pt_len], b"before rekey");

        // Rekey both sides.
        i_transport.rekey().unwrap();
        r_transport.rekey().unwrap();

        // Communication must still work after rekey.
        let ct_len = i_transport.send(b"after rekey", &mut ct).unwrap();
        let pt_len = r_transport.receive(&ct[..ct_len], &mut pt).unwrap();
        assert_eq!(&pt[..pt_len], b"after rekey");

        // Reverse direction also works.
        let ct_len = r_transport.send(b"reply after rekey", &mut ct).unwrap();
        let pt_len = i_transport.receive(&ct[..ct_len], &mut pt).unwrap();
        assert_eq!(&pt[..pt_len], b"reply after rekey");
    }

    /// Exercises the split-transport API: `Transport::split` and the
    /// resulting `TransportSend`/`TransportRecv` halves (encrypt/decrypt/
    /// rekey/session_id/ephemeral accessors), plus the `Transport`-level
    /// ephemeral accessors. IKpsk1 is interactive, so both sides hold a
    /// local *and* a remote ephemeral.
    #[test]
    fn transport_split_round_trip() {
        let mut provider = EphemeralOnly::new(StdRng::from_os_rng());

        let initiator_static = provider.generate::<P256>().unwrap();
        let responder_static = provider.generate::<P256>().unwrap();
        let responder_pub = provider.public(&responder_static).unwrap();
        let psk = Psk::from_bytes([0x5A; 32]);

        // Complete handshake.
        let (i_pipe, r_pipe) = Pipe::pair();
        let i_hs = SyncHandshake::<Channel, Initiator, _, _, _, _>::initiate(
            EphemeralOnly::new(StdRng::from_os_rng()),
            &[],
            i_pipe.clone(),
        )
        .set_rs(responder_pub);
        let r_hs = SyncHandshake::<Channel, Responder, _, _, _, _>::respond(
            EphemeralOnly::new(StdRng::from_os_rng()),
            &[],
            r_pipe.clone(),
        )
        .set_s(responder_static)
        .unwrap();

        let i_hs = i_hs
            .e()
            .unwrap()
            .es()
            .unwrap()
            .s(initiator_static)
            .unwrap()
            .ss()
            .unwrap()
            .psk(&psk)
            .unwrap();
        let (_, recv) = r_hs.recv().e().unwrap();
        let recv = recv.es().unwrap();
        let (_, recv) = recv.s().unwrap();
        let recv = recv.ss().unwrap();
        let r_hs = recv.psk(&psk).unwrap();

        let (r_transport, _) = r_hs.e().unwrap().ee().unwrap().se().unwrap().into_parts();
        let (_, recv) = i_hs.recv().e().unwrap();
        let (i_transport, _) = recv.ee().unwrap().se().unwrap().into_parts();

        // `Transport`-level ephemeral accessors: interactive pattern ⇒
        // both ephemerals present on each side. Both peers agree on the
        // session id (it is derived from the shared handshake hash).
        assert!(i_transport.local_ephemeral().is_some());
        assert!(i_transport.remote_ephemeral().is_some());
        assert!(r_transport.local_ephemeral().is_some());
        assert!(r_transport.remote_ephemeral().is_some());
        // `SessionId` is `PartialEq` but not `Debug`, so compare with `==`.
        assert!(i_transport.session_id() == r_transport.session_id());

        // Split each peer into independent send / receive halves.
        let (mut i_send, mut i_recv) = i_transport.split();
        let (mut r_send, mut r_recv) = r_transport.split();

        // Each half carries a clone of the session id and ephemerals.
        assert!(i_send.session_id() == i_recv.session_id());
        assert!(i_send.session_id() == r_recv.session_id());
        assert!(i_send.local_ephemeral().is_some());
        assert!(i_send.remote_ephemeral().is_some());
        assert!(r_recv.local_ephemeral().is_some());
        assert!(r_recv.remote_ephemeral().is_some());

        let mut ct = [0u8; 256];
        let mut pt = [0u8; 256];

        // initiator → responder across the split halves.
        let ct_len = i_send.encrypt(b"ping", &mut ct).unwrap();
        assert_eq!(ct_len, b"ping".len() + TransportSend::<Channel>::OVERHEAD);
        let pt_len = r_recv.decrypt(&ct[..ct_len], &mut pt).unwrap();
        assert_eq!(&pt[..pt_len], b"ping");

        // responder → initiator.
        let ct_len = r_send.encrypt(b"pong", &mut ct).unwrap();
        let pt_len = i_recv.decrypt(&ct[..ct_len], &mut pt).unwrap();
        assert_eq!(&pt[..pt_len], b"pong");

        // Rekey every half, then communication must still work both ways.
        i_send.rekey().unwrap();
        r_recv.rekey().unwrap();
        r_send.rekey().unwrap();
        i_recv.rekey().unwrap();

        let ct_len = i_send.encrypt(b"after rekey", &mut ct).unwrap();
        let pt_len = r_recv.decrypt(&ct[..ct_len], &mut pt).unwrap();
        assert_eq!(&pt[..pt_len], b"after rekey");

        let ct_len = r_send.encrypt(b"reply after rekey", &mut ct).unwrap();
        let pt_len = i_recv.decrypt(&ct[..ct_len], &mut pt).unwrap();
        assert_eq!(&pt[..pt_len], b"reply after rekey");
    }

    // ── Datagram-mode transport (into_datagram) ───────────────────────
    //
    // These exercise the out-of-order pair from `Transport::into_datagram`:
    // an explicit send counter that `hiss` owns, and a stateless receive
    // half that opens whatever counter it is handed. Each test runs a real
    // IKpsk1 handshake through the shared helper so the datagram pair is
    // backed by genuine, matched keys.

    /// Run a full IKpsk1 handshake over the in-memory `Pipe` harness and
    /// return the two completed transports `(initiator, responder)`. The
    /// datagram tests each need a real, matched transport pair; this factors
    /// out the handshake dance they would otherwise repeat verbatim.
    fn ikpsk1_transport_pair() -> (Transport<Channel>, Transport<Channel>) {
        let mut provider = EphemeralOnly::new(StdRng::from_os_rng());

        let initiator_static = provider.generate::<P256>().unwrap();
        let responder_static = provider.generate::<P256>().unwrap();
        let responder_pub = provider.public(&responder_static).unwrap();
        let psk = Psk::from_bytes([0x7A; 32]);

        let (i_pipe, r_pipe) = Pipe::pair();
        let i_hs = SyncHandshake::<Channel, Initiator, _, _, _, _>::initiate(
            EphemeralOnly::new(StdRng::from_os_rng()),
            &[],
            i_pipe.clone(),
        )
        .set_rs(responder_pub);
        let r_hs = SyncHandshake::<Channel, Responder, _, _, _, _>::respond(
            EphemeralOnly::new(StdRng::from_os_rng()),
            &[],
            r_pipe.clone(),
        )
        .set_s(responder_static)
        .unwrap();

        let i_hs = i_hs
            .e()
            .unwrap()
            .es()
            .unwrap()
            .s(initiator_static)
            .unwrap()
            .ss()
            .unwrap()
            .psk(&psk)
            .unwrap();
        let (_, recv) = r_hs.recv().e().unwrap();
        let recv = recv.es().unwrap();
        let (_, recv) = recv.s().unwrap();
        let recv = recv.ss().unwrap();
        let r_hs = recv.psk(&psk).unwrap();

        let (r_transport, _) = r_hs.e().unwrap().ee().unwrap().se().unwrap().into_parts();
        let (_, recv) = i_hs.recv().e().unwrap();
        let (i_transport, _) = recv.ee().unwrap().se().unwrap().into_parts();
        (i_transport, r_transport)
    }

    /// Seal several datagrams, shuffle them, and open each at its stated
    /// counter — all must decrypt. Also pins that `encrypt_next` hands out a
    /// strictly monotonic counter and that both halves share a session id.
    #[test]
    fn datagram_shuffled_delivery_all_open() {
        let (i_transport, r_transport) = ikpsk1_transport_pair();
        let (mut i_send, _i_recv) = i_transport.into_datagram();
        let (_r_send, r_recv) = r_transport.into_datagram();

        assert!(i_send.session_id() == r_recv.session_id());

        // Seal N messages, remembering each (counter, ciphertext).
        let mut ct = [0u8; 256];
        let mut sealed: Vec<(u64, Vec<u8>)> = Vec::new();
        for i in 0..8u64 {
            let msg = format!("datagram {i}");
            let (counter, ct_len) = i_send.encrypt_next(&[], msg.as_bytes(), &mut ct).unwrap();
            assert_eq!(counter, i); // hiss owns a strictly monotonic counter
            sealed.push((counter, ct[..ct_len].to_vec()));
        }

        // A fixed, non-trivial permutation keeps the shuffle deterministic.
        sealed.swap(0, 7);
        sealed.swap(1, 4);
        sealed.swap(2, 6);
        sealed.swap(3, 5);

        let mut pt = [0u8; 256];
        for (counter, packet) in &sealed {
            let pt_len = r_recv.decrypt_at(*counter, &[], packet, &mut pt).unwrap();
            assert_eq!(&pt[..pt_len], format!("datagram {counter}").as_bytes());
        }
    }

    /// A gap in the counter sequence (a dropped packet) does not stop later
    /// counters opening — the receive half is stateless.
    #[test]
    fn datagram_gap_later_counters_still_open() {
        let (i_transport, r_transport) = ikpsk1_transport_pair();
        let (mut i_send, _) = i_transport.into_datagram();
        let (_, r_recv) = r_transport.into_datagram();

        let mut ct = [0u8; 256];
        let mut sealed: Vec<(u64, Vec<u8>)> = Vec::new();
        for i in 0..5u64 {
            let msg = format!("packet {i}");
            let (counter, ct_len) = i_send.encrypt_next(&[], msg.as_bytes(), &mut ct).unwrap();
            sealed.push((counter, ct[..ct_len].to_vec()));
        }

        // Drop counter 2 entirely, as a lossy wire would — the rest still open.
        let mut pt = [0u8; 256];
        for (counter, packet) in sealed.iter().filter(|(c, _)| *c != 2) {
            let pt_len = r_recv.decrypt_at(*counter, &[], packet, &mut pt).unwrap();
            assert_eq!(&pt[..pt_len], format!("packet {counter}").as_bytes());
        }
    }

    /// The same counter can be opened twice (replay rejection is the
    /// caller's duty, documented on `decrypt_at`), while `encrypt_next`
    /// never re-issues a counter.
    #[test]
    fn datagram_replay_opens_and_counter_is_monotonic() {
        let (i_transport, r_transport) = ikpsk1_transport_pair();
        let (mut i_send, _) = i_transport.into_datagram();
        let (_, r_recv) = r_transport.into_datagram();

        // Counters handed out are strictly monotonic and never repeat.
        let mut ct = [0u8; 256];
        let mut seen: Vec<u64> = Vec::new();
        for _ in 0..4 {
            let (counter, _) = i_send.encrypt_next(&[], b"tick", &mut ct).unwrap();
            assert!(seen.iter().all(|c| *c != counter));
            seen.push(counter);
        }
        assert_eq!(seen, vec![0, 1, 2, 3]);

        // Seal one packet, then open the SAME counter twice — both succeed,
        // because the receiver keeps no state to reject a replay.
        let (counter, ct_len) = i_send.encrypt_next(&[], b"payload", &mut ct).unwrap();
        let mut pt = [0u8; 256];
        let first = r_recv
            .decrypt_at(counter, &[], &ct[..ct_len], &mut pt)
            .unwrap();
        assert_eq!(&pt[..first], b"payload");
        let second = r_recv
            .decrypt_at(counter, &[], &ct[..ct_len], &mut pt)
            .unwrap();
        assert_eq!(&pt[..second], b"payload");
    }

    /// Tampered ciphertext, the wrong associated data, and the wrong counter
    /// all error; a subsequent honest decrypt still succeeds, because
    /// `decrypt_at` is `&self` and cannot poison any state.
    #[test]
    fn datagram_bad_inputs_error_without_poisoning_state() {
        let (i_transport, r_transport) = ikpsk1_transport_pair();
        let (mut i_send, _) = i_transport.into_datagram();
        let (_, r_recv) = r_transport.into_datagram();

        let mut ct = [0u8; 256];
        let (counter, ct_len) = i_send.encrypt_next(b"ad", b"honest", &mut ct).unwrap();
        let good = ct[..ct_len].to_vec();
        let mut pt = [0u8; 256];

        // Tampered ciphertext → DecryptionFailed.
        let mut tampered = good.clone();
        tampered[0] ^= 0xFF;
        let err = r_recv
            .decrypt_at(counter, b"ad", &tampered, &mut pt)
            .unwrap_err();
        assert!(matches!(err, error::HandshakeError::DecryptionFailed));

        // Wrong associated data → DecryptionFailed.
        let err = r_recv
            .decrypt_at(counter, b"other", &good, &mut pt)
            .unwrap_err();
        assert!(matches!(err, error::HandshakeError::DecryptionFailed));

        // Wrong counter → DecryptionFailed.
        let err = r_recv
            .decrypt_at(counter + 1, b"ad", &good, &mut pt)
            .unwrap_err();
        assert!(matches!(err, error::HandshakeError::DecryptionFailed));

        // The honest decrypt at the true counter still works.
        let pt_len = r_recv.decrypt_at(counter, b"ad", &good, &mut pt).unwrap();
        assert_eq!(&pt[..pt_len], b"honest");
    }

    /// The send counter refuses to wrap: driven to `u64::MAX`, `encrypt_next`
    /// errors with `NonceOverflow` and writes nothing.
    #[test]
    fn datagram_encrypt_next_guards_nonce_exhaustion() {
        let (i_transport, _r_transport) = ikpsk1_transport_pair();
        let (mut i_send, _) = i_transport.into_datagram();

        // One short of the cap: this call succeeds and reports u64::MAX - 1.
        i_send.set_counter_for_test(u64::MAX - 1);
        let mut ct = [0u8; 64];
        let (counter, _) = i_send.encrypt_next(&[], b"x", &mut ct).unwrap();
        assert_eq!(counter, u64::MAX - 1);

        // The counter is now u64::MAX: the next seal must refuse to reuse the
        // nonce, and must leave the output untouched.
        let mut ct2 = [0xABu8; 64];
        let err = i_send.encrypt_next(&[], b"x", &mut ct2).unwrap_err();
        assert!(matches!(err, error::HandshakeError::NonceOverflow));
        assert_eq!(ct2, [0xABu8; 64]);
    }

    /// A datagram half and a stream half from the *same* handshake transcript
    /// interoperate for the in-order counter sequence 0, 1, 2, …: the
    /// explicit-nonce datagram path computes exactly the bytes the implicit-
    /// nonce stream path expects. This is the security argument that
    /// `into_datagram` invents no new cryptography — it only surfaces the
    /// nonce Noise already uses.
    #[test]
    fn datagram_and_stream_interoperate_in_order() {
        let (i_transport, r_transport) = ikpsk1_transport_pair();
        let (mut i_dg_send, i_dg_recv) = i_transport.into_datagram();
        let (mut r_send, mut r_recv) = r_transport.split();

        let mut ct = [0u8; 256];
        let mut pt = [0u8; 256];

        // Datagram sender → stream receiver: the stream half decrypts with
        // its implicit counter 0, 1, 2, …, proving the datagram bytes at
        // counter k are byte-for-byte the stream record k.
        for i in 0..4u64 {
            let msg = format!("dg->stream {i}");
            let (counter, ct_len) = i_dg_send
                .encrypt_next(&[], msg.as_bytes(), &mut ct)
                .unwrap();
            assert_eq!(counter, i);
            let pt_len = r_recv.decrypt(&ct[..ct_len], &mut pt).unwrap();
            assert_eq!(&pt[..pt_len], msg.as_bytes());
        }

        // Stream sender → datagram receiver: `decrypt_at` opens each stream
        // record at its explicit counter.
        for i in 0..4u64 {
            let msg = format!("stream->dg {i}");
            let ct_len = r_send.encrypt(msg.as_bytes(), &mut ct).unwrap();
            let pt_len = i_dg_recv
                .decrypt_at(i, &[], &ct[..ct_len], &mut pt)
                .unwrap();
            assert_eq!(&pt[..pt_len], msg.as_bytes());
        }

        // Both halves agree on the session id with their stream counterparts.
        assert!(i_dg_send.session_id() == r_recv.session_id());
        assert!(i_dg_recv.session_id() == r_send.session_id());
    }

    #[test]
    fn transport_rekey_desync_rejected() {
        let mut provider = EphemeralOnly::new(StdRng::from_os_rng());

        let initiator_static = provider.generate::<P256>().unwrap();
        let responder_static = provider.generate::<P256>().unwrap();
        let responder_pub = provider.public(&responder_static).unwrap();
        let psk = Psk::from_bytes([0x22; 32]);

        // Complete handshake.
        let (i_pipe, r_pipe) = Pipe::pair();
        let i_hs = SyncHandshake::<Channel, Initiator, _, _, _, _>::initiate(
            EphemeralOnly::new(StdRng::from_os_rng()),
            &[],
            i_pipe.clone(),
        )
        .set_rs(responder_pub);
        let r_hs = SyncHandshake::<Channel, Responder, _, _, _, _>::respond(
            EphemeralOnly::new(StdRng::from_os_rng()),
            &[],
            r_pipe.clone(),
        )
        .set_s(responder_static)
        .unwrap();

        let i_hs = i_hs
            .e()
            .unwrap()
            .es()
            .unwrap()
            .s(initiator_static)
            .unwrap()
            .ss()
            .unwrap()
            .psk(&psk)
            .unwrap();
        let (_, recv) = r_hs.recv().e().unwrap();
        let recv = recv.es().unwrap();
        let (_, recv) = recv.s().unwrap();
        let recv = recv.ss().unwrap();
        let r_hs = recv.psk(&psk).unwrap();

        let (r_transport, _) = r_hs.e().unwrap().ee().unwrap().se().unwrap().into_parts();
        let (_, recv) = i_hs.recv().e().unwrap();
        let (i_transport, _) = recv.ee().unwrap().se().unwrap().into_parts();

        let mut i_transport = i_transport;
        let mut r_transport = r_transport;

        // Only initiator rekeys — responder does not.
        i_transport.rekey().unwrap();

        // Messages encrypted with the new key cannot be decrypted
        // by the responder still using the old key.
        let mut ct = [0u8; 256];
        let ct_len = i_transport.send(b"desynced", &mut ct).unwrap();

        let mut pt = [0u8; 256];
        let err = r_transport.receive(&ct[..ct_len], &mut pt).unwrap_err();
        assert!(matches!(err, error::HandshakeError::DecryptionFailed));
    }

    #[test]
    fn rekey_without_key_fails() {
        let mut cs = cipher_state::CipherState::<ChaChaPoly>::empty();
        let err = cs.rekey().unwrap_err();
        assert!(matches!(err, error::HandshakeError::RekeyWithoutKey));
    }

    // ── Prologue tests ────────────────────────────────────────────────

    #[test]
    fn matching_prologue_succeeds() {
        let mut provider = EphemeralOnly::new(StdRng::from_os_rng());

        let responder_static = provider.generate::<P256>().unwrap();
        let responder_pub = provider.public(&responder_static).unwrap();

        let prologue = b"hiss/v1";

        type NoiseSeal = Noise<pattern::N, P256, ChaChaPoly, Blake2b>;

        let (i_pipe, r_pipe) = Pipe::pair();
        let sealer = SyncHandshake::<NoiseSeal, Initiator, _, _, _, _>::initiate(
            EphemeralOnly::new(StdRng::from_os_rng()),
            prologue,
            i_pipe.clone(),
        )
        .set_rs(responder_pub);
        let (mut i_transport, _) = sealer.e().unwrap().es().unwrap().into_parts();
        let msg = i_pipe.take_written();

        r_pipe.feed(&msg);
        let opener = SyncHandshake::<NoiseSeal, Responder, _, _, _, _>::respond(
            EphemeralOnly::new(StdRng::from_os_rng()),
            prologue,
            r_pipe.clone(),
        )
        .set_s(responder_static)
        .unwrap();
        let (_, recv) = opener.recv().e().unwrap();
        let (mut r_transport, _) = recv.es().unwrap().into_parts();

        // Transport works with matching prologue.
        let mut ct = [0u8; 64];
        let mut pt = [0u8; 64];
        let ct_len = i_transport.send(b"hello", &mut ct).unwrap();
        let pt_len = r_transport.receive(&ct[..ct_len], &mut pt).unwrap();
        assert_eq!(&pt[..pt_len], b"hello");
    }

    #[test]
    fn mismatched_prologue_rejected() {
        let mut provider = EphemeralOnly::new(StdRng::from_os_rng());

        let responder_static = provider.generate::<P256>().unwrap();
        let responder_pub = provider.public(&responder_static).unwrap();

        type NoiseSeal = Noise<pattern::N, P256, ChaChaPoly, Blake2b>;

        let (i_pipe, r_pipe) = Pipe::pair();
        // Initiator uses prologue "v1", responder uses "v2".
        let sealer = SyncHandshake::<NoiseSeal, Initiator, _, _, _, _>::initiate(
            EphemeralOnly::new(StdRng::from_os_rng()),
            b"v1",
            i_pipe.clone(),
        )
        .set_rs(responder_pub);
        let (_i_transport, _) = sealer.e().unwrap().es().unwrap().into_parts();
        let msg = i_pipe.take_written();

        r_pipe.feed(&msg);
        let opener = SyncHandshake::<NoiseSeal, Responder, _, _, _, _>::respond(
            EphemeralOnly::new(StdRng::from_os_rng()),
            b"v2",
            r_pipe.clone(),
        )
        .set_s(responder_static)
        .unwrap();
        let (_, recv) = opener.recv().e().unwrap();

        // The es token will fail because the handshake hashes diverge
        // due to different prologues — the payload AEAD tag won't match.
        assert!(recv.es().is_err());
    }

    // ── Output buffer too small ─────────────────────────────────────

    #[test]
    fn chacha_encrypt_output_buffer_too_small() {
        let key = [0u8; 32];
        let plaintext = b"hello world";
        let mut output = [0u8; 10]; // needs 11 + 16 = 27
        let err = ChaChaPoly::encrypt(&key, 0, &[], plaintext, &mut output).unwrap_err();
        assert!(matches!(
            err,
            error::HandshakeError::OutputBufferTooSmall { .. }
        ));
    }

    #[test]
    fn chacha_decrypt_output_buffer_too_small() {
        let key = [0u8; 32];
        // First encrypt something.
        let plaintext = b"hello world";
        let mut ct = [0u8; 64];
        let ct_len = ChaChaPoly::encrypt(&key, 0, &[], plaintext, &mut ct).unwrap();

        // Try to decrypt into a too-small buffer.
        let mut output = [0u8; 5]; // needs 11 bytes
        let err = ChaChaPoly::decrypt(&key, 0, &[], &ct[..ct_len], &mut output).unwrap_err();
        assert!(matches!(
            err,
            error::HandshakeError::OutputBufferTooSmall { .. }
        ));
    }

    // ── Property-based tests ──────────────────────────────────────────

    mod prop {
        use super::*;
        use crate::psk::Psk;
        use proptest::prelude::*;

        /// Complete an IKpsk1 handshake with the given keys and PSK,
        /// returning both transport states.
        fn full_ikpsk1_handshake(
            initiator_static: P256r1PrivateKey,
            responder_static: P256r1PrivateKey,
            psk: Psk,
        ) -> (transport::Transport<Channel>, transport::Transport<Channel>) {
            let provider = EphemeralOnly::new(StdRng::from_os_rng());
            let responder_pub = provider.public(&responder_static).unwrap();

            let (i_pipe, r_pipe) = Pipe::pair();
            let i_hs = SyncHandshake::<Channel, Initiator, _, _, _, _>::initiate(
                EphemeralOnly::new(StdRng::from_os_rng()),
                &[],
                i_pipe.clone(),
            )
            .set_rs(responder_pub);
            let r_hs = SyncHandshake::<Channel, Responder, _, _, _, _>::respond(
                EphemeralOnly::new(StdRng::from_os_rng()),
                &[],
                r_pipe.clone(),
            )
            .set_s(responder_static)
            .unwrap();

            let i_hs = i_hs
                .e()
                .unwrap()
                .es()
                .unwrap()
                .s(initiator_static)
                .unwrap()
                .ss()
                .unwrap()
                .psk(&psk)
                .unwrap();
            let (_, recv) = r_hs.recv().e().unwrap();
            let recv = recv.es().unwrap();
            let (_, recv) = recv.s().unwrap();
            let recv = recv.ss().unwrap();
            let r_hs = recv.psk(&psk).unwrap();

            let (r_transport, _) = r_hs.e().unwrap().ee().unwrap().se().unwrap().into_parts();
            let (_, recv) = i_hs.recv().e().unwrap();
            let (i_transport, _) = recv.ee().unwrap().se().unwrap().into_parts();

            (i_transport, r_transport)
        }

        proptest! {
            /// Any plaintext (up to 4 KiB) survives an IKpsk1 round-trip.
            #[test]
            fn transport_any_payload(
                plaintext in proptest::collection::vec(any::<u8>(), 0..4096),
                psk in any::<[u8; 32]>().prop_map(Psk::from_bytes),
            ) {
                let i_sk = EphemeralOnly::new(StdRng::from_os_rng()).generate::<P256>().unwrap();
                let r_sk = EphemeralOnly::new(StdRng::from_os_rng()).generate::<P256>().unwrap();

                let (mut i_t, mut r_t) = full_ikpsk1_handshake(i_sk, r_sk, psk);

                // Initiator → responder.
                let mut ct = vec![0u8; plaintext.len() + 16];
                let ct_len = i_t.send(&plaintext, &mut ct).unwrap();
                let mut pt = vec![0u8; plaintext.len()];
                let pt_len = r_t.receive(&ct[..ct_len], &mut pt).unwrap();
                prop_assert_eq!(&pt[..pt_len], &plaintext[..]);

                // Responder → initiator.
                let ct_len = r_t.send(&plaintext, &mut ct).unwrap();
                let pt_len = i_t.receive(&ct[..ct_len], &mut pt).unwrap();
                prop_assert_eq!(&pt[..pt_len], &plaintext[..]);
            }

            /// Corrupting any single byte in a transport ciphertext causes
            /// decryption failure.
            #[test]
            fn transport_any_corruption_detected(
                plaintext in proptest::collection::vec(any::<u8>(), 1..512),
                psk in any::<[u8; 32]>().prop_map(Psk::from_bytes),
                corrupt_pos_seed in any::<usize>(),
            ) {
                let i_sk = EphemeralOnly::new(StdRng::from_os_rng()).generate::<P256>().unwrap();
                let r_sk = EphemeralOnly::new(StdRng::from_os_rng()).generate::<P256>().unwrap();

                let (mut i_t, mut r_t) = full_ikpsk1_handshake(i_sk, r_sk, psk);

                let mut ct = vec![0u8; plaintext.len() + 16];
                let ct_len = i_t.send(&plaintext, &mut ct).unwrap();

                // Corrupt a single byte at a random position.
                let pos = corrupt_pos_seed % ct_len;
                ct[pos] ^= 0x01;

                let mut pt = vec![0u8; plaintext.len()];
                let result = r_t.receive(&ct[..ct_len], &mut pt);
                prop_assert!(result.is_err());
            }

            /// Random bytes fed as a handshake msg1 are always rejected.
            #[test]
            fn random_msg1_rejected(
                garbage in proptest::collection::vec(any::<u8>(), 162..163),
            ) {
                let r_sk = EphemeralOnly::new(StdRng::from_os_rng()).generate::<P256>().unwrap();
                let (_unused, r_pipe) = Pipe::pair();
                r_pipe.feed(&garbage);
                let r_hs = SyncHandshake::<Channel, Responder, _, _, _, _>::respond(
                    EphemeralOnly::new(StdRng::from_os_rng()),
                    &[],
                    r_pipe.clone(),
                )
                .set_s(r_sk)
                .unwrap();

                // Random bytes of the correct length — should fail at
                // e() (invalid point), or at s() (AEAD tag mismatch on
                // the encrypted static key). In IKpsk1, es() just does
                // DH and mixes — no tag check — so the failure is at s().
                match r_hs.recv().e() {
                    Err(_) => {} // invalid point
                    Ok((_, recv)) => {
                        let recv = recv.es().unwrap();
                        prop_assert!(recv.s().is_err());
                    }
                }
            }

            /// AEAD: encrypt then decrypt with random key, nonce, AD, and
            /// plaintext always round-trips.
            #[test]
            fn chacha_round_trip_any(
                key in any::<[u8; 32]>(),
                nonce in 0..1000u64,
                ad in proptest::collection::vec(any::<u8>(), 0..128),
                plaintext in proptest::collection::vec(any::<u8>(), 0..4096),
            ) {
                let mut ct = vec![0u8; plaintext.len() + 16];
                let ct_len = ChaChaPoly::encrypt(&key, nonce, &ad, &plaintext, &mut ct).unwrap();

                let mut pt = vec![0u8; plaintext.len()];
                let pt_len = ChaChaPoly::decrypt(&key, nonce, &ad, &ct[..ct_len], &mut pt).unwrap();
                prop_assert_eq!(&pt[..pt_len], &plaintext[..]);
            }

            /// AEAD: flipping any single bit in ciphertext causes decryption
            /// failure.
            #[test]
            fn chacha_any_bit_flip_detected(
                key in any::<[u8; 32]>(),
                plaintext in proptest::collection::vec(any::<u8>(), 1..256),
                flip_pos_seed in any::<usize>(),
                flip_bit in 0u8..8,
            ) {
                let mut ct = vec![0u8; plaintext.len() + 16];
                let ct_len = ChaChaPoly::encrypt(&key, 0, &[], &plaintext, &mut ct).unwrap();

                let pos = flip_pos_seed % ct_len;
                ct[pos] ^= 1 << flip_bit;

                let mut pt = vec![0u8; plaintext.len()];
                let result = ChaChaPoly::decrypt(&key, 0, &[], &ct[..ct_len], &mut pt);
                prop_assert!(result.is_err());
            }
        }
    }

    // ── Single-`e` send finalizer regression tests ────────────────
    //
    // A send message consisting of exactly one `e` token (`-> e`) must be
    // finalizable when more messages follow. None of the shipped patterns
    // have such a message, so these tests define a throwaway local pattern
    // (`EThenEe`, NN's shape) to exercise the single-`E` more-messages
    // finalizer on the send entry point: a single `-> e` with more messages
    // advances to the next handshake state.
    //
    // (A single `-> e` as the *last* message is not a valid Noise pattern — it
    // would never key the cipher — and is rejected at compile time by the
    // `WellFormed` keyed-cipher guard, so the engine has no last-message
    // single-`e` finalizer.)
    //
    // The finalizer is driven hiss↔hiss across both drivers: `SyncHandshake`
    // and, under `async-io`, `AsyncHandshake`.
    mod single_e_send_finalizer_tests {
        use super::super::SyncHandshake;
        use super::super::tokens::{Cons, E, Ee, Message, Nil, ToInitiator, ToResponder};
        use super::super::{Blake2b, ChaChaPoly, Noise, P256};
        use super::super::{Initiator, Pattern, Responder};
        use crate::provider::EphemeralOnly;
        use rand::{SeedableRng, rngs::StdRng};

        // A two-message pattern: `-> e` / `<- e, ee` (NN's shape, kept
        // local). The initiator's first message is a single `e`, which
        // exercises the single-`E` more-messages finalizer (variant 2 →
        // next handshake state).
        struct EThenEe;
        impl Pattern for EThenEe {
            const NAME: &'static str = "EThenEe";
            const NUM_MESSAGES: usize = 2;
            type PreMessages = Nil;
            // -> e / <- e, ee
            type Messages = Cons<
                Message<ToResponder, Cons<E, Nil>>,
                Cons<Message<ToInitiator, Cons<E, Cons<Ee, Nil>>>, Nil>,
            >;
        }
        type EThenEeProto = Noise<EThenEe, P256, ChaChaPoly, Blake2b>;

        /// Variant 2: a single `-> e` followed by another message advances
        /// to the next `SyncHandshake`; the full `-> e` / `<- e, ee`
        /// handshake completes with matching sessions. Driven hiss↔hiss over
        /// a shared in-memory `Pipe`.
        #[test]
        fn single_e_more_messages_advances_handshake() {
            let (i2r, r2i) = (
                std::rc::Rc::new(std::cell::RefCell::new(
                    std::collections::VecDeque::<u8>::new(),
                )),
                std::rc::Rc::new(std::cell::RefCell::new(
                    std::collections::VecDeque::<u8>::new(),
                )),
            );
            let init_stream = Pipe {
                inbound: r2i.clone(),
                outbound: i2r.clone(),
            };
            let resp_stream = Pipe {
                inbound: i2r.clone(),
                outbound: r2i.clone(),
            };

            // Initiator msg1: -> e (single E, more messages remain) must
            // advance to the next `SyncHandshake` (variant 2).
            let initiator = SyncHandshake::<EThenEeProto, Initiator, _, _, _, _>::initiate(
                EphemeralOnly::new(StdRng::from_os_rng()),
                &[],
                init_stream,
            );
            let initiator = initiator.e().unwrap();
            assert_eq!(
                i2r.borrow().len(),
                65,
                "a bare `-> e` must be exactly 65 bytes"
            );

            // Responder reads msg1 (-> e), then sends msg2 (<- e, ee).
            let responder = SyncHandshake::<EThenEeProto, Responder, _, _, _, _>::respond(
                EphemeralOnly::new(StdRng::from_os_rng()),
                &[],
                resp_stream,
            );
            let (_revealed_e, responder) = responder.recv().e().unwrap();

            // <- e, ee : e (65) + ee (keys) + payload tag (16) = 81 bytes.
            let mut responder_transport = responder.e().unwrap().ee().unwrap();
            assert_eq!(
                r2i.borrow().len(),
                81,
                "`<- e, ee` must be exactly 81 bytes"
            );

            // Initiator reads msg2 (<- e, ee) → `SyncTransport`.
            let (_revealed_e, initiator) = initiator.recv().e().unwrap();
            let mut initiator_transport = initiator.ee().unwrap();

            assert_eq!(
                initiator_transport.transport().session_id(),
                responder_transport.transport().session_id(),
                "initiator and responder must derive a matching session",
            );
        }

        // ── Async-driver coverage ─────────────────────────────────
        //
        // The single-`E` more-messages finalizer exists in both drivers. The
        // test above drives it over `SyncHandshake`; the test below repeats it
        // over `AsyncHandshake` (the `single_e_more_messages_sync_streaming`
        // test additionally covers the sync driver over a shared `Pipe`).

        /// A single-threaded in-memory bidirectional byte pipe (mirrors
        /// the one in `io_sync::tests`): reads pull from one shared queue,
        /// writes push to the other; the peer endpoint has them swapped.
        #[derive(Clone)]
        struct Pipe {
            inbound: std::rc::Rc<std::cell::RefCell<std::collections::VecDeque<u8>>>,
            outbound: std::rc::Rc<std::cell::RefCell<std::collections::VecDeque<u8>>>,
        }

        impl std::io::Read for Pipe {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                let mut q = self.inbound.borrow_mut();
                let n = q.len().min(buf.len());
                for slot in buf.iter_mut().take(n) {
                    *slot = q.pop_front().unwrap();
                }
                Ok(n)
            }
        }

        impl std::io::Write for Pipe {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.outbound.borrow_mut().extend(buf.iter().copied());
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        /// Variant 2 over `SyncHandshake`: a single `-> e` msg1 must
        /// advance to the next `SyncHandshake`; the full `-> e` /
        /// `<- e, ee` handshake then completes with matching sessions.
        /// Driven hiss↔hiss over a shared in-memory `Pipe`.
        #[test]
        fn single_e_more_messages_sync_streaming() {
            let (i2r, r2i) = (
                std::rc::Rc::new(std::cell::RefCell::new(
                    std::collections::VecDeque::<u8>::new(),
                )),
                std::rc::Rc::new(std::cell::RefCell::new(
                    std::collections::VecDeque::<u8>::new(),
                )),
            );
            let init_stream = Pipe {
                inbound: r2i.clone(),
                outbound: i2r.clone(),
            };
            let resp_stream = Pipe {
                inbound: i2r.clone(),
                outbound: r2i.clone(),
            };

            // Initiator msg1: -> e (single E, more messages remain) must
            // advance to the next `SyncHandshake` (variant 2).
            let initiator = SyncHandshake::<EThenEeProto, Initiator, _, _, _, _>::initiate(
                EphemeralOnly::new(StdRng::from_os_rng()),
                &[],
                init_stream,
            );
            let initiator = initiator.e().unwrap();
            assert_eq!(
                i2r.borrow().len(),
                65,
                "a bare `-> e` must be exactly 65 bytes"
            );

            // Responder reads msg1 (-> e), then sends msg2 (<- e, ee).
            let responder = SyncHandshake::<EThenEeProto, Responder, _, _, _, _>::respond(
                EphemeralOnly::new(StdRng::from_os_rng()),
                &[],
                resp_stream,
            );
            let (_revealed_e, responder) = responder.recv().e().unwrap();
            let mut responder_transport = responder.e().unwrap().ee().unwrap();
            assert_eq!(
                r2i.borrow().len(),
                81,
                "`<- e, ee` must be exactly 81 bytes"
            );

            // Initiator reads msg2 (<- e, ee) → `SyncTransport`.
            let (_revealed_e, initiator) = initiator.recv().e().unwrap();
            let mut initiator_transport = initiator.ee().unwrap();

            assert_eq!(
                initiator_transport.transport().session_id(),
                responder_transport.transport().session_id(),
                "initiator and responder must derive a matching session",
            );
        }

        /// Variant 2 over `AsyncHandshake`: a single `-> e` msg1 must
        /// advance to the next `AsyncHandshake`; the full `-> e` /
        /// `<- e, ee` handshake then completes with matching sessions.
        /// Driven hiss↔hiss over a `tokio::io::duplex` pair.
        #[cfg(feature = "async-io")]
        #[tokio::test]
        async fn single_e_more_messages_async_streaming() {
            use super::super::AsyncHandshake;

            let (init_stream, resp_stream) = tokio::io::duplex(4096);

            // Initiator msg1: -> e (single E, more messages remain) must
            // advance to the next `AsyncHandshake` (variant 2).
            let initiator = AsyncHandshake::<EThenEeProto, Initiator, _, _, _, _>::initiate(
                EphemeralOnly::new(StdRng::from_os_rng()),
                &[],
                init_stream,
            );
            let initiator = initiator.e().await.unwrap();

            // Responder reads msg1 (-> e), then sends msg2 (<- e, ee).
            let responder = AsyncHandshake::<EThenEeProto, Responder, _, _, _, _>::respond(
                EphemeralOnly::new(StdRng::from_os_rng()),
                &[],
                resp_stream,
            );
            let (_revealed_e, responder) = responder.recv().e().await.unwrap();
            let mut responder_transport = responder.e().await.unwrap().ee().await.unwrap();

            // Initiator reads msg2 (<- e, ee) → `AsyncTransport`.
            let (_revealed_e, initiator) = initiator.recv().e().await.unwrap();
            let mut initiator_transport = initiator.ee().await.unwrap();

            assert_eq!(
                initiator_transport.transport().session_id(),
                responder_transport.transport().session_id(),
                "initiator and responder must derive a matching session",
            );
        }
    }
}
