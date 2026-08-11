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
//! ## 3. Pre-messages
//!
//! A pre-message is a static key both parties already hold when the
//! handshake begins. [`noise!`](crate::noise!) reads the pattern's
//! pre-message lines at expansion time and turns each one into a
//! **parameter of the role's constructor**, after `provider` and
//! `prologue` and in pattern order — so every key the pattern requires
//! up front is supplied in the one call that starts the handshake, and
//! omitting one is a missing argument, not a runtime error. Which key
//! a role supplies depends on whether the pre-message travels in that
//! role's own sending direction:
//!
//! | Pre-message | Role          | Parameter       | What you supply              |
//! |-------------|---------------|-----------------|------------------------------|
//! | `← s`       | [`Initiator`] | `remote_static` | The peer's static public key |
//! | `← s`       | [`Responder`] | `static_key`    | Our own static private key   |
//! | `→ s`       | [`Initiator`] | `static_key`    | Our own static private key   |
//! | `→ s`       | [`Responder`] | `remote_static` | The peer's static public key |
//!
//! A constructor taking a `static_key` returns `Result`, because
//! deriving its public half goes through the provider and can fail; one
//! taking only a `remote_static` — or no pre-message at all — is
//! infallible.
//!
//! The [`Pattern::PreMessages`] Cons-list is the type-level record of
//! the same pre-messages: [`WellFormed`] walks it ahead of the message
//! list to check the pattern against Noise §7.3 at compile time.
//!
//! ## 4. The generated state machine
//!
//! [`noise!`](crate::noise!) turns a pattern into a type-state machine
//! with one method per handshake message. Each `write_message_N` returns
//! the finished message as a `[u8; MSGn_SIZE]`; each `read_message_N`
//! borrows one for the duration of the call. Calling them out of order,
//! or handing a reader a buffer of the wrong length, is a compile error.
//!
//! Nothing here performs I/O. Which message sizes exist, which keys each
//! method consumes, and which states expose `remote_static()` are all
//! decided by the pattern at expansion time — the compiler picks the
//! right one, with no `match`, no `if`, and no runtime check.
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
//! The generated state machine is generic over the crypto provider, so
//! the per-token DH and key generation can use any backend:
//!
//! - **Software** (`eccoxide`/`cryptoxide`) — resolves immediately.
//! - **Secure Enclave** (Apple Security framework) — the blocking
//!   Security-framework calls run on the calling thread; may prompt for
//!   biometric authentication.
//!
//! It takes a synchronous
//! [`DhProvider`](crate::provider::DhProvider); the
//! [`DhProviderAsync`](crate::provider::DhProviderAsync) refinement
//! exists for backends whose work is awaitable.
//!
//! # Usage
//!
//! See the [crate-level Quickstart](crate) for a complete worked example,
//! and [`noise!`](crate::noise!) for the DSL and the full generated API.

pub(crate) mod buffers;
pub mod cipher;
pub mod cipher_state;
pub mod curve;
pub mod datagram;
pub mod error;
pub(crate) mod handshake;
pub mod hash;
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
// Protocol re-exported from this module (defined below on Noise).
pub use self::hash::{Blake2b, Blake2s, Hash, Sha256, Sha512};
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
/// parameter by the generated state machines instead of spreading four
/// separate generic parameters.
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
    use rand::rngs::StdRng;

    use std::num::NonZeroU64;

    // The zero-sized protocol descriptors, used by the `descriptor_string`
    // and `sizes` tests below — these exercise `Noise<P, Cu, Ci, H>` itself.
    type Channel = Noise<pattern::IKpsk1, P256, ChaChaPoly, Blake2b>;
    type NoiseSeal = Noise<pattern::N, P256, ChaChaPoly, Blake2b>;
    type NoiseK = Noise<pattern::K, P256, ChaChaPoly, Blake2b>;
    type NoiseKpsk0 = Noise<pattern::Kpsk0, P256, ChaChaPoly, Blake2b>;

    // The generated state machines the handshake tests drive. Named for
    // their patterns: the identifier becomes `Pattern::NAME` and reaches the
    // protocol name that seeds the initial handshake hash.
    hiss::noise! { pub N<P256, ChaChaPoly, Blake2b>      { <- s ... -> e, es } }
    hiss::noise! { pub K<P256, ChaChaPoly, Blake2b>      { -> s <- s ... -> e, es, ss } }
    hiss::noise! { pub Kpsk0<P256, ChaChaPoly, Blake2b>  { -> s <- s ... -> psk, e, es, ss } }
    hiss::noise! {
        pub IKpsk1<P256, ChaChaPoly, Blake2b> { <- s ... -> e, es, s, ss, psk <- e, ee, se }
    }

    /// Complete an IKpsk1 handshake hiss↔hiss and hand back both
    /// transports.
    ///
    /// The whole exchange is two calls a side, so the tests that only need
    /// a live channel say that rather than restating the token sequence.
    fn complete_ikpsk1(psk: &Psk) -> (Transport<IKpsk1>, Transport<IKpsk1>) {
        let mut provider = EphemeralOnly::new(rand::make_rng::<StdRng>());
        let initiator_static = provider.generate::<P256>().unwrap();
        let responder_static = provider.generate::<P256>().unwrap();
        let responder_pub = provider.public(&responder_static).unwrap();

        let (msg1, i_hs) = IKpsk1::initiator(
            EphemeralOnly::new(rand::make_rng::<StdRng>()),
            &[],
            responder_pub,
        )
        .write_message_1(initiator_static, psk)
        .unwrap();

        let r_hs = IKpsk1::responder(
            EphemeralOnly::new(rand::make_rng::<StdRng>()),
            &[],
            responder_static,
        )
        .unwrap()
        .read_message_1(&msg1, psk)
        .unwrap();

        let (msg2, r_transport) = r_hs.write_message_2().unwrap();
        let i_transport = i_hs.read_message_2(&msg2).unwrap();
        (i_transport, r_transport)
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
        let mut provider = EphemeralOnly::new(rand::make_rng::<StdRng>());

        // The "recipient" — in practice, the device's own Secure Enclave key.
        let recipient_static = provider.generate::<P256>().unwrap();
        let recipient_pub = provider.public(&recipient_static).unwrap();

        let psk_to_seal = Psk::from_bytes([0x42; 32]);

        // ── Seal (initiator side) ─────────────────────────────────
        // `-> e, es` is N's only message and also its last, so writing it
        // hands back the finished message and the transport together.
        let (msg, mut transport) = N::initiator(
            EphemeralOnly::new(rand::make_rng::<StdRng>()),
            &[],
            recipient_pub,
        )
        .write_message_1()
        .unwrap();

        // msg = ephemeral public key (65) + payload tag (16) = 81 bytes
        assert_eq!(N::MSG1_SIZE, 81);

        // Encrypt the PSK as a transport payload.
        let mut sealed = [0u8; 64]; // 32 + 16 tag
        let sealed_len = transport.send(psk_to_seal.as_bytes(), &mut sealed).unwrap();

        // ── Open (responder side) ─────────────────────────────────
        let mut transport = N::responder(
            EphemeralOnly::new(rand::make_rng::<StdRng>()),
            &[],
            recipient_static,
        )
        .unwrap()
        .read_message_1(&msg)
        .unwrap();

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
        let mut provider = EphemeralOnly::new(rand::make_rng::<StdRng>());

        let recipient_static = provider.generate::<P256>().unwrap();
        let recipient_pub = provider.public(&recipient_static).unwrap();

        let (mut tampered, _transport) = N::initiator(
            EphemeralOnly::new(rand::make_rng::<StdRng>()),
            &[],
            recipient_pub,
        )
        .write_message_1()
        .unwrap();
        // Flip a byte in the ephemeral public key.
        tampered[1] ^= 0xFF;

        // The tampered ephemeral either fails to decode as a curve point or
        // yields the wrong shared secret, which fails the payload tag.
        // Either way the read rejects it; there is no partial state to
        // inspect, since the message is processed as a whole.
        let outcome = N::responder(
            EphemeralOnly::new(rand::make_rng::<StdRng>()),
            &[],
            recipient_static,
        )
        .unwrap()
        .read_message_1(&tampered);
        assert!(outcome.is_err());
    }

    #[test]
    fn noise_n_tampered_tag_rejected() {
        let mut provider = EphemeralOnly::new(rand::make_rng::<StdRng>());

        let recipient_static = provider.generate::<P256>().unwrap();
        let recipient_pub = provider.public(&recipient_static).unwrap();

        let (mut tampered, _transport) = N::initiator(
            EphemeralOnly::new(rand::make_rng::<StdRng>()),
            &[],
            recipient_pub,
        )
        .write_message_1()
        .unwrap();
        // Flip a byte in the payload tag (last 16 bytes).
        tampered[N::MSG1_SIZE - 1] ^= 0xFF;

        // The tag is corrupted, so the read must fail at DecryptAndHash.
        let outcome = N::responder(
            EphemeralOnly::new(rand::make_rng::<StdRng>()),
            &[],
            recipient_static,
        )
        .unwrap()
        .read_message_1(&tampered);
        assert!(matches!(outcome, Err(HandshakeError::DecryptionFailed)));
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
        let mut provider = EphemeralOnly::new(rand::make_rng::<StdRng>());

        // Alice (sender) and Bob (recipient) each have static keys.
        let alice_static = provider.generate::<P256>().unwrap();
        let alice_pub = provider.public(&alice_static).unwrap();

        let bob_static = provider.generate::<P256>().unwrap();
        let bob_pub = provider.public(&bob_static).unwrap();

        let payload: [u8; 32] = [0x42; 32];

        // ── Seal (Alice → Bob) ──────────────────────────────────
        // Pre-messages `-> s` (Alice) and `<- s` (Bob) are constructor
        // arguments, in pattern order.
        let (msg, mut transport) = K::initiator(
            EphemeralOnly::new(rand::make_rng::<StdRng>()),
            &[],
            alice_static,
            bob_pub,
        )
        .unwrap()
        .write_message_1()
        .unwrap();

        // msg = ephemeral public key (65) + payload tag (16) = 81 bytes
        assert_eq!(K::MSG1_SIZE, 81);

        let mut sealed = [0u8; 64]; // 32 + 16 tag
        let sealed_len = transport.send(&payload, &mut sealed).unwrap();

        // ── Open (Bob) ──────────────────────────────────────────
        // Same two pre-messages, mirrored: the peer's public first.
        let mut transport = K::responder(
            EphemeralOnly::new(rand::make_rng::<StdRng>()),
            &[],
            alice_pub,
            bob_static,
        )
        .unwrap()
        .read_message_1(&msg)
        .unwrap();

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
        let mut provider = EphemeralOnly::new(rand::make_rng::<StdRng>());

        let alice_static = provider.generate::<P256>().unwrap();
        let alice_pub = provider.public(&alice_static).unwrap();

        let bob_static = provider.generate::<P256>().unwrap();
        let bob_pub = provider.public(&bob_static).unwrap();

        let psk = Psk::from_bytes([0xBB; 32]);
        let payload: [u8; 32] = [0x42; 32];

        // ── Seal (Alice → Bob) ──────────────────────────────────
        // `-> psk, e, es, ss`: the psk is a message token, so it is a
        // writer argument rather than a constructor one.
        let (msg, mut transport) = Kpsk0::initiator(
            EphemeralOnly::new(rand::make_rng::<StdRng>()),
            &[],
            alice_static,
            bob_pub,
        )
        .unwrap()
        .write_message_1(&psk)
        .unwrap();

        assert_eq!(Kpsk0::MSG1_SIZE, 81);

        let mut sealed = [0u8; 64];
        let sealed_len = transport.send(&payload, &mut sealed).unwrap();

        // ── Open (Bob) ──────────────────────────────────────────
        let mut transport = Kpsk0::responder(
            EphemeralOnly::new(rand::make_rng::<StdRng>()),
            &[],
            alice_pub,
            bob_static,
        )
        .unwrap()
        .read_message_1(&msg, &psk)
        .unwrap();

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
        let mut provider = EphemeralOnly::new(rand::make_rng::<StdRng>());

        let alice_static = provider.generate::<P256>().unwrap();
        let alice_pub = provider.public(&alice_static).unwrap();

        let bob_static = provider.generate::<P256>().unwrap();
        let bob_pub = provider.public(&bob_static).unwrap();

        let psk = Psk::from_bytes([0xBB; 32]);
        let wrong_psk = Psk::from_bytes([0xCC; 32]);
        let payload: [u8; 32] = [0x42; 32];

        // Seal with correct PSK
        let (msg, mut transport) = Kpsk0::initiator(
            EphemeralOnly::new(rand::make_rng::<StdRng>()),
            &[],
            alice_static,
            bob_pub,
        )
        .unwrap()
        .write_message_1(&psk)
        .unwrap();

        let mut sealed = [0u8; 64];
        let _sealed_len = transport.send(&payload, &mut sealed).unwrap();

        // Open with wrong PSK — the wrong PSK produces different derived
        // keys, so the payload tag closing the message fails to verify.
        let result = Kpsk0::responder(
            EphemeralOnly::new(rand::make_rng::<StdRng>()),
            &[],
            alice_pub,
            bob_static,
        )
        .unwrap()
        .read_message_1(&msg, &wrong_psk);
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
        let mut provider = EphemeralOnly::new(rand::make_rng::<StdRng>());

        // ── Key generation ──────────────────────────────────────
        let initiator_static = provider.generate::<P256>().unwrap();
        let initiator_pub = provider.public(&initiator_static).unwrap();

        let responder_static = provider.generate::<P256>().unwrap();
        let responder_pub = provider.public(&responder_static).unwrap();

        // PSK established during the QR ceremony.
        let psk = Psk::from_bytes([0xAA; 32]);

        // ── Message 1: -> e, es, s, ss, psk (initiator sends) ──
        let (msg1, i_hs) = IKpsk1::initiator(
            EphemeralOnly::new(rand::make_rng::<StdRng>()),
            &[],
            responder_pub,
        )
        .write_message_1(initiator_static, &psk)
        .unwrap();

        // msg1 = ephemeral (65) + encrypted static (65+16) + payload tag (16) = 162 bytes
        assert_eq!(IKpsk1::MSG1_SIZE, 162);

        // The first 65 bytes of msg1 are the initiator's ephemeral
        // public key (SEC1 uncompressed P-256).
        let initiator_e_from_wire =
            P256r1PublicKey::from_bytes(&msg1[..65]).expect("valid ephemeral in msg1");

        // ── Message 1 (responder receives) ──────────────────────
        let r_hs = IKpsk1::responder(
            EphemeralOnly::new(rand::make_rng::<StdRng>()),
            &[],
            responder_static,
        )
        .unwrap()
        .read_message_1(&msg1, &psk)
        .unwrap();

        // What the read recovered matches what was on the wire, and the
        // responder now knows the initiator's static key.
        assert_eq!(*r_hs.remote_ephemeral(), initiator_e_from_wire);
        assert_eq!(*r_hs.remote_static(), initiator_pub);

        // ── Message 2: <- e, ee, se (responder sends) ──────────
        let (msg2, mut r_transport) = r_hs.write_message_2().unwrap();

        // msg2 = ephemeral (65) + payload tag (16) = 81 bytes
        assert_eq!(IKpsk1::MSG2_SIZE, 81);

        // The first 65 bytes of msg2 are the responder's ephemeral
        // public key (SEC1 uncompressed P-256).
        P256r1PublicKey::from_bytes(&msg2[..65]).expect("valid ephemeral in msg2");

        // ── Message 2 (initiator receives) ──────────────────────
        let mut i_transport = i_hs.read_message_2(&msg2).unwrap();

        // ── Verify: both sides derived the same handshake hash ──
        assert_eq!(i_transport.session_id(), r_transport.session_id());

        // ── Verify: transport encryption works bidirectionally ──
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

    /// HMAC-BLAKE2b over RFC 4231's *inputs* — but the values below are
    /// **not** standards-body vectors, and must not be presented as such.
    ///
    /// No standards body publishes HMAC-BLAKE2 vectors: RFC 7693 defines no
    /// HMAC, Wycheproof ships no HMAC-BLAKE2 file, and macOS's LibreSSL has
    /// no BLAKE2 digest at all. So these are cross-generated, and pinned only
    /// because two implementations independent of `cryptoxide` — Python's
    /// `hmac` over `hashlib.blake2b`, and RustCrypto's `hmac::SimpleHmac`
    /// over `blake2::Blake2b512` — agree on every one of them. The recipe was
    /// validated first against this file's pinned BLAKE2s case-6 value, which
    /// it reproduced exactly.
    ///
    /// These matter more than their BLAKE2s counterparts, because since the
    /// move to `cryptoxide` 0.6 the RFC 2104 key schedule under them is
    /// *hiss's own* (`noise::hash`'s private `hmac_blake2` module) rather
    /// than the library's. `tests/primitive_diag.rs` checks the same code
    /// against a hand-rolled ipad/opad oracle, but that oracle shares an
    /// author with the implementation; these do not, so a shared misreading
    /// of RFC 2104 fails here and passes there.
    ///
    /// The broader check on this code path is elsewhere: `mix_key` runs
    /// `Blake2b::hmac` on every one of the 85 BLAKE2b handshake replays — 68
    /// in `tests/noise_cacophony.rs` (34 vectors, each in both roles) and 17
    /// in `tests/noise_kat.rs` — against implementations neither hiss nor
    /// `snow` wrote.
    ///
    /// Cases 1, 2, 3 and 6 of RFC 4231 §4. Case 6's 131-byte key is the only
    /// one of the four longer than the 128-byte block, so it is the only one
    /// that reaches the hash-the-key branch of the key schedule — a branch no
    /// handshake can reach, since `mix_key` always keys with a 64-byte
    /// chaining key. It is reachable only through the public `Hash` trait.
    #[test]
    fn blake2b_hmac_cross_checked() {
        assert_eq!(
            hex::encode(Blake2b::hmac(&[0x0b; 20], b"Hi There")),
            "358a6a184924894fc34bee5680eedf57d84a37bb38832f288e3b27dc63a98cc8\
             c91e76da476b508bc6b2d408a248857452906e4a20b48c6b4b55d2df0fe1dd24"
        );
        assert_eq!(
            hex::encode(Blake2b::hmac(b"Jefe", b"what do ya want for nothing?")),
            "6ff884f8ddc2a6586b3c98a4cd6ebdf14ec10204b6710073eb5865ade37a2643\
             b8807c1335d107ecdb9ffeaeb6828c4625ba172c66379efcd222c2de11727ab4"
        );
        assert_eq!(
            hex::encode(Blake2b::hmac(&[0xaa; 20], &[0xdd; 50])),
            "f43bc62c7a99353c3b2c60e8ef24fbbd42e9547866dc9c5be4edc6f4a7d4bc0a\
             c620c2c60034d040f0dbaf86f9e9cd7891a095595eed55e2a996215f0c15c018"
        );
        assert_eq!(
            hex::encode(Blake2b::hmac(
                &[0xaa; 131],
                b"Test Using Larger Than Block-Size Key - Hash Key First"
            )),
            "a54b2943b2a20227d41ca46c0945af09bc1faefb2f49894c23aebc557fb79c48\
             89dca74408dc865086667aedee4a3185c53a49c80b814c4c5813ea0c8b38a8f8"
        );
    }

    /// FIPS 180-4 Appendix B short-message digests — a standards-body
    /// oracle, which the BLAKE2b tests above have no equivalent of.
    #[test]
    fn sha256_matches_nist_vectors() {
        assert_eq!(
            hex::encode(Sha256::hash(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex::encode(Sha256::hash(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        // The 448-bit two-block message.
        assert_eq!(
            hex::encode(Sha256::hash(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
        assert_eq!(Sha256::hash(b"abc").len(), 32);
    }

    #[test]
    fn sha256_hash_two_equals_concat() {
        // hash_two(a, b) should equal hash(a || b)
        let a = b"first part";
        let b = b"second part";
        let h1 = Sha256::hash_two(a, b);
        let mut concat = a.to_vec();
        concat.extend_from_slice(b);
        let h2 = Sha256::hash(&concat);
        assert_eq!(h1, h2);
    }

    /// RFC 4231 §4 HMAC-SHA-256 cases 1, 2, 3 and 6. Case 6's key is
    /// longer than the 64-byte block, which is the only one of the four
    /// that reaches the hash-the-key path inside `Hmac`.
    #[test]
    fn sha256_hmac_rfc4231() {
        assert_eq!(
            hex::encode(Sha256::hmac(&[0x0b; 20], b"Hi There")),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
        assert_eq!(
            hex::encode(Sha256::hmac(b"Jefe", b"what do ya want for nothing?")),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        assert_eq!(
            hex::encode(Sha256::hmac(&[0xaa; 20], &[0xdd; 50])),
            "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"
        );
        assert_eq!(
            hex::encode(Sha256::hmac(
                &[0xaa; 131],
                b"Test Using Larger Than Block-Size Key - Hash Key First"
            )),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    #[test]
    fn sha256_hmac_different_keys() {
        let a = Sha256::hmac(b"key1", b"data");
        let b = Sha256::hmac(b"key2", b"data");
        assert_ne!(a, b);
    }

    /// RFC 7693 Appendix B, "Example of BLAKE2s Computation" — the one
    /// standards-body digest that exists for this hash. `snow` vendors the
    /// same value from `draft-saarinen-blake2-06`
    /// (`resolvers/default.rs`, `test_blake2s`), and Python's
    /// `hashlib.blake2s` reproduces it — three independent sources.
    #[test]
    fn blake2s_matches_rfc7693() {
        assert_eq!(
            hex::encode(Blake2s::hash(b"abc")),
            "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982"
        );
        assert_eq!(Blake2s::hash(b"abc").len(), 32);
    }

    #[test]
    fn blake2s_hash_two_equals_concat() {
        // hash_two(a, b) should equal hash(a || b)
        let a = b"first part";
        let b = b"second part";
        let h1 = Blake2s::hash_two(a, b);
        let mut concat = a.to_vec();
        concat.extend_from_slice(b);
        let h2 = Blake2s::hash(&concat);
        assert_eq!(h1, h2);
    }

    /// HMAC-BLAKE2s over RFC 4231's *inputs* — but the values below are
    /// **not** standards-body vectors, and must not be presented as such.
    ///
    /// No standards body publishes HMAC-BLAKE2 vectors: RFC 7693 defines no
    /// HMAC, Wycheproof ships no HMAC-BLAKE2 file, and macOS's LibreSSL has
    /// no BLAKE2 digest at all. So these are cross-generated, and pinned only
    /// because two implementations independent of `cryptoxide` — Python's
    /// `hmac` over `hashlib.blake2s`, and RustCrypto's `hmac::SimpleHmac`
    /// over `blake2::Blake2s256` — agree on every one of them.
    ///
    /// The stronger check on this code path is elsewhere: `mix_key` runs
    /// `Blake2s::hmac` on every one of the 22 BLAKE2s handshakes in
    /// `tests/noise_cacophony.rs`, against an implementation neither hiss
    /// nor `snow` wrote.
    ///
    /// Cases 1, 2, 3 and 6 of RFC 4231 §4. Case 6's 131-byte key is the only
    /// one of the four longer than the 64-byte block, so it is the only one
    /// that reaches the hash-the-key path inside `Hmac`.
    #[test]
    fn blake2s_hmac_cross_checked() {
        assert_eq!(
            hex::encode(Blake2s::hmac(&[0x0b; 20], b"Hi There")),
            "65a8b7c5cc9136d424e82c37e2707e74e913c0655b99c75f40edf387453a3260"
        );
        assert_eq!(
            hex::encode(Blake2s::hmac(b"Jefe", b"what do ya want for nothing?")),
            "90b6281e2f3038c9056af0b4a7e763cae6fe5d9eb4386a0ec95237890c104ff0"
        );
        assert_eq!(
            hex::encode(Blake2s::hmac(&[0xaa; 20], &[0xdd; 50])),
            "fcc4f59529502e34c3d8da3ffdab82966a2cb637ff5e9bd701135c2e9469e790"
        );
        assert_eq!(
            hex::encode(Blake2s::hmac(
                &[0xaa; 131],
                b"Test Using Larger Than Block-Size Key - Hash Key First"
            )),
            "d23d79394f53d536a096e6514447eeaabb05ded01be32c1937da6a8f7103bc4e"
        );
    }

    #[test]
    fn blake2s_hmac_different_keys() {
        let a = Blake2s::hmac(b"key1", b"data");
        let b = Blake2s::hmac(b"key2", b"data");
        assert_ne!(a, b);
    }

    /// FIPS 180-4 Appendix C short-message digests, plus the 896-bit
    /// two-block message — cross-checked against `openssl dgst -sha512`.
    #[test]
    fn sha512_matches_nist_vectors() {
        assert_eq!(
            hex::encode(Sha512::hash(b"")),
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce\
             47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        );
        assert_eq!(
            hex::encode(Sha512::hash(b"abc")),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
             2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
        // The 896-bit two-block message.
        assert_eq!(
            hex::encode(Sha512::hash(
                b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn\
                  hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
            )),
            "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018\
             501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"
        );
        assert_eq!(Sha512::hash(b"abc").len(), 64);
    }

    #[test]
    fn sha512_hash_two_equals_concat() {
        // hash_two(a, b) should equal hash(a || b)
        let a = b"first part";
        let b = b"second part";
        let h1 = Sha512::hash_two(a, b);
        let mut concat = a.to_vec();
        concat.extend_from_slice(b);
        let h2 = Sha512::hash(&concat);
        assert_eq!(h1, h2);
    }

    /// RFC 4231 §4 HMAC-SHA-512 cases 1, 2, 3 and 6 — standards-body
    /// vectors, unlike BLAKE2s, which has none. Case 3 additionally matches
    /// `snow`'s own vendored test verbatim. Case 6's key is longer than the
    /// 128-byte block, the only one of the four that reaches the
    /// hash-the-key path.
    #[test]
    fn sha512_hmac_rfc4231() {
        assert_eq!(
            hex::encode(Sha512::hmac(&[0x0b; 20], b"Hi There")),
            "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde\
             daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
        );
        assert_eq!(
            hex::encode(Sha512::hmac(b"Jefe", b"what do ya want for nothing?")),
            "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554\
             9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"
        );
        assert_eq!(
            hex::encode(Sha512::hmac(&[0xaa; 20], &[0xdd; 50])),
            "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39\
             bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb"
        );
        assert_eq!(
            hex::encode(Sha512::hmac(
                &[0xaa; 131],
                b"Test Using Larger Than Block-Size Key - Hash Key First"
            )),
            "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f352\
             6b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598"
        );
    }

    #[test]
    fn sha512_hmac_different_keys() {
        let a = Sha512::hmac(b"key1", b"data");
        let b = Sha512::hmac(b"key2", b"data");
        assert_ne!(a, b);
    }

    // ── Handshake error path tests ────────────────────────────────

    #[test]
    fn generated_message_size_matches_the_size_macro() {
        // This test used to feed a 64-byte buffer to a responder expecting
        // 162 and assert that a token's `read_exact` ran out of bytes.
        // `read_message_1` now takes `&[u8; IKpsk1::MSG1_SIZE]`, so a
        // wrong-length buffer cannot reach it at all: the check moved from
        // run time into the type system, where it is pinned by a
        // `compile_fail` doctest on `hiss::noise!`.
        //
        // What is still worth asserting is that the two *independent* size
        // computations agree — the const the macro generates, and the
        // `noise_message_size!` arithmetic.
        assert_eq!(
            IKpsk1::MSG1_SIZE,
            noise_message_size!(curve: P256, cipher: ChaChaPoly, has_psk: true, keyed: false, tokens: [E, Es, S, Ss, Psk],),
        );
    }

    #[test]
    fn expected_message_size_reports_correctly() {
        // There is no runtime `expected_message_size` query any more; the
        // same value is available at compile time from the message-size
        // macro. msg1 (-> e, es, s, ss, psk):
        // 65 (ephemeral) + 65 (encrypted static) + 16 (tag) + 16 (payload tag) = 162
        assert_eq!(
            noise_message_size!(curve: P256, cipher: ChaChaPoly, has_psk: true, keyed: false, tokens: [E, Es, S, Ss, Psk],),
            162
        );
    }

    #[test]
    fn corrupted_encrypted_static_in_msg1_rejected() {
        let mut provider = EphemeralOnly::new(rand::make_rng::<StdRng>());

        let initiator_static = provider.generate::<P256>().unwrap();
        let responder_static = provider.generate::<P256>().unwrap();
        let responder_pub = provider.public(&responder_static).unwrap();

        let psk = Psk::from_bytes([0xBB; 32]);

        // Initiator constructs msg1 normally.
        let (mut corrupted, _i_hs) = IKpsk1::initiator(
            EphemeralOnly::new(rand::make_rng::<StdRng>()),
            &[],
            responder_pub,
        )
        .write_message_1(initiator_static, &psk)
        .unwrap();

        // Corrupt a byte in the encrypted static key area (after the
        // 65-byte ephemeral).
        corrupted[70] ^= 0xFF;

        // The `s` token decrypts the static key — corruption fails its tag,
        // so the read rejects the message.
        let outcome = IKpsk1::responder(
            EphemeralOnly::new(rand::make_rng::<StdRng>()),
            &[],
            responder_static,
        )
        .unwrap()
        .read_message_1(&corrupted, &psk);
        assert!(matches!(outcome, Err(HandshakeError::DecryptionFailed)));
    }

    #[test]
    fn mismatched_psk_fails() {
        let mut provider = EphemeralOnly::new(rand::make_rng::<StdRng>());

        let initiator_static = provider.generate::<P256>().unwrap();
        let responder_static = provider.generate::<P256>().unwrap();
        let responder_pub = provider.public(&responder_static).unwrap();

        let i_psk = Psk::from_bytes([0xAA; 32]);
        let r_psk = Psk::from_bytes([0xBB; 32]); // different!

        // Initiator sends msg1 with i_psk.
        let (msg1, _i_hs) = IKpsk1::initiator(
            EphemeralOnly::new(rand::make_rng::<StdRng>()),
            &[],
            responder_pub,
        )
        .write_message_1(initiator_static, &i_psk)
        .unwrap();

        // Responder reads msg1 with r_psk — mismatch. The psk token is the
        // last in msg1, so the payload tag closing the message catches the
        // divergence.
        let result = IKpsk1::responder(
            EphemeralOnly::new(rand::make_rng::<StdRng>()),
            &[],
            responder_static,
        )
        .unwrap()
        .read_message_1(&msg1, &r_psk);
        assert!(result.is_err());
    }

    #[test]
    fn transport_corrupted_ciphertext_rejected() {
        let psk = Psk::from_bytes([0xCC; 32]);
        let (mut i_transport, mut r_transport) = complete_ikpsk1(&psk);

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
        let psk = Psk::from_bytes([0xDD; 32]);
        let (mut i_transport, mut r_transport) = complete_ikpsk1(&psk);

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

    // ── SymmetricState protocol name hashing ──────────────────────

    #[test]
    fn symmetric_state_long_protocol_name() {
        // A protocol name longer than HASHLEN (64) should be hashed.
        let long_name = "A".repeat(100);
        let ss = symmetric_state::SymmetricState::<ChaChaPoly, Blake2b>::initialize(&long_name);
        // Just verify it doesn't panic and the hash is 64 bytes.
        assert_eq!(ss.handshake_hash().len(), 64);
    }

    #[test]
    fn symmetric_state_short_protocol_name_sha256() {
        // 31 bytes, so at HASHLEN 32 this takes the padding branch. The
        // hashing branch is the one `Noise_IKpsk1_P256_ChaChaPoly_SHA256`
        // (35 bytes) reaches, pinned against snow in `tests/noise_kat.rs`.
        let name = "Noise_XX_P256_ChaChaPoly_SHA256";
        let ss = symmetric_state::SymmetricState::<ChaChaPoly, Sha256>::initialize(name);
        let mut want = vec![0u8; 32];
        want[..name.len()].copy_from_slice(name.as_bytes());
        assert_eq!(ss.handshake_hash(), want.as_slice());
    }

    // ── Wrong responder static key ──────────────────────────────────

    #[test]
    fn ikpsk1_wrong_responder_key_rejected() {
        let mut provider = EphemeralOnly::new(rand::make_rng::<StdRng>());

        let initiator_static = provider.generate::<P256>().unwrap();
        let responder_static = provider.generate::<P256>().unwrap();
        let wrong_static = provider.generate::<P256>().unwrap();
        let wrong_pub = provider.public(&wrong_static).unwrap();
        let psk = Psk::from_bytes([0xCC; 32]);

        // Initiator targets the wrong responder public key, so its `es` DH
        // is against a key the real responder does not hold.
        let (msg1, _i_hs) = IKpsk1::initiator(
            EphemeralOnly::new(rand::make_rng::<StdRng>()),
            &[],
            wrong_pub,
        )
        .write_message_1(initiator_static, &psk)
        .unwrap();

        // The actual responder holds a different static key, so `es`
        // produces a different shared secret. The token itself succeeds —
        // it only mixes the DH result in — but the derived cipher key is
        // wrong, so decrypting the initiator's static at the `s` token
        // fails and the read rejects the message.
        let result = IKpsk1::responder(
            EphemeralOnly::new(rand::make_rng::<StdRng>()),
            &[],
            responder_static,
        )
        .unwrap()
        .read_message_1(&msg1, &psk);
        assert!(result.is_err());
    }

    // ── Transport direction isolation ───────────────────────────────

    #[test]
    fn transport_keys_are_directional() {
        let psk = Psk::from_bytes([0xFF; 32]);
        let (mut i_transport, mut r_transport) = complete_ikpsk1(&psk);

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

            let initiator_static = EphemeralOnly::new(rand::make_rng::<StdRng>())
                .generate::<P256>()
                .unwrap();

            let (msg1, i_hs) = IKpsk1::initiator(
                EphemeralOnly::new(rand::make_rng::<StdRng>()),
                &[],
                responder_pub,
            )
            .write_message_1(initiator_static, &psk)
            .unwrap();

            let r_hs = IKpsk1::responder(
                EphemeralOnly::new(rand::make_rng::<StdRng>()),
                &[],
                responder_static,
            )
            .unwrap()
            .read_message_1(&msg1, &psk)
            .unwrap();

            let (msg2, r_transport) = r_hs.write_message_2().unwrap();
            let i_transport = i_hs.read_message_2(&msg2).unwrap();

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
        let mut provider = EphemeralOnly::new(rand::make_rng::<StdRng>());

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

        let (msg1, i_hs) = IKpsk1::initiator(
            EphemeralOnly::new(rand::make_rng::<StdRng>()),
            &[],
            responder_pub,
        )
        .write_message_1(wrong_static, &psk)
        .unwrap();

        let r_hs = IKpsk1::responder(
            EphemeralOnly::new(rand::make_rng::<StdRng>()),
            &[],
            responder_static,
        )
        .unwrap()
        .read_message_1(&msg1, &psk)
        .unwrap();

        // The responder decrypted the wrong initiator static key.
        assert_ne!(*r_hs.remote_static(), initiator_pub);

        // Complete the handshake — msg2 still works because the `se`
        // token uses DH(wrong_s, responder_e), which both sides compute
        // consistently.
        let (msg2, r_transport) = r_hs.write_message_2().unwrap();
        let i_transport = i_hs.read_message_2(&msg2).unwrap();

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
        let mut provider = EphemeralOnly::new(rand::make_rng::<StdRng>());

        let initiator_static = provider.generate::<P256>().unwrap();
        let responder_static = provider.generate::<P256>().unwrap();
        let responder_pub = provider.public(&responder_static).unwrap();
        let psk = Psk::from_bytes([0xDD; 32]);

        let (mut corrupted, _i_hs) = IKpsk1::initiator(
            EphemeralOnly::new(rand::make_rng::<StdRng>()),
            &[],
            responder_pub,
        )
        .write_message_1(initiator_static, &psk)
        .unwrap();
        // Corrupt a byte in the ephemeral public key.
        corrupted[5] ^= 0xFF;

        // Corruption yields either an invalid curve point or a valid but
        // wrong one, whose `es` DH diverges the key and fails the payload
        // tag. Either way the read rejects it and no state comes back.
        let outcome = IKpsk1::responder(
            EphemeralOnly::new(rand::make_rng::<StdRng>()),
            &[],
            responder_static,
        )
        .unwrap()
        .read_message_1(&corrupted, &psk);
        assert!(outcome.is_err());
    }

    // ── Corrupted msg2 (tampered ephemeral in IKpsk1) ─────────────────

    #[test]
    fn ikpsk1_corrupted_msg2_rejected() {
        let mut provider = EphemeralOnly::new(rand::make_rng::<StdRng>());

        let initiator_static = provider.generate::<P256>().unwrap();
        let responder_static = provider.generate::<P256>().unwrap();
        let responder_pub = provider.public(&responder_static).unwrap();
        let psk = Psk::from_bytes([0xDD; 32]);

        // msg1 flows through cleanly so the responder can produce msg2.
        let (msg1, i_hs) = IKpsk1::initiator(
            EphemeralOnly::new(rand::make_rng::<StdRng>()),
            &[],
            responder_pub,
        )
        .write_message_1(initiator_static, &psk)
        .unwrap();
        let r_hs = IKpsk1::responder(
            EphemeralOnly::new(rand::make_rng::<StdRng>()),
            &[],
            responder_static,
        )
        .unwrap()
        .read_message_1(&msg1, &psk)
        .unwrap();

        let (mut corrupted, _r_transport) = r_hs.write_message_2().unwrap();
        // Corrupt a byte in the responder's ephemeral public key.
        corrupted[3] ^= 0xFF;

        // Either an invalid curve point or a valid but wrong one whose `ee`
        // DH fails the payload tag — the initiator's read rejects it.
        assert!(i_hs.read_message_2(&corrupted).is_err());
    }

    // ── Transport replay detection (nonce desync) ─────────────────────

    #[test]
    fn transport_replayed_message_rejected() {
        let psk = Psk::from_bytes([0xEE; 32]);
        let (mut i_transport, mut r_transport) = complete_ikpsk1(&psk);

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
        let psk = Psk::from_bytes([0xFF; 32]);
        let (mut i_transport, mut r_transport) = complete_ikpsk1(&psk);

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
        let psk = Psk::from_bytes([0x11; 32]);
        let (mut i_transport, mut r_transport) = complete_ikpsk1(&psk);

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
        let psk = Psk::from_bytes([0x5A; 32]);
        let (i_transport, r_transport) = complete_ikpsk1(&psk);

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

    /// Run a full IKpsk1 handshake and return the two completed transports
    /// `(initiator, responder)`. The datagram tests each need a real,
    /// matched transport pair.
    fn ikpsk1_transport_pair() -> (Transport<IKpsk1>, Transport<IKpsk1>) {
        complete_ikpsk1(&Psk::from_bytes([0x7A; 32]))
    }

    /// Seal several datagrams, shuffle them, and open each at its stated
    /// counter — all must decrypt. Also pins that `encrypt_next` hands out a
    /// strictly monotonic counter and that both halves share a session id.
    #[test]
    fn datagram_shuffled_delivery_all_open() {
        let (i_transport, r_transport) = ikpsk1_transport_pair();
        let (mut i_send, _i_recv) = i_transport.into_datagram();
        let (_r_send, mut r_recv) = r_transport.into_datagram();

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
        let (_, mut r_recv) = r_transport.into_datagram();

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
        let (_, mut r_recv) = r_transport.into_datagram();

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
        let (_, mut r_recv) = r_transport.into_datagram();

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
        let (mut i_dg_send, mut i_dg_recv) = i_transport.into_datagram();
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

    // ── Epoch-ratcheting datagram transport (into_datagram_with_epoch) ─
    //
    // These exercise the counter-derived Rekey ratchet. Most use a
    // deterministic fixed-key transport (`fixed_epoch_transport`) so a test
    // can seal known bytes and open them on as many independent, matched
    // receivers as it needs — a real handshake yields fresh random keys and
    // only one receiver per pair.

    /// A shorthand for a non-zero epoch size.
    fn epoch(n: u64) -> NonZeroU64 {
        NonZeroU64::new(n).expect("epoch size must be non-zero")
    }

    /// A transport built from a fixed, known key in both directions, so
    /// datagram bytes it seals are deterministic and open on any receiver
    /// built the same way. Not a real handshake — a test fixture.
    fn fixed_epoch_transport() -> Transport<IKpsk1> {
        let key = [0x24u8; 32];
        Transport::<IKpsk1>::new(
            CipherState::from_key(key),
            CipherState::from_key(key),
            SessionId::from(vec![0xEE; 8]),
            None,
            None,
            None,
        )
    }

    /// The Noise §11.3 REKEY known-answer test. Pins the next key derived
    /// from an all-zero key, cross-checking the raw definition path
    /// (`ENCRYPT(k, 2^64−1, "", zeros)[..32]`), the `rekey_key` helper, and
    /// `CipherState::rekey` against one another and against the pinned hex.
    #[test]
    fn rekey_kat() {
        use super::cipher_state::rekey_key;

        let k = [0u8; 32];

        // Definition path: encrypt 32 zeros at nonce 2^64−1 with empty ad,
        // take the first 32 ciphertext bytes (the 16-byte tag is discarded).
        let mut scratch = [0u8; 48];
        ChaChaPoly::encrypt(&k, u64::MAX, &[], &[0u8; 32], &mut scratch).unwrap();
        let mut definition = [0u8; 32];
        definition.copy_from_slice(&scratch[..32]);

        // The helper path must agree with the definition, byte for byte.
        let derived = rekey_key::<ChaChaPoly>(&k).unwrap();
        assert_eq!(derived, definition);

        // `CipherState::rekey` installs exactly that next key.
        let mut cs = CipherState::<ChaChaPoly>::from_key(k);
        cs.rekey().unwrap();
        assert_eq!(cs.key(), Some(definition));

        // The pinned answer (computed once, cross-checked against the
        // definition above).
        assert_eq!(
            hex::encode(derived),
            "25ce5d37df19f3783185f2ffd5ab17fa3397c212f02d62fb1733e0b875b74c58",
            "REKEY next-key KAT drifted"
        );
    }

    /// The no-ratchet path is byte-identical to a plain half at epoch 0, and
    /// the ratchet demonstrably fires at the first boundary. Uses a fixed key
    /// so the two senders' output can be compared byte for byte.
    #[test]
    fn datagram_no_ratchet_byte_identity() {
        let size = epoch(4);
        let (mut plain_send, _) = fixed_epoch_transport().into_datagram();
        let (mut epoch_send, _) = fixed_epoch_transport().into_datagram_with_epoch(size);

        let mut a = [0u8; 64];
        let mut b = [0u8; 64];

        // Epoch 0 (counters 0..4): the ratcheting sender has not rekeyed, so
        // its output is byte-for-byte the plain sender's.
        for _ in 0..4u64 {
            let (ca, na) = plain_send
                .encrypt_next(b"ad", b"identical payload", &mut a)
                .unwrap();
            let (cb, nb) = epoch_send
                .encrypt_next(b"ad", b"identical payload", &mut b)
                .unwrap();
            assert_eq!(ca, cb);
            assert_eq!(a[..na], b[..nb]);
        }

        // Counter 4 crosses into epoch 1: the ratcheting sender rekeys, so its
        // bytes now diverge from the plain sender's, and a plain receiver
        // (still on the handshake key) cannot open the epoch-1 packet though
        // it opens the plain one.
        let (cp, np) = plain_send.encrypt_next(b"ad", b"x", &mut a).unwrap();
        let (ce, ne) = epoch_send.encrypt_next(b"ad", b"x", &mut b).unwrap();
        assert_eq!(cp, 4);
        assert_eq!(ce, 4);
        assert_ne!(a[..np], b[..ne]);

        let (_, mut plain_recv) = fixed_epoch_transport().into_datagram();
        let mut pt = [0u8; 64];
        assert!(plain_recv.decrypt_at(4, b"ad", &a[..np], &mut pt).is_ok());
        let err = plain_recv
            .decrypt_at(4, b"ad", &b[..ne], &mut pt)
            .unwrap_err();
        assert!(matches!(err, error::HandshakeError::DecryptionFailed));
    }

    /// Seal across an epoch boundary and open both in order and reordered.
    /// The reordered pass proves a straggler from the previous epoch opens
    /// under the retained previous key, and that a forward commit happens on
    /// the first future-epoch packet regardless of arrival order.
    #[test]
    fn datagram_epoch_boundary_roundtrip_and_reorder() {
        let size = epoch(4);
        let (mut send, _) = fixed_epoch_transport().into_datagram_with_epoch(size);

        // Seal counters 0..=5; the boundary N = 4 opens epoch 1.
        let mut ctbuf = [0u8; 64];
        let mut sealed: Vec<Vec<u8>> = Vec::new();
        for i in 0..6u64 {
            let (c, n) = send
                .encrypt_next(&[], format!("m{i}").as_bytes(), &mut ctbuf)
                .unwrap();
            assert_eq!(c, i);
            sealed.push(ctbuf[..n].to_vec());
        }

        let mut pt = [0u8; 64];

        // In order on a fresh receiver: N−1 (epoch 0), N (epoch 1 commit),
        // N+1 (epoch 1).
        let (_, mut ra) = fixed_epoch_transport().into_datagram_with_epoch(size);
        for i in [3u64, 4, 5] {
            let n = ra.decrypt_at(i, &[], &sealed[i as usize], &mut pt).unwrap();
            assert_eq!(&pt[..n], format!("m{i}").as_bytes());
        }

        // Reordered on another fresh receiver: N+1 first (commits epoch 1,
        // keeps epoch 0 as prev), then the N−1 straggler (opens under prev),
        // then N.
        let (_, mut rb) = fixed_epoch_transport().into_datagram_with_epoch(size);
        for i in [5u64, 3, 4] {
            let n = rb.decrypt_at(i, &[], &sealed[i as usize], &mut pt).unwrap();
            assert_eq!(&pt[..n], format!("m{i}").as_bytes());
        }
    }

    /// A datagram from two epochs back — older than the retained previous
    /// key — is refused with the ordinary decrypt error, while a straggler
    /// from the immediately-preceding epoch still opens.
    #[test]
    fn datagram_old_epoch_refused() {
        let size = epoch(4);
        let (mut send, _) = fixed_epoch_transport().into_datagram_with_epoch(size);

        let mut ctbuf = [0u8; 64];
        let mut sealed: Vec<Vec<u8>> = Vec::new();
        for i in 0..9u64 {
            let (c, n) = send
                .encrypt_next(&[], format!("m{i}").as_bytes(), &mut ctbuf)
                .unwrap();
            assert_eq!(c, i);
            sealed.push(ctbuf[..n].to_vec());
        }

        let (_, mut recv) = fixed_epoch_transport().into_datagram_with_epoch(size);
        let mut pt = [0u8; 64];

        // Jump straight to epoch 2 (steps = MAX_EPOCH_JUMP, allowed): commits
        // current = epoch 2, prev = epoch 1.
        let n = recv.decrypt_at(8, &[], &sealed[8], &mut pt).unwrap();
        assert_eq!(&pt[..n], b"m8");

        // A straggler from epoch 1 (counter 4) still opens — it is prev.
        let n = recv.decrypt_at(4, &[], &sealed[4], &mut pt).unwrap();
        assert_eq!(&pt[..n], b"m4");

        // Epoch 0 (counter 0) is now two epochs back; its key is gone.
        let err = recv.decrypt_at(0, &[], &sealed[0], &mut pt).unwrap_err();
        assert!(matches!(err, error::HandshakeError::DecryptionFailed));
    }

    /// A datagram more than `MAX_EPOCH_JUMP` epochs ahead is refused before
    /// any key is derived, even when genuine, and the committed state is left
    /// untouched so reachable epochs still open.
    #[test]
    fn datagram_forward_jump_cap_refuses_without_derivation() {
        let size = epoch(4);
        let (mut send, _) = fixed_epoch_transport().into_datagram_with_epoch(size);

        let mut ctbuf = [0u8; 64];
        let mut sealed: Vec<Vec<u8>> = Vec::new();
        for i in 0..13u64 {
            let (_, n) = send
                .encrypt_next(&[], format!("m{i}").as_bytes(), &mut ctbuf)
                .unwrap();
            sealed.push(ctbuf[..n].to_vec());
        }

        let (_, mut recv) = fixed_epoch_transport().into_datagram_with_epoch(size);
        let mut pt = [0u8; 64];

        // Counter 12 is epoch 3 = MAX_EPOCH_JUMP + 1 beyond the committed
        // epoch 0. It is refused WITHOUT deriving a key (the cap check returns
        // before any Rekey chain), even though the packet is genuine.
        let err = recv.decrypt_at(12, &[], &sealed[12], &mut pt).unwrap_err();
        assert!(matches!(err, error::HandshakeError::DecryptionFailed));

        // Committed state is untouched: an epoch-0 packet still opens as
        // current, and the receiver can still advance to a reachable epoch.
        let n = recv.decrypt_at(0, &[], &sealed[0], &mut pt).unwrap();
        assert_eq!(&pt[..n], b"m0");
        let n = recv.decrypt_at(8, &[], &sealed[8], &mut pt).unwrap();
        assert_eq!(&pt[..n], b"m8");
    }

    /// A forged packet claiming a valid future epoch (within the cap) opens
    /// under a candidate key, fails the AEAD tag, and does NOT advance the
    /// committed state — the one-packet-desync guard.
    #[test]
    fn datagram_forged_future_tag_does_not_advance() {
        let size = epoch(4);
        let (mut send, _) = fixed_epoch_transport().into_datagram_with_epoch(size);

        let mut ctbuf = [0u8; 64];
        let mut sealed: Vec<Vec<u8>> = Vec::new();
        for i in 0..6u64 {
            let (_, n) = send
                .encrypt_next(&[], format!("m{i}").as_bytes(), &mut ctbuf)
                .unwrap();
            sealed.push(ctbuf[..n].to_vec());
        }

        let (_, mut recv) = fixed_epoch_transport().into_datagram_with_epoch(size);
        let mut pt = [0u8; 64];

        // Forge an epoch-1 packet (counter 4, within the cap) with a corrupt
        // ciphertext. The candidate derivation runs, the tag fails, and the
        // committed keys must stay at epoch 0.
        let mut forged = sealed[4].clone();
        forged[0] ^= 0xFF;
        let err = recv.decrypt_at(4, &[], &forged, &mut pt).unwrap_err();
        assert!(matches!(err, error::HandshakeError::DecryptionFailed));

        // Proof of no advance: an epoch-0 packet still opens as current, and a
        // genuine epoch-1 packet still triggers a fresh, successful commit.
        let n = recv.decrypt_at(0, &[], &sealed[0], &mut pt).unwrap();
        assert_eq!(&pt[..n], b"m0");
        let n = recv.decrypt_at(4, &[], &sealed[4], &mut pt).unwrap();
        assert_eq!(&pt[..n], b"m4");
        let n = recv.decrypt_at(5, &[], &sealed[5], &mut pt).unwrap();
        assert_eq!(&pt[..n], b"m5");
    }

    /// An epoch-ratcheting sender still refuses to seal at counter 2^64 − 1.
    /// A huge epoch size keeps the ratchet target trivial so the shared
    /// exhaustion guard — not the ratchet loop — is what fires.
    #[test]
    fn datagram_epoch_seal_refuses_nonce_exhaustion() {
        let big = NonZeroU64::new(u64::MAX).unwrap();
        let (mut send, _) = fixed_epoch_transport().into_datagram_with_epoch(big);

        // One short of the cap: succeeds, reports u64::MAX − 1.
        send.set_counter_for_test(u64::MAX - 1);
        let mut ct = [0u8; 64];
        let (c, _) = send.encrypt_next(&[], b"x", &mut ct).unwrap();
        assert_eq!(c, u64::MAX - 1);

        // Counter is now u64::MAX: the next seal must refuse and write nothing.
        let mut ct2 = [0xABu8; 64];
        let err = send.encrypt_next(&[], b"x", &mut ct2).unwrap_err();
        assert!(matches!(err, error::HandshakeError::NonceOverflow));
        assert_eq!(ct2, [0xABu8; 64]);
    }

    #[test]
    fn transport_rekey_desync_rejected() {
        let psk = Psk::from_bytes([0x22; 32]);
        let (mut i_transport, mut r_transport) = complete_ikpsk1(&psk);

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
        let mut provider = EphemeralOnly::new(rand::make_rng::<StdRng>());

        let responder_static = provider.generate::<P256>().unwrap();
        let responder_pub = provider.public(&responder_static).unwrap();

        let prologue = b"hiss/v1";

        let (msg, mut i_transport) = N::initiator(
            EphemeralOnly::new(rand::make_rng::<StdRng>()),
            prologue,
            responder_pub,
        )
        .write_message_1()
        .unwrap();

        let mut r_transport = N::responder(
            EphemeralOnly::new(rand::make_rng::<StdRng>()),
            prologue,
            responder_static,
        )
        .unwrap()
        .read_message_1(&msg)
        .unwrap();

        // Transport works with matching prologue.
        let mut ct = [0u8; 64];
        let mut pt = [0u8; 64];
        let ct_len = i_transport.send(b"hello", &mut ct).unwrap();
        let pt_len = r_transport.receive(&ct[..ct_len], &mut pt).unwrap();
        assert_eq!(&pt[..pt_len], b"hello");
    }

    #[test]
    fn mismatched_prologue_rejected() {
        let mut provider = EphemeralOnly::new(rand::make_rng::<StdRng>());

        let responder_static = provider.generate::<P256>().unwrap();
        let responder_pub = provider.public(&responder_static).unwrap();

        // Initiator uses prologue "v1", responder uses "v2".
        let (msg, _i_transport) = N::initiator(
            EphemeralOnly::new(rand::make_rng::<StdRng>()),
            b"v1",
            responder_pub,
        )
        .write_message_1()
        .unwrap();

        // The read fails because the handshake hashes diverge on the
        // differing prologues — the payload AEAD tag will not match.
        let outcome = N::responder(
            EphemeralOnly::new(rand::make_rng::<StdRng>()),
            b"v2",
            responder_static,
        )
        .unwrap()
        .read_message_1(&msg);
        assert!(matches!(outcome, Err(HandshakeError::DecryptionFailed)));
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
        ) -> (transport::Transport<IKpsk1>, transport::Transport<IKpsk1>) {
            let provider = EphemeralOnly::new(rand::make_rng::<StdRng>());
            let responder_pub = provider.public(&responder_static).unwrap();

            let (msg1, i_hs) = IKpsk1::initiator(
                EphemeralOnly::new(rand::make_rng::<StdRng>()),
                &[],
                responder_pub,
            )
            .write_message_1(initiator_static, &psk)
            .unwrap();

            let r_hs = IKpsk1::responder(
                EphemeralOnly::new(rand::make_rng::<StdRng>()),
                &[],
                responder_static,
            )
            .unwrap()
            .read_message_1(&msg1, &psk)
            .unwrap();

            let (msg2, r_transport) = r_hs.write_message_2().unwrap();
            let i_transport = i_hs.read_message_2(&msg2).unwrap();

            (i_transport, r_transport)
        }

        proptest! {
            /// Any plaintext (up to 4 KiB) survives an IKpsk1 round-trip.
            #[test]
            fn transport_any_payload(
                plaintext in proptest::collection::vec(any::<u8>(), 0..4096),
                psk in any::<[u8; 32]>().prop_map(Psk::from_bytes),
            ) {
                let i_sk = EphemeralOnly::new(rand::make_rng::<StdRng>()).generate::<P256>().unwrap();
                let r_sk = EphemeralOnly::new(rand::make_rng::<StdRng>()).generate::<P256>().unwrap();

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
                let i_sk = EphemeralOnly::new(rand::make_rng::<StdRng>()).generate::<P256>().unwrap();
                let r_sk = EphemeralOnly::new(rand::make_rng::<StdRng>()).generate::<P256>().unwrap();

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
                let r_sk = EphemeralOnly::new(rand::make_rng::<StdRng>()).generate::<P256>().unwrap();
                let garbage: [u8; IKpsk1::MSG1_SIZE] =
                    garbage.try_into().expect("generated at the wire size");

                // Random bytes of the correct length — rejected either as
                // an invalid curve point at the `e` token, or by the AEAD
                // tag on the encrypted static at `s`. Either way the read
                // fails and no handshake state comes back.
                let outcome = IKpsk1::responder(
                    EphemeralOnly::new(rand::make_rng::<StdRng>()),
                    &[],
                    r_sk,
                )
                .unwrap()
                .read_message_1(&garbage, &Psk::from_bytes([0u8; 32]));
                prop_assert!(outcome.is_err());
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
}
