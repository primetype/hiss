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
//! | `P`       | [`Pattern`] | [`IKpsk1`]  | Token sequences, pre-messages   |
//! | `Cu`      | [`Curve`]   | [`P256`]    | Key sizes, DH output length     |
//! | `Ci`      | [`Cipher`]  | [`ChaChaPoly`] | Tag size, AEAD operations    |
//! | `H`       | [`Hash`]    | [`Blake2b`] | Hash length, HMAC, HKDF         |
//!
//! A type alias pins the protocol for an entire application:
//!
//! ```
//! use hiss::noise::*;
//!
//! type Channel = Noise<IKpsk1, P256, ChaChaPoly, Blake2b>;
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
//! # type Channel = Noise<IKpsk1, P256, ChaChaPoly, Blake2b>;
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
//! parameter. Each call to [`set_s()`] or [`set_rs()`] consumes one
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
//! ## 4. Handshake state machine
//!
//! Three state types form a type-state machine:
//!
//! - **[`HandshakeState`]** — between messages. Offers `e()` /
//!   `s()` (to start sending) or `read()` (to start receiving),
//!   depending on the next message direction and role.
//! - **[`Sending`]** — within a send message. Each token method
//!   appends data to an internal buffer and advances the token
//!   Cons-list.
//! - **[`Receiving`]** — within a receive message. Each token
//!   method reads data from the buffer and advances the token
//!   Cons-list.
//!
//! When the last token in a message is processed, the return type
//! changes automatically:
//!
//! **Sending** (building an outgoing message):
//! - More messages remain → `(Box<[u8]>, HandshakeState<…>)`
//! - Last message complete → `(Box<[u8]>, Transport<N>)`
//!
//! **Receiving** (consuming an incoming message):
//! - More messages remain → `HandshakeState<…>`
//! - Last message complete → `Transport<N>`
//!
//! On the receiving side the caller already provided the bytes via
//! `read(&msg)`, so there is nothing to hand back — only the next
//! state (or for revealing tokens like `e`/`s`, the revealed public
//! key paired with the next state).
//!
//! This is encoded via three non-overlapping `impl` blocks per token
//! per context (send/recv), selected by the Cons-list tail. The
//! compiler picks the right one — no `match`, no `if`, no runtime
//! check.
//!
//! # Compile-time message sizes
//!
//! Because every component size is a `const` — public key size from
//! the [`Curve`], tag size from the [`Cipher`], hash length from the
//! [`Hash`] — the exact byte size of every handshake message is
//! known at compile time. For `Noise_IKpsk1_P256_ChaChaPoly_BLAKE2b`:
//!
//! | Message | Contents                              | Size (bytes)     |
//! |---------|---------------------------------------|------------------|
//! | msg1    | `e_pub` + `encrypted(s_pub)` + tag    | 65 + 65 + 16 = 146 |
//! | msg2    | `e_pub`                               | 65               |
//!
//! # Async crypto provider
//!
//! Token methods are `async` because the [`CryptoProviderAsync`] trait is
//! async-native. This allows pluggable crypto backends:
//!
//! - **Software** (`eccoxide`/`cryptoxide`) — resolves immediately.
//! - **Secure Enclave** (Apple CryptoKit) — suspends until hardware
//!   completes; may prompt for biometric authentication.
//! - **KMS / HSM / USB hardware key** — suspends until the external
//!   device responds.
//! - **WebCrypto** (WASM) — suspends until the browser promise
//!   resolves.
//!
//! The handshake state machine is a single `async` function that
//! `await`s each crypto operation. The runtime handles scheduling
//! transparently.
//!
//! # Usage
//!
//! ```ignore
//! use hiss::noise::*;
//!
//! type Channel = Noise<IKpsk1, P256, ChaChaPoly, Blake2b>;
//!
//! // ── Initiator ───────────────────────────────────────────
//! let hs = Channel::initiate(provider, &[])
//!     .set_rs(responder_pub);                     // <- s pre-message
//!
//! let (msg1, hs) = hs
//!     .e().await?                                 // -> e
//!     .es().await?                                //    es
//!     .s(initiator_static).await?                 //    s
//!     .ss().await?                                //    ss
//!     .psk(&psk).await?;                          //    psk
//!
//! let (re, recv) = hs                             // <- e, ee, se
//!     .read(&msg2)?
//!     .e().await?;                                // remote ephemeral revealed
//! let transport = recv
//!     .ee().await?
//!     .se().await?;
//!
//! // ── Responder ───────────────────────────────────────────
//! let hs = Channel::respond(provider, &[])
//!     .set_s(responder_static)?;                  // <- s pre-message
//!
//! let (re, recv) = hs                             // -> e, es, s, ss, psk
//!     .read(&msg1)?
//!     .e().await?;                                // remote ephemeral revealed
//! let recv = recv
//!     .es().await?;
//! let (rs, recv) = recv
//!     .s().await?;                                // remote static revealed
//! let recv = recv
//!     .ss().await?;
//! let hs = recv
//!     .psk(&psk).await?;
//!
//! let (msg2, transport) = hs
//!     .e().await?                                 // <- e, ee, se
//!     .ee().await?
//!     .se().await?;
//! ```
//!
//! [`CryptoProviderAsync`]: crate::curve::CryptoProviderAsync

pub(crate) mod buffers;
pub mod cipher;
pub mod cipher_state;
pub mod curve;
pub mod error;
#[allow(clippy::type_complexity)]
pub mod handshake;
pub mod hash;
pub mod pattern;
#[allow(clippy::type_complexity)]
pub mod process;
pub mod role;
pub mod seal;
pub mod session_id;
pub mod symmetric_state;
pub mod tokens;
pub mod transport;

pub use self::cipher::{ChaChaPoly, Cipher};
pub use self::cipher_state::CipherState;
pub use self::curve::{Curve, P256};
pub use self::error::HandshakeError;
pub use self::handshake::{HandshakeState, Receiving, Sending};
// Protocol re-exported from this module (defined below on Noise).
pub use self::hash::{Blake2b, Hash};
pub use self::pattern::{IKpsk1, K, Kpsk0, N, Pattern};
pub use self::role::{Initiator, Responder, Role};
pub use self::session_id::SessionId;
pub use self::symmetric_state::SymmetricState;
pub use self::tokens::*;
pub use self::transport::{Transport, TransportRecv, TransportSend};

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

impl<P: Pattern, Cu: Curve, Ci: Cipher, H: Hash> Noise<P, Cu, Ci, H> {
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
/// parameter on [`HandshakeState`], [`Sending`], and [`Receiving`]
/// instead of spreading four separate generic parameters.
pub trait Protocol {
    /// The handshake pattern (e.g. [`IKpsk1`]).
    type Pattern: Pattern;
    /// The DH curve (e.g. [`P256`]).
    type Curve: Curve;
    /// The AEAD cipher (e.g. [`ChaChaPoly`]).
    type Cipher: Cipher;
    /// The hash function (e.g. [`Blake2b`]).
    type Hash: Hash;
}

impl<P: Pattern, Cu: Curve, Ci: Cipher, H: Hash> Protocol for Noise<P, Cu, Ci, H> {
    type Pattern = P;
    type Curve = Cu;
    type Cipher = Ci;
    type Hash = H;
}

impl<P: Pattern, Cu: Curve, Ci: Cipher, H: Hash> Noise<P, Cu, Ci, H> {
    /// Begin a handshake as the **initiator**.
    ///
    /// The `prologue` is mixed into the handshake hash before any
    /// tokens are processed. Both sides must use the same prologue.
    ///
    /// # Example
    ///
    /// ```ignore
    /// type Channel = Noise<IKpsk1, P256, ChaChaPoly, Blake2b>;
    ///
    /// let hs = Channel::initiate(provider, &[])
    ///     .set_rs(responder_pub);
    /// ```
    pub fn initiate<CP: crate::curve::CryptoProviderAsync<Cu>>(
        provider: CP,
        prologue: &[u8],
    ) -> HandshakeState<Self, Initiator, P::PreMessages, P::Messages, CP> {
        HandshakeState::new(provider, prologue)
    }

    /// Begin a handshake as the **responder**.
    ///
    /// The `prologue` is mixed into the handshake hash before any
    /// tokens are processed. Both sides must use the same prologue.
    ///
    /// # Example
    ///
    /// ```ignore
    /// type Channel = Noise<IKpsk1, P256, ChaChaPoly, Blake2b>;
    ///
    /// let hs = Channel::respond(provider, &[])
    ///     .set_s(our_static)?;
    /// ```
    pub fn respond<CP: crate::curve::CryptoProviderAsync<Cu>>(
        provider: CP,
        prologue: &[u8],
    ) -> HandshakeState<Self, Responder, P::PreMessages, P::Messages, CP> {
        HandshakeState::new(provider, prologue)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curve::{CryptoKeys, CryptoProviderAsync};
    use crate::curve::p256::{P256r1PrivateKey, P256r1PublicKey, SoftwareCryptoProvider};
    use crate::noise_message_size;
    use crate::psk::Psk;
    type Channel = Noise<IKpsk1, P256, ChaChaPoly, Blake2b>;
    type NoiseSeal = Noise<N, P256, ChaChaPoly, Blake2b>;
    type NoiseK = Noise<K, P256, ChaChaPoly, Blake2b>;
    type NoiseKpsk0 = Noise<Kpsk0, P256, ChaChaPoly, Blake2b>;

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
    #[tokio::test]
    async fn noise_n_seal_open() {
        let provider = SoftwareCryptoProvider;

        // The "recipient" — in practice, the device's own Secure Enclave key.
        let recipient_static = provider.generate_static_key().await.unwrap();
        let recipient_pub = provider.public_key(&recipient_static).unwrap();

        let psk_to_seal = Psk::from_bytes([0x42; 32]);

        // ── Seal (initiator side) ─────────────────────────────────
        let sealer = NoiseSeal::initiate(SoftwareCryptoProvider, &[]).set_rs(recipient_pub);

        let mut msg_buf = [0u8;
            noise_message_size!(curve: P256, cipher: ChaChaPoly, has_psk: false, keyed: false, tokens: [E, Es],)];
        let (msg, mut transport) = sealer.e(&mut msg_buf).await.unwrap().es().await.unwrap();

        // msg = ephemeral public key (65) + payload tag (16) = 81 bytes
        assert_eq!(msg.len(), 81);

        // Encrypt the PSK as a transport payload.
        let mut sealed = [0u8; 64]; // 32 + 16 tag
        let sealed_len = transport.send(psk_to_seal.as_bytes(), &mut sealed).unwrap();

        // ── Open (responder side) ─────────────────────────────────
        let opener = NoiseSeal::respond(SoftwareCryptoProvider, &[])
            .set_s(recipient_static)
            .unwrap();

        let msg = msg.to_vec();
        let (_, recv) = opener.read(&msg).unwrap().e().await.unwrap();
        let mut transport = recv.es().await.unwrap();

        let mut opened = [0u8; 32];
        let opened_len = transport
            .receive(&sealed[..sealed_len], &mut opened)
            .unwrap();

        assert_eq!(opened_len, 32);
        assert_eq!(opened, *psk_to_seal.as_bytes());
    }

    // ── Noise N tampered handshake ─────────────────────────────────

    #[tokio::test]
    async fn noise_n_tampered_ephemeral_rejected() {
        let provider = SoftwareCryptoProvider;

        let recipient_static = provider.generate_static_key().await.unwrap();
        let recipient_pub = provider.public_key(&recipient_static).unwrap();

        let sealer = NoiseSeal::initiate(SoftwareCryptoProvider, &[]).set_rs(recipient_pub);
        let mut msg_buf = [0u8;
            noise_message_size!(curve: P256, cipher: ChaChaPoly, has_psk: false, keyed: false, tokens: [E, Es],)];
        let (msg, _transport) = sealer.e(&mut msg_buf).await.unwrap().es().await.unwrap();

        let mut tampered = msg.to_vec();
        // Flip a byte in the ephemeral public key.
        tampered[1] ^= 0xFF;

        let opener = NoiseSeal::respond(SoftwareCryptoProvider, &[])
            .set_s(recipient_static)
            .unwrap();

        // The tampered ephemeral key causes either an invalid public key
        // error or a DH mismatch leading to payload tag failure.
        let recv = match opener.read(&tampered) {
            Err(_) => return, // invalid message length or parse error
            Ok(recv) => recv,
        };
        let (_, recv) = match recv.e().await {
            Err(_) => return, // invalid ephemeral key
            Ok(result) => result,
        };
        // DH produces wrong shared secret → tag fails.
        assert!(recv.es().await.is_err());
    }

    #[tokio::test]
    async fn noise_n_tampered_tag_rejected() {
        let provider = SoftwareCryptoProvider;

        let recipient_static = provider.generate_static_key().await.unwrap();
        let recipient_pub = provider.public_key(&recipient_static).unwrap();

        let sealer = NoiseSeal::initiate(SoftwareCryptoProvider, &[]).set_rs(recipient_pub);
        let mut msg_buf = [0u8;
            noise_message_size!(curve: P256, cipher: ChaChaPoly, has_psk: false, keyed: false, tokens: [E, Es],)];
        let (msg, _transport) = sealer.e(&mut msg_buf).await.unwrap().es().await.unwrap();

        let mut tampered = msg.to_vec();
        // Flip a byte in the payload tag (last 16 bytes).
        let len = tampered.len();
        tampered[len - 1] ^= 0xFF;

        let opener = NoiseSeal::respond(SoftwareCryptoProvider, &[])
            .set_s(recipient_static)
            .unwrap();

        let (_, recv) = opener.read(&tampered).unwrap().e().await.unwrap();
        // The tag is corrupted, so es must fail at DecryptAndHash.
        assert!(recv.es().await.is_err());
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
    #[tokio::test]
    async fn noise_k_seal_open() {
        let provider = SoftwareCryptoProvider;

        // Alice (sender) and Bob (recipient) each have static keys.
        let alice_static = provider.generate_static_key().await.unwrap();
        let alice_pub = provider.public_key(&alice_static).unwrap();

        let bob_static = provider.generate_static_key().await.unwrap();
        let bob_pub = provider.public_key(&bob_static).unwrap();

        let payload: [u8; 32] = [0x42; 32];

        // ── Seal (Alice → Bob) ──────────────────────────────────
        // Pre-messages: -> s (Alice), <- s (Bob)
        let sealer = NoiseK::initiate(SoftwareCryptoProvider, &[])
            .set_s(alice_static)
            .unwrap()
            .set_rs(bob_pub);

        // -> e, es, ss
        let mut msg_buf = [0u8;
            noise_message_size!(curve: P256, cipher: ChaChaPoly, has_psk: false, keyed: false, tokens: [E, Es, Ss],)];
        let (msg, mut transport) = sealer
            .e(&mut msg_buf)
            .await
            .unwrap()
            .es()
            .await
            .unwrap()
            .ss()
            .await
            .unwrap();

        // msg = ephemeral public key (65) + payload tag (16) = 81 bytes
        assert_eq!(msg.len(), 81);

        let mut sealed = [0u8; 64]; // 32 + 16 tag
        let sealed_len = transport.send(&payload, &mut sealed).unwrap();

        // ── Open (Bob) ──────────────────────────────────────────
        // Pre-messages: -> s (Alice), <- s (Bob)
        let opener = NoiseK::respond(SoftwareCryptoProvider, &[])
            .set_rs(alice_pub)
            .set_s(bob_static)
            .unwrap();

        let msg = msg.to_vec();
        let (_, recv) = opener.read(&msg).unwrap().e().await.unwrap();
        let recv = recv.es().await.unwrap();
        let mut transport = recv.ss().await.unwrap();

        let mut opened = [0u8; 32];
        let opened_len = transport
            .receive(&sealed[..sealed_len], &mut opened)
            .unwrap();

        assert_eq!(opened_len, 32);
        assert_eq!(opened, payload);
    }

    /// Noise Kpsk0 authenticated seal with PSK binding.
    #[tokio::test]
    async fn noise_kpsk0_seal_open() {
        let provider = SoftwareCryptoProvider;

        let alice_static = provider.generate_static_key().await.unwrap();
        let alice_pub = provider.public_key(&alice_static).unwrap();

        let bob_static = provider.generate_static_key().await.unwrap();
        let bob_pub = provider.public_key(&bob_static).unwrap();

        let psk = Psk::from_bytes([0xBB; 32]);
        let payload: [u8; 32] = [0x42; 32];

        // ── Seal (Alice → Bob) ──────────────────────────────────
        let sealer = NoiseKpsk0::initiate(SoftwareCryptoProvider, &[])
            .set_s(alice_static)
            .unwrap()
            .set_rs(bob_pub);

        // -> psk, e, es, ss
        let mut msg_buf = [0u8;
            noise_message_size!(curve: P256, cipher: ChaChaPoly, has_psk: true, keyed: false, tokens: [Psk, E, Es, Ss],)];
        let (msg, mut transport) = sealer
            .psk(&mut msg_buf, &psk)
            .await
            .unwrap()
            .e()
            .await
            .unwrap()
            .es()
            .await
            .unwrap()
            .ss()
            .await
            .unwrap();

        assert_eq!(msg.len(), 81);

        let mut sealed = [0u8; 64];
        let sealed_len = transport.send(&payload, &mut sealed).unwrap();

        // ── Open (Bob) ──────────────────────────────────────────
        let opener = NoiseKpsk0::respond(SoftwareCryptoProvider, &[])
            .set_rs(alice_pub)
            .set_s(bob_static)
            .unwrap();

        let msg = msg.to_vec();
        let recv = opener.read(&msg).unwrap();
        let recv = recv.psk(&psk).await.unwrap();
        let (_, recv) = recv.e().await.unwrap();
        let recv = recv.es().await.unwrap();
        let mut transport = recv.ss().await.unwrap();

        let mut opened = [0u8; 32];
        let opened_len = transport
            .receive(&sealed[..sealed_len], &mut opened)
            .unwrap();

        assert_eq!(opened_len, 32);
        assert_eq!(opened, payload);
    }

    /// Kpsk0 with wrong PSK fails to decrypt.
    #[tokio::test]
    async fn noise_kpsk0_wrong_psk_fails() {
        let provider = SoftwareCryptoProvider;

        let alice_static = provider.generate_static_key().await.unwrap();
        let alice_pub = provider.public_key(&alice_static).unwrap();

        let bob_static = provider.generate_static_key().await.unwrap();
        let bob_pub = provider.public_key(&bob_static).unwrap();

        let psk = Psk::from_bytes([0xBB; 32]);
        let wrong_psk = Psk::from_bytes([0xCC; 32]);
        let payload: [u8; 32] = [0x42; 32];

        // Seal with correct PSK
        let sealer = NoiseKpsk0::initiate(SoftwareCryptoProvider, &[])
            .set_s(alice_static)
            .unwrap()
            .set_rs(bob_pub);

        let mut msg_buf = [0u8;
            noise_message_size!(curve: P256, cipher: ChaChaPoly, has_psk: false, keyed: false, tokens: [E, Es],)];
        let (msg, mut transport) = sealer
            .psk(&mut msg_buf, &psk)
            .await
            .unwrap()
            .e()
            .await
            .unwrap()
            .es()
            .await
            .unwrap()
            .ss()
            .await
            .unwrap();

        let mut sealed = [0u8; 64];
        let _sealed_len = transport.send(&payload, &mut sealed).unwrap();

        // Open with wrong PSK — the empty payload tag verification at
        // the end of the message catches the key divergence immediately.
        let opener = NoiseKpsk0::respond(SoftwareCryptoProvider, &[])
            .set_rs(alice_pub)
            .set_s(bob_static)
            .unwrap();

        let msg = msg.to_vec();
        let recv = opener.read(&msg).unwrap();
        let recv = recv.psk(&wrong_psk).await.unwrap();
        let (_, recv) = recv.e().await.unwrap();
        let recv = recv.es().await.unwrap();
        // ss is the last token — payload tag verification fails because
        // the wrong PSK produced different derived keys.
        let result = recv.ss().await;
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
    #[tokio::test]
    async fn ikpsk1_round_trip() {
        let provider = SoftwareCryptoProvider;

        // ── Key generation ──────────────────────────────────────
        let initiator_static = provider.generate_static_key().await.unwrap();
        let initiator_pub = provider.public_key(&initiator_static).unwrap();

        let responder_static = provider.generate_static_key().await.unwrap();
        let responder_pub = provider.public_key(&responder_static).unwrap();

        // PSK established during the QR ceremony.
        let psk = Psk::from_bytes([0xAA; 32]);

        // ── Construction ────────────────────────────────────────
        let i_hs = Channel::initiate(SoftwareCryptoProvider, &[]).set_rs(responder_pub);

        let r_hs = Channel::respond(SoftwareCryptoProvider, &[])
            .set_s(responder_static)
            .unwrap();

        // ── Message 1: -> e, es, s, ss, psk (initiator sends) ──
        let mut msg1_buf = [0u8;
            noise_message_size!(curve: P256, cipher: ChaChaPoly, has_psk: true, keyed: false, tokens: [E, Es, S, Ss, Psk],)];
        let (msg1, i_hs) = i_hs
            .e(&mut msg1_buf)
            .await
            .unwrap()
            .es()
            .await
            .unwrap()
            .s(initiator_static)
            .await
            .unwrap()
            .ss()
            .await
            .unwrap()
            .psk(&psk)
            .await
            .unwrap();

        // msg1 = ephemeral (65) + encrypted static (65+16) + payload tag (16) = 162 bytes
        assert_eq!(msg1.len(), 162);

        // ── Message 1 (responder receives) ──────────────────────
        let msg1 = msg1.to_vec();

        // The first 65 bytes of msg1 are the initiator's ephemeral
        // public key (SEC1 uncompressed P-256).
        let initiator_e_from_wire =
            P256r1PublicKey::from_bytes(&msg1[..65]).expect("valid ephemeral in msg1");

        let (initiator_ephemeral, recv) = r_hs.read(&msg1).unwrap().e().await.unwrap();

        // The ephemeral key revealed by recv matches what was on the wire.
        assert_eq!(initiator_ephemeral, initiator_e_from_wire);

        let recv = recv.es().await.unwrap();
        let (revealed_initiator_pub, recv) = recv.s().await.unwrap();
        let recv = recv.ss().await.unwrap();
        let r_hs = recv.psk(&psk).await.unwrap();

        // The responder now knows the initiator's static key.
        assert_eq!(revealed_initiator_pub, initiator_pub);

        // ── Message 2: <- e, ee, se (responder sends) ──────────
        let mut msg2_buf = [0u8;
            noise_message_size!(curve: P256, cipher: ChaChaPoly, has_psk: true, keyed: true, tokens: [E, Ee, Se],)];
        let (msg2, r_transport) = r_hs
            .e(&mut msg2_buf)
            .await
            .unwrap()
            .ee()
            .await
            .unwrap()
            .se()
            .await
            .unwrap();

        // msg2 = ephemeral (65) + payload tag (16) = 81 bytes
        assert_eq!(msg2.len(), 81);

        // ── Message 2 (initiator receives) ──────────────────────
        let msg2 = msg2.to_vec();

        // The first 65 bytes of msg2 are the responder's ephemeral
        // public key (SEC1 uncompressed P-256).
        let responder_e_from_wire =
            P256r1PublicKey::from_bytes(&msg2[..65]).expect("valid ephemeral in msg2");

        let (responder_ephemeral, recv) = i_hs.read(&msg2).unwrap().e().await.unwrap();

        // The ephemeral key revealed by recv matches what was on the wire.
        assert_eq!(responder_ephemeral, responder_e_from_wire);

        let i_transport = recv.ee().await.unwrap().se().await.unwrap();

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

    #[tokio::test]
    async fn wrong_message_length_rejected() {
        let provider = SoftwareCryptoProvider;
        let responder_static = provider.generate_static_key().await.unwrap();

        let r_hs = Channel::respond(SoftwareCryptoProvider, &[])
            .set_s(responder_static)
            .unwrap();

        // msg1 should be 162 bytes (65 ephemeral + 65 encrypted static + 16 tag + 16 payload tag) — send 64 instead.
        let bad_msg = [0u8; 64];
        match r_hs.read(&bad_msg) {
            Err(error::HandshakeError::UnexpectedMessageLength {
                expected: 162,
                actual: 64,
            }) => {}
            Err(e) => panic!("expected UnexpectedMessageLength, got {e:?}"),
            Ok(_) => panic!("expected error, got Ok"),
        }
    }

    #[tokio::test]
    async fn expected_message_size_reports_correctly() {
        let provider = SoftwareCryptoProvider;
        let responder_static = provider.generate_static_key().await.unwrap();

        let r_hs = Channel::respond(SoftwareCryptoProvider, &[])
            .set_s(responder_static)
            .unwrap();

        // msg1 (-> e, es, s, ss, psk): 65 (ephemeral) + 65 (encrypted static) + 16 (tag) + 16 (payload tag) = 162
        assert_eq!(r_hs.expected_message_size(), 162);
    }

    #[tokio::test]
    async fn corrupted_encrypted_static_in_msg1_rejected() {
        let provider = SoftwareCryptoProvider;

        let initiator_static = provider.generate_static_key().await.unwrap();
        let responder_static = provider.generate_static_key().await.unwrap();
        let responder_pub = provider.public_key(&responder_static).unwrap();

        let psk = Psk::from_bytes([0xBB; 32]);

        // Initiator constructs msg1 normally.
        let i_hs = Channel::initiate(SoftwareCryptoProvider, &[]).set_rs(responder_pub);

        let mut msg1_buf = [0u8;
            noise_message_size!(curve: P256, cipher: ChaChaPoly, has_psk: true, keyed: false, tokens: [E, Es, S, Ss, Psk],)];
        let (msg1, _) = i_hs
            .e(&mut msg1_buf)
            .await
            .unwrap()
            .es()
            .await
            .unwrap()
            .s(initiator_static)
            .await
            .unwrap()
            .ss()
            .await
            .unwrap()
            .psk(&psk)
            .await
            .unwrap();

        // Corrupt a byte in the encrypted static key area (after the 65-byte ephemeral).
        let mut corrupted = msg1.to_vec();
        corrupted[70] ^= 0xFF;

        // Responder reads msg1 — corruption in the encrypted static key
        // area causes decryption failure at the `s` token.
        let r_hs = Channel::respond(SoftwareCryptoProvider, &[])
            .set_s(responder_static)
            .unwrap();

        let (_, recv) = r_hs.read(&corrupted).unwrap().e().await.unwrap();
        let recv = recv.es().await.unwrap();
        // The `s` token decrypts the static key — corruption causes tag failure.
        assert!(recv.s().await.is_err());
    }

    #[tokio::test]
    async fn mismatched_psk_fails() {
        let provider = SoftwareCryptoProvider;

        let initiator_static = provider.generate_static_key().await.unwrap();
        let responder_static = provider.generate_static_key().await.unwrap();
        let responder_pub = provider.public_key(&responder_static).unwrap();

        let i_psk = Psk::from_bytes([0xAA; 32]);
        let r_psk = Psk::from_bytes([0xBB; 32]); // different!

        // Initiator sends msg1 with i_psk.
        let i_hs = Channel::initiate(SoftwareCryptoProvider, &[]).set_rs(responder_pub);

        let mut msg1_buf = [0u8;
            noise_message_size!(curve: P256, cipher: ChaChaPoly, has_psk: true, keyed: false, tokens: [E, Es, S, Ss, Psk],)];
        let (msg1, _i_hs) = i_hs
            .e(&mut msg1_buf)
            .await
            .unwrap()
            .es()
            .await
            .unwrap()
            .s(initiator_static)
            .await
            .unwrap()
            .ss()
            .await
            .unwrap()
            .psk(&i_psk)
            .await
            .unwrap();
        let msg1 = msg1.to_vec();

        // Responder reads msg1 with r_psk — mismatch.
        let r_hs = Channel::respond(SoftwareCryptoProvider, &[])
            .set_s(responder_static)
            .unwrap();

        let (_, recv) = r_hs.read(&msg1).unwrap().e().await.unwrap();
        let recv = recv.es().await.unwrap();
        let (_, recv) = recv.s().await.unwrap();
        let recv = recv.ss().await.unwrap();

        // The psk token is the last in msg1 — the payload tag
        // verification catches the PSK mismatch immediately.
        let result = recv.psk(&r_psk).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn transport_corrupted_ciphertext_rejected() {
        let provider = SoftwareCryptoProvider;

        let initiator_static = provider.generate_static_key().await.unwrap();
        let responder_static = provider.generate_static_key().await.unwrap();
        let responder_pub = provider.public_key(&responder_static).unwrap();
        let psk = Psk::from_bytes([0xCC; 32]);

        // Complete handshake.
        let i_hs = Channel::initiate(SoftwareCryptoProvider, &[]).set_rs(responder_pub);
        let r_hs = Channel::respond(SoftwareCryptoProvider, &[])
            .set_s(responder_static)
            .unwrap();

        let mut msg1_buf = [0u8;
            noise_message_size!(curve: P256, cipher: ChaChaPoly, has_psk: true, keyed: false, tokens: [E, Es, S, Ss, Psk],)];
        let (msg1, i_hs) = i_hs
            .e(&mut msg1_buf)
            .await
            .unwrap()
            .es()
            .await
            .unwrap()
            .s(initiator_static)
            .await
            .unwrap()
            .ss()
            .await
            .unwrap()
            .psk(&psk)
            .await
            .unwrap();
        let msg1 = msg1.to_vec();
        let (_, recv) = r_hs.read(&msg1).unwrap().e().await.unwrap();
        let recv = recv.es().await.unwrap();
        let (_, recv) = recv.s().await.unwrap();
        let recv = recv.ss().await.unwrap();
        let r_hs = recv.psk(&psk).await.unwrap();

        let mut msg2_buf = [0u8;
            noise_message_size!(curve: P256, cipher: ChaChaPoly, has_psk: true, keyed: true, tokens: [E, Ee, Se],)];
        let (msg2, r_transport) = r_hs
            .e(&mut msg2_buf)
            .await
            .unwrap()
            .ee()
            .await
            .unwrap()
            .se()
            .await
            .unwrap();
        let msg2 = msg2.to_vec();
        let (_, recv) = i_hs.read(&msg2).unwrap().e().await.unwrap();
        let i_transport = recv.ee().await.unwrap().se().await.unwrap();

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

    #[tokio::test]
    async fn transport_multiple_messages_nonce_advances() {
        let provider = SoftwareCryptoProvider;

        let initiator_static = provider.generate_static_key().await.unwrap();
        let responder_static = provider.generate_static_key().await.unwrap();
        let responder_pub = provider.public_key(&responder_static).unwrap();
        let psk = Psk::from_bytes([0xDD; 32]);

        // Complete handshake.
        let i_hs = Channel::initiate(SoftwareCryptoProvider, &[]).set_rs(responder_pub);
        let r_hs = Channel::respond(SoftwareCryptoProvider, &[])
            .set_s(responder_static)
            .unwrap();

        let mut msg1_buf = [0u8;
            noise_message_size!(curve: P256, cipher: ChaChaPoly, has_psk: true, keyed: false, tokens: [E, Es, S, Ss, Psk],)];
        let (msg1, i_hs) = i_hs
            .e(&mut msg1_buf)
            .await
            .unwrap()
            .es()
            .await
            .unwrap()
            .s(initiator_static)
            .await
            .unwrap()
            .ss()
            .await
            .unwrap()
            .psk(&psk)
            .await
            .unwrap();
        let msg1 = msg1.to_vec();
        let (_, recv) = r_hs.read(&msg1).unwrap().e().await.unwrap();
        let recv = recv.es().await.unwrap();
        let (_, recv) = recv.s().await.unwrap();
        let recv = recv.ss().await.unwrap();
        let r_hs = recv.psk(&psk).await.unwrap();

        let mut msg2_buf = [0u8;
            noise_message_size!(curve: P256, cipher: ChaChaPoly, has_psk: true, keyed: true, tokens: [E, Ee, Se],)];
        let (msg2, r_transport) = r_hs
            .e(&mut msg2_buf)
            .await
            .unwrap()
            .ee()
            .await
            .unwrap()
            .se()
            .await
            .unwrap();
        let msg2 = msg2.to_vec();
        let (_, recv) = i_hs.read(&msg2).unwrap().e().await.unwrap();
        let i_transport = recv.ee().await.unwrap().se().await.unwrap();

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

    #[tokio::test]
    async fn ikpsk1_wrong_responder_key_rejected() {
        let provider = SoftwareCryptoProvider;

        let initiator_static = provider.generate_static_key().await.unwrap();
        let responder_static = provider.generate_static_key().await.unwrap();
        let wrong_static = provider.generate_static_key().await.unwrap();
        let wrong_pub = provider.public_key(&wrong_static).unwrap();
        let psk = Psk::from_bytes([0xCC; 32]);

        // Initiator targets the wrong responder public key.
        let i_hs = Channel::initiate(SoftwareCryptoProvider, &[]).set_rs(wrong_pub);

        // Initiator sends msg1 with es DH against the wrong key.
        let mut msg1_buf = [0u8;
            noise_message_size!(curve: P256, cipher: ChaChaPoly, has_psk: true, keyed: false, tokens: [E, Es, S, Ss, Psk],)];
        let (msg1, _i_hs) = i_hs
            .e(&mut msg1_buf)
            .await
            .unwrap()
            .es()
            .await
            .unwrap()
            .s(initiator_static)
            .await
            .unwrap()
            .ss()
            .await
            .unwrap()
            .psk(&psk)
            .await
            .unwrap();
        let msg1 = msg1.to_vec();

        // Actual responder holds a different static key.
        let r_hs = Channel::respond(SoftwareCryptoProvider, &[])
            .set_s(responder_static)
            .unwrap();

        // Responder reads msg1. The es DH produces a different shared
        // secret because the initiator used the wrong responder key.
        // The `es` token itself succeeds (it just mixes in the DH result),
        // but the `s` token fails because the derived cipher key is wrong
        // and cannot decrypt the initiator's encrypted static key.
        let (_, recv) = r_hs.read(&msg1).unwrap().e().await.unwrap();
        let recv = recv.es().await.unwrap();
        let result = recv.s().await;
        assert!(result.is_err());
    }

    // ── Transport direction isolation ───────────────────────────────

    #[tokio::test]
    async fn transport_keys_are_directional() {
        let provider = SoftwareCryptoProvider;

        let initiator_static = provider.generate_static_key().await.unwrap();
        let responder_static = provider.generate_static_key().await.unwrap();
        let responder_pub = provider.public_key(&responder_static).unwrap();
        let psk = Psk::from_bytes([0xFF; 32]);

        // Complete handshake.
        let i_hs = Channel::initiate(SoftwareCryptoProvider, &[]).set_rs(responder_pub);
        let r_hs = Channel::respond(SoftwareCryptoProvider, &[])
            .set_s(responder_static)
            .unwrap();

        let mut msg1_buf = [0u8;
            noise_message_size!(curve: P256, cipher: ChaChaPoly, has_psk: true, keyed: false, tokens: [E, Es, S, Ss, Psk],)];
        let (msg1, i_hs) = i_hs
            .e(&mut msg1_buf)
            .await
            .unwrap()
            .es()
            .await
            .unwrap()
            .s(initiator_static)
            .await
            .unwrap()
            .ss()
            .await
            .unwrap()
            .psk(&psk)
            .await
            .unwrap();
        let msg1 = msg1.to_vec();
        let (_, recv) = r_hs.read(&msg1).unwrap().e().await.unwrap();
        let recv = recv.es().await.unwrap();
        let (_, recv) = recv.s().await.unwrap();
        let recv = recv.ss().await.unwrap();
        let r_hs = recv.psk(&psk).await.unwrap();

        let mut msg2_buf = [0u8;
            noise_message_size!(curve: P256, cipher: ChaChaPoly, has_psk: true, keyed: true, tokens: [E, Ee, Se],)];
        let (msg2, r_transport) = r_hs
            .e(&mut msg2_buf)
            .await
            .unwrap()
            .ee()
            .await
            .unwrap()
            .se()
            .await
            .unwrap();
        let msg2 = msg2.to_vec();
        let (_, recv) = i_hs.read(&msg2).unwrap().e().await.unwrap();
        let i_transport = recv.ee().await.unwrap().se().await.unwrap();

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

    #[tokio::test]
    async fn two_sessions_produce_different_handshake_hashes() {
        // Use a fixed responder key so both sessions share the same
        // responder identity — only ephemeral keys differ.
        let responder_bytes = [0xBB_u8; 32];
        let psk = Psk::from_bytes([0xAA; 32]);

        let mut hashes = Vec::new();

        for _ in 0..2 {
            let responder_static =
                P256r1PrivateKey::from_bytes(responder_bytes).expect("valid test scalar");
            let responder_pub = responder_static.public();

            let initiator_static = SoftwareCryptoProvider.generate_static_key().await.unwrap();

            let i_hs = Channel::initiate(SoftwareCryptoProvider, &[]).set_rs(responder_pub);

            let mut msg1_buf = [0u8;
                noise_message_size!(curve: P256, cipher: ChaChaPoly, has_psk: true, keyed: false, tokens: [E, Es, S, Ss, Psk],)];
            let (msg1, i_hs) = i_hs
                .e(&mut msg1_buf)
                .await
                .unwrap()
                .es()
                .await
                .unwrap()
                .s(initiator_static)
                .await
                .unwrap()
                .ss()
                .await
                .unwrap()
                .psk(&psk)
                .await
                .unwrap();
            let msg1 = msg1.to_vec();

            let r_hs = Channel::respond(SoftwareCryptoProvider, &[])
                .set_s(responder_static)
                .unwrap();

            let (_, recv) = r_hs.read(&msg1).unwrap().e().await.unwrap();
            let recv = recv.es().await.unwrap();
            let (_, recv) = recv.s().await.unwrap();
            let recv = recv.ss().await.unwrap();
            let r_hs = recv.psk(&psk).await.unwrap();

            let mut msg2_buf = [0u8;
                noise_message_size!(curve: P256, cipher: ChaChaPoly, has_psk: true, keyed: true, tokens: [E, Ee, Se],)];
            let (msg2, r_transport) = r_hs
                .e(&mut msg2_buf)
                .await
                .unwrap()
                .ee()
                .await
                .unwrap()
                .se()
                .await
                .unwrap();
            let msg2 = msg2.to_vec();
            let (_, recv) = i_hs.read(&msg2).unwrap().e().await.unwrap();
            let i_transport = recv.ee().await.unwrap().se().await.unwrap();

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
        let provider = SoftwareCryptoProvider;

        let initiator_static = provider.generate_static_key().await.unwrap();
        let initiator_pub = provider.public_key(&initiator_static).unwrap();
        let responder_static = provider.generate_static_key().await.unwrap();
        let responder_pub = provider.public_key(&responder_static).unwrap();
        let psk = Psk::from_bytes([0xCC; 32]);

        // Initiator sends msg1 with the WRONG static key.
        // In IKpsk1 msg1 (-> e, es, s, ss, psk), the `ss` token is
        // DH(wrong_s, responder_s). Since the responder decrypts the
        // wrong key from the `s` token and computes the same ECDH result,
        // the handshake completes — but the responder sees a different
        // initiator identity. The application layer must verify the
        // revealed static key matches the expected peer.
        let wrong_static = provider.generate_static_key().await.unwrap();

        let i_hs = Channel::initiate(SoftwareCryptoProvider, &[]).set_rs(responder_pub);

        let mut msg1_buf = [0u8;
            noise_message_size!(curve: P256, cipher: ChaChaPoly, has_psk: true, keyed: false, tokens: [E, Es, S, Ss, Psk],)];
        let (msg1, i_hs) = i_hs
            .e(&mut msg1_buf)
            .await
            .unwrap()
            .es()
            .await
            .unwrap()
            .s(wrong_static)
            .await
            .unwrap()
            .ss()
            .await
            .unwrap()
            .psk(&psk)
            .await
            .unwrap();
        let msg1 = msg1.to_vec();

        let r_hs = Channel::respond(SoftwareCryptoProvider, &[])
            .set_s(responder_static)
            .unwrap();

        let (_, recv) = r_hs.read(&msg1).unwrap().e().await.unwrap();
        let recv = recv.es().await.unwrap();
        let (revealed_pub, recv) = recv.s().await.unwrap();
        let recv = recv.ss().await.unwrap();
        let r_hs = recv.psk(&psk).await.unwrap();

        // The responder decrypted the wrong initiator static key.
        assert_ne!(revealed_pub, initiator_pub);

        // Complete the handshake — msg2 still works because the `se`
        // token uses DH(wrong_s, responder_e), which both sides compute
        // consistently.
        let mut msg2_buf = [0u8;
            noise_message_size!(curve: P256, cipher: ChaChaPoly, has_psk: true, keyed: true, tokens: [E, Ee, Se],)];
        let (msg2, r_transport) = r_hs
            .e(&mut msg2_buf)
            .await
            .unwrap()
            .ee()
            .await
            .unwrap()
            .se()
            .await
            .unwrap();
        let msg2 = msg2.to_vec();
        let (_, recv) = i_hs.read(&msg2).unwrap().e().await.unwrap();
        let i_transport = recv.ee().await.unwrap().se().await.unwrap();

        // Transport works — keys are derived consistently from the wrong
        // static key. The responder must reject this identity at the
        // application layer. The handshake hash also differs from what
        // the real initiator would produce, so channel binding catches it.
        assert_eq!(i_transport.session_id(), r_transport.session_id());
        drop(i_transport);
        drop(r_transport);
    }

    // ── Corrupted msg1 (tampered ephemeral in IKpsk1) ─────────────────

    #[tokio::test]
    async fn ikpsk1_corrupted_msg1_rejected() {
        let provider = SoftwareCryptoProvider;

        let initiator_static = provider.generate_static_key().await.unwrap();
        let responder_static = provider.generate_static_key().await.unwrap();
        let responder_pub = provider.public_key(&responder_static).unwrap();
        let psk = Psk::from_bytes([0xDD; 32]);

        let i_hs = Channel::initiate(SoftwareCryptoProvider, &[]).set_rs(responder_pub);

        let mut msg1_buf = [0u8;
            noise_message_size!(curve: P256, cipher: ChaChaPoly, has_psk: true, keyed: false, tokens: [E, Es, S, Ss, Psk],)];
        let (msg1, _) = i_hs
            .e(&mut msg1_buf)
            .await
            .unwrap()
            .es()
            .await
            .unwrap()
            .s(initiator_static)
            .await
            .unwrap()
            .ss()
            .await
            .unwrap()
            .psk(&psk)
            .await
            .unwrap();
        let mut corrupted = msg1.to_vec();
        // Corrupt a byte in the ephemeral public key.
        corrupted[5] ^= 0xFF;

        let r_hs = Channel::respond(SoftwareCryptoProvider, &[])
            .set_s(responder_static)
            .unwrap();

        // Responder reads msg1 — corruption may produce an invalid curve
        // point (caught at `e()`) or a valid but wrong point (caught at
        // `es()` when the payload tag fails). Either way, the handshake
        // must not complete.
        let read = r_hs.read(&corrupted).unwrap();
        match read.e().await {
            Err(_) => {} // invalid point — rejected at e() token
            Ok((_, recv)) => {
                // Valid point but wrong — es DH + payload tag catches it.
                assert!(recv.es().await.is_err());
            }
        }
    }

    // ── Corrupted msg2 (tampered ephemeral in IKpsk1) ─────────────────

    #[tokio::test]
    async fn ikpsk1_corrupted_msg2_rejected() {
        let provider = SoftwareCryptoProvider;

        let initiator_static = provider.generate_static_key().await.unwrap();
        let responder_static = provider.generate_static_key().await.unwrap();
        let responder_pub = provider.public_key(&responder_static).unwrap();
        let psk = Psk::from_bytes([0xDD; 32]);

        let i_hs = Channel::initiate(SoftwareCryptoProvider, &[]).set_rs(responder_pub);
        let r_hs = Channel::respond(SoftwareCryptoProvider, &[])
            .set_s(responder_static)
            .unwrap();

        let mut msg1_buf = [0u8;
            noise_message_size!(curve: P256, cipher: ChaChaPoly, has_psk: true, keyed: false, tokens: [E, Es, S, Ss, Psk],)];
        let (msg1, i_hs) = i_hs
            .e(&mut msg1_buf)
            .await
            .unwrap()
            .es()
            .await
            .unwrap()
            .s(initiator_static)
            .await
            .unwrap()
            .ss()
            .await
            .unwrap()
            .psk(&psk)
            .await
            .unwrap();
        let msg1 = msg1.to_vec();
        let (_, recv) = r_hs.read(&msg1).unwrap().e().await.unwrap();
        let recv = recv.es().await.unwrap();
        let (_, recv) = recv.s().await.unwrap();
        let recv = recv.ss().await.unwrap();
        let r_hs = recv.psk(&psk).await.unwrap();

        let mut msg2_buf = [0u8;
            noise_message_size!(curve: P256, cipher: ChaChaPoly, has_psk: true, keyed: true, tokens: [E, Ee, Se],)];
        let (msg2, _) = r_hs
            .e(&mut msg2_buf)
            .await
            .unwrap()
            .ee()
            .await
            .unwrap()
            .se()
            .await
            .unwrap();
        let mut corrupted = msg2.to_vec();
        // Corrupt a byte in the responder's ephemeral public key.
        corrupted[3] ^= 0xFF;

        // Corruption may produce an invalid curve point (caught at `e()`)
        // or a valid but wrong point (caught at `ee()` payload tag).
        let read = i_hs.read(&corrupted).unwrap();
        match read.e().await {
            Err(_) => {} // invalid point — rejected at e() token
            Ok((_, recv)) => {
                assert!(recv.ee().await.is_err());
            }
        }
    }

    // ── Transport replay detection (nonce desync) ─────────────────────

    #[tokio::test]
    async fn transport_replayed_message_rejected() {
        let provider = SoftwareCryptoProvider;

        let initiator_static = provider.generate_static_key().await.unwrap();
        let responder_static = provider.generate_static_key().await.unwrap();
        let responder_pub = provider.public_key(&responder_static).unwrap();
        let psk = Psk::from_bytes([0xEE; 32]);

        // Complete handshake.
        let i_hs = Channel::initiate(SoftwareCryptoProvider, &[]).set_rs(responder_pub);
        let r_hs = Channel::respond(SoftwareCryptoProvider, &[])
            .set_s(responder_static)
            .unwrap();

        let mut msg1_buf = [0u8;
            noise_message_size!(curve: P256, cipher: ChaChaPoly, has_psk: true, keyed: false, tokens: [E, Es, S, Ss, Psk],)];
        let (msg1, i_hs) = i_hs
            .e(&mut msg1_buf)
            .await
            .unwrap()
            .es()
            .await
            .unwrap()
            .s(initiator_static)
            .await
            .unwrap()
            .ss()
            .await
            .unwrap()
            .psk(&psk)
            .await
            .unwrap();
        let msg1 = msg1.to_vec();
        let (_, recv) = r_hs.read(&msg1).unwrap().e().await.unwrap();
        let recv = recv.es().await.unwrap();
        let (_, recv) = recv.s().await.unwrap();
        let recv = recv.ss().await.unwrap();
        let r_hs = recv.psk(&psk).await.unwrap();

        let mut msg2_buf = [0u8;
            noise_message_size!(curve: P256, cipher: ChaChaPoly, has_psk: true, keyed: true, tokens: [E, Ee, Se],)];
        let (msg2, r_transport) = r_hs
            .e(&mut msg2_buf)
            .await
            .unwrap()
            .ee()
            .await
            .unwrap()
            .se()
            .await
            .unwrap();
        let msg2 = msg2.to_vec();
        let (_, recv) = i_hs.read(&msg2).unwrap().e().await.unwrap();
        let i_transport = recv.ee().await.unwrap().se().await.unwrap();

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

    #[tokio::test]
    async fn transport_enforces_max_message_length() {
        let provider = SoftwareCryptoProvider;

        let initiator_static = provider.generate_static_key().await.unwrap();
        let responder_static = provider.generate_static_key().await.unwrap();
        let responder_pub = provider.public_key(&responder_static).unwrap();
        let psk = Psk::from_bytes([0xFF; 32]);

        // Complete handshake.
        let i_hs = Channel::initiate(SoftwareCryptoProvider, &[]).set_rs(responder_pub);
        let r_hs = Channel::respond(SoftwareCryptoProvider, &[])
            .set_s(responder_static)
            .unwrap();

        let mut msg1_buf = [0u8;
            noise_message_size!(curve: P256, cipher: ChaChaPoly, has_psk: true, keyed: false, tokens: [E, Es, S, Ss, Psk],)];
        let (msg1, i_hs) = i_hs
            .e(&mut msg1_buf)
            .await
            .unwrap()
            .es()
            .await
            .unwrap()
            .s(initiator_static)
            .await
            .unwrap()
            .ss()
            .await
            .unwrap()
            .psk(&psk)
            .await
            .unwrap();
        let msg1 = msg1.to_vec();
        let (_, recv) = r_hs.read(&msg1).unwrap().e().await.unwrap();
        let recv = recv.es().await.unwrap();
        let (_, recv) = recv.s().await.unwrap();
        let recv = recv.ss().await.unwrap();
        let r_hs = recv.psk(&psk).await.unwrap();

        let mut msg2_buf = [0u8;
            noise_message_size!(curve: P256, cipher: ChaChaPoly, has_psk: true, keyed: true, tokens: [E, Ee, Se],)];
        let (msg2, r_transport) = r_hs
            .e(&mut msg2_buf)
            .await
            .unwrap()
            .ee()
            .await
            .unwrap()
            .se()
            .await
            .unwrap();
        let msg2 = msg2.to_vec();
        let (_, recv) = i_hs.read(&msg2).unwrap().e().await.unwrap();
        let i_transport = recv.ee().await.unwrap().se().await.unwrap();

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

    #[tokio::test]
    async fn transport_rekey_then_communicate() {
        let provider = SoftwareCryptoProvider;

        let initiator_static = provider.generate_static_key().await.unwrap();
        let responder_static = provider.generate_static_key().await.unwrap();
        let responder_pub = provider.public_key(&responder_static).unwrap();
        let psk = Psk::from_bytes([0x11; 32]);

        // Complete handshake.
        let i_hs = Channel::initiate(SoftwareCryptoProvider, &[]).set_rs(responder_pub);
        let r_hs = Channel::respond(SoftwareCryptoProvider, &[])
            .set_s(responder_static)
            .unwrap();

        let mut msg1_buf = [0u8;
            noise_message_size!(curve: P256, cipher: ChaChaPoly, has_psk: true, keyed: false, tokens: [E, Es, S, Ss, Psk],)];
        let (msg1, i_hs) = i_hs
            .e(&mut msg1_buf)
            .await
            .unwrap()
            .es()
            .await
            .unwrap()
            .s(initiator_static)
            .await
            .unwrap()
            .ss()
            .await
            .unwrap()
            .psk(&psk)
            .await
            .unwrap();
        let msg1 = msg1.to_vec();
        let (_, recv) = r_hs.read(&msg1).unwrap().e().await.unwrap();
        let recv = recv.es().await.unwrap();
        let (_, recv) = recv.s().await.unwrap();
        let recv = recv.ss().await.unwrap();
        let r_hs = recv.psk(&psk).await.unwrap();

        let mut msg2_buf = [0u8;
            noise_message_size!(curve: P256, cipher: ChaChaPoly, has_psk: true, keyed: true, tokens: [E, Ee, Se],)];
        let (msg2, r_transport) = r_hs
            .e(&mut msg2_buf)
            .await
            .unwrap()
            .ee()
            .await
            .unwrap()
            .se()
            .await
            .unwrap();
        let msg2 = msg2.to_vec();
        let (_, recv) = i_hs.read(&msg2).unwrap().e().await.unwrap();
        let i_transport = recv.ee().await.unwrap().se().await.unwrap();

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

    #[tokio::test]
    async fn transport_rekey_desync_rejected() {
        let provider = SoftwareCryptoProvider;

        let initiator_static = provider.generate_static_key().await.unwrap();
        let responder_static = provider.generate_static_key().await.unwrap();
        let responder_pub = provider.public_key(&responder_static).unwrap();
        let psk = Psk::from_bytes([0x22; 32]);

        // Complete handshake.
        let i_hs = Channel::initiate(SoftwareCryptoProvider, &[]).set_rs(responder_pub);
        let r_hs = Channel::respond(SoftwareCryptoProvider, &[])
            .set_s(responder_static)
            .unwrap();

        let mut msg1_buf = [0u8;
            noise_message_size!(curve: P256, cipher: ChaChaPoly, has_psk: true, keyed: false, tokens: [E, Es, S, Ss, Psk],)];
        let (msg1, i_hs) = i_hs
            .e(&mut msg1_buf)
            .await
            .unwrap()
            .es()
            .await
            .unwrap()
            .s(initiator_static)
            .await
            .unwrap()
            .ss()
            .await
            .unwrap()
            .psk(&psk)
            .await
            .unwrap();
        let msg1 = msg1.to_vec();
        let (_, recv) = r_hs.read(&msg1).unwrap().e().await.unwrap();
        let recv = recv.es().await.unwrap();
        let (_, recv) = recv.s().await.unwrap();
        let recv = recv.ss().await.unwrap();
        let r_hs = recv.psk(&psk).await.unwrap();

        let mut msg2_buf = [0u8;
            noise_message_size!(curve: P256, cipher: ChaChaPoly, has_psk: true, keyed: true, tokens: [E, Ee, Se],)];
        let (msg2, r_transport) = r_hs
            .e(&mut msg2_buf)
            .await
            .unwrap()
            .ee()
            .await
            .unwrap()
            .se()
            .await
            .unwrap();
        let msg2 = msg2.to_vec();
        let (_, recv) = i_hs.read(&msg2).unwrap().e().await.unwrap();
        let i_transport = recv.ee().await.unwrap().se().await.unwrap();

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

    #[tokio::test]
    async fn matching_prologue_succeeds() {
        let provider = SoftwareCryptoProvider;

        let responder_static = provider.generate_static_key().await.unwrap();
        let responder_pub = provider.public_key(&responder_static).unwrap();

        let prologue = b"hiss/v1";

        type NoiseSeal = Noise<N, P256, ChaChaPoly, Blake2b>;

        let sealer = NoiseSeal::initiate(SoftwareCryptoProvider, prologue).set_rs(responder_pub);
        let mut msg_buf = [0u8;
            noise_message_size!(curve: P256, cipher: ChaChaPoly, has_psk: false, keyed: false, tokens: [E, Es],)];
        let (msg, mut i_transport) = sealer.e(&mut msg_buf).await.unwrap().es().await.unwrap();
        let msg = msg.to_vec();

        let opener = NoiseSeal::respond(SoftwareCryptoProvider, prologue)
            .set_s(responder_static)
            .unwrap();
        let (_, recv) = opener.read(&msg).unwrap().e().await.unwrap();
        let mut r_transport = recv.es().await.unwrap();

        // Transport works with matching prologue.
        let mut ct = [0u8; 64];
        let mut pt = [0u8; 64];
        let ct_len = i_transport.send(b"hello", &mut ct).unwrap();
        let pt_len = r_transport.receive(&ct[..ct_len], &mut pt).unwrap();
        assert_eq!(&pt[..pt_len], b"hello");
    }

    #[tokio::test]
    async fn mismatched_prologue_rejected() {
        let provider = SoftwareCryptoProvider;

        let responder_static = provider.generate_static_key().await.unwrap();
        let responder_pub = provider.public_key(&responder_static).unwrap();

        type NoiseSeal = Noise<N, P256, ChaChaPoly, Blake2b>;

        // Initiator uses prologue "v1", responder uses "v2".
        let sealer = NoiseSeal::initiate(SoftwareCryptoProvider, b"v1").set_rs(responder_pub);
        let mut msg_buf = [0u8;
            noise_message_size!(curve: P256, cipher: ChaChaPoly, has_psk: false, keyed: false, tokens: [E, Es],)];
        let (msg, _) = sealer.e(&mut msg_buf).await.unwrap().es().await.unwrap();
        let msg = msg.to_vec();

        let opener = NoiseSeal::respond(SoftwareCryptoProvider, b"v2")
            .set_s(responder_static)
            .unwrap();
        let (_, recv) = opener.read(&msg).unwrap().e().await.unwrap();

        // The es token will fail because the handshake hashes diverge
        // due to different prologues — the payload AEAD tag won't match.
        assert!(recv.es().await.is_err());
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
        async fn full_ikpsk1_handshake(
            initiator_static: P256r1PrivateKey,
            responder_static: P256r1PrivateKey,
            psk: Psk,
        ) -> (
            transport::Transport<Channel>,
            transport::Transport<Channel>,
        ) {
            let provider = SoftwareCryptoProvider;
            let responder_pub = provider.public_key(&responder_static).unwrap();

            let i_hs = Channel::initiate(SoftwareCryptoProvider, &[]).set_rs(responder_pub);
            let r_hs = Channel::respond(SoftwareCryptoProvider, &[])
                .set_s(responder_static)
                .unwrap();

            let mut msg1_buf = [0u8;
                noise_message_size!(curve: P256, cipher: ChaChaPoly, has_psk: true, keyed: false, tokens: [E, Es, S, Ss, Psk],)];
            let (msg1, i_hs) = i_hs
                .e(&mut msg1_buf)
                .await
                .unwrap()
                .es()
                .await
                .unwrap()
                .s(initiator_static)
                .await
                .unwrap()
                .ss()
                .await
                .unwrap()
                .psk(&psk)
                .await
                .unwrap();
            let msg1 = msg1.to_vec();
            let (_, recv) = r_hs.read(&msg1).unwrap().e().await.unwrap();
            let recv = recv.es().await.unwrap();
            let (_, recv) = recv.s().await.unwrap();
            let recv = recv.ss().await.unwrap();
            let r_hs = recv.psk(&psk).await.unwrap();

            let mut msg2_buf = [0u8;
                noise_message_size!(curve: P256, cipher: ChaChaPoly, has_psk: true, keyed: true, tokens: [E, Ee, Se],)];
            let (msg2, r_transport) = r_hs
                .e(&mut msg2_buf)
                .await
                .unwrap()
                .ee()
                .await
                .unwrap()
                .se()
                .await
                .unwrap();
            let msg2 = msg2.to_vec();
            let (_, recv) = i_hs.read(&msg2).unwrap().e().await.unwrap();
            let i_transport = recv.ee().await.unwrap().se().await.unwrap();

            (i_transport, r_transport)
        }

        proptest! {
            /// Any plaintext (up to 4 KiB) survives an IKpsk1 round-trip.
            #[test]
            fn transport_any_payload(
                plaintext in proptest::collection::vec(any::<u8>(), 0..4096),
                psk in any::<[u8; 32]>().prop_map(Psk::from_bytes),
            ) {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                rt.block_on(async {
                    let i_sk = SoftwareCryptoProvider.generate_static_key().await.unwrap();
                    let r_sk = SoftwareCryptoProvider.generate_static_key().await.unwrap();

                    let (mut i_t, mut r_t) = full_ikpsk1_handshake(i_sk, r_sk, psk).await;

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

                    Ok(())
                })?;
            }

            /// Corrupting any single byte in a transport ciphertext causes
            /// decryption failure.
            #[test]
            fn transport_any_corruption_detected(
                plaintext in proptest::collection::vec(any::<u8>(), 1..512),
                psk in any::<[u8; 32]>().prop_map(Psk::from_bytes),
                corrupt_pos_seed in any::<usize>(),
            ) {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                rt.block_on(async {
                    let i_sk = SoftwareCryptoProvider.generate_static_key().await.unwrap();
                    let r_sk = SoftwareCryptoProvider.generate_static_key().await.unwrap();

                    let (mut i_t, mut r_t) = full_ikpsk1_handshake(i_sk, r_sk, psk).await;

                    let mut ct = vec![0u8; plaintext.len() + 16];
                    let ct_len = i_t.send(&plaintext, &mut ct).unwrap();

                    // Corrupt a single byte at a random position.
                    let pos = corrupt_pos_seed % ct_len;
                    ct[pos] ^= 0x01;

                    let mut pt = vec![0u8; plaintext.len()];
                    let result = r_t.receive(&ct[..ct_len], &mut pt);
                    prop_assert!(result.is_err());

                    Ok(())
                })?;
            }

            /// Random bytes fed as a handshake msg1 are always rejected.
            #[test]
            fn random_msg1_rejected(
                garbage in proptest::collection::vec(any::<u8>(), 162..163),
            ) {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                rt.block_on(async {
                    let r_sk = SoftwareCryptoProvider.generate_static_key().await.unwrap();
                    let r_hs = Channel::respond(SoftwareCryptoProvider, &[])
                        .set_s(r_sk)
                        .unwrap();

                    // Random bytes of the correct length — should fail at
                    // e() (invalid point), or at s() (AEAD tag mismatch on
                    // the encrypted static key). In IKpsk1, es() just does
                    // DH and mixes — no tag check — so the failure is at s().
                    let read = r_hs.read(&garbage).unwrap();
                    match read.e().await {
                        Err(_) => {} // invalid point
                        Ok((_, recv)) => {
                            let recv = recv.es().await.unwrap();
                            prop_assert!(recv.s().await.is_err());
                        }
                    }

                    Ok(())
                })?;
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
