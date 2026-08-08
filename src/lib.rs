//! `hiss` — the [Noise Protocol Framework][noise], resolved at compile time.
//!
//! `hiss` is a Noise Protocol Framework implementation in which the
//! handshake is chosen at compile time: you name a pattern, a curve, a
//! cipher, and a hash, and the compiler builds — and checks — exactly
//! that protocol for you. There is nothing to configure at runtime and
//! nothing to negotiate; if it builds, the handshake is well-formed.
//!
//! Concretely, a [`Noise<Pattern, Curve, Cipher, Hash>`](noise::Noise)
//! is *zero-sized*: the pattern, curve, cipher, and hash are type
//! parameters, so every message size is an associated `const` and every
//! protocol misuse — a token out of order, a wrong-direction message, a
//! malformed pattern — is a *compile error*, rejected by the type-state
//! and the [`WellFormed`](noise::WellFormed) pattern guard rather than
//! at runtime. Get the handshake wrong and it never builds.
//!
//! # Quickstart
//!
//! Two peers authenticate each other and exchange an encrypted message in
//! each direction, neither knowing the other's key in advance. Four steps,
//! each one a doctest that compiles and runs. Assembled into a single
//! program it is the `quickstart` example in the repository —
//! `cargo run --example quickstart`.
//!
//! You write the pattern in Noise's own notation together with a concrete
//! suite, and the [`noise!`](crate::noise!) macro generates a type-state
//! state machine for it: one method per handshake message, every message a
//! fixed-size `[u8; N]` known at compile time. It performs **no I/O** —
//! `write_message_N` hands you the bytes and you move them however you
//! already move bytes. See the [`noise!`](crate::noise!) docs for the DSL
//! and the full generated API.
//!
//! ### 1. Describe the handshake you want
//!
//! You write it in the Noise specification's own notation and `hiss`
//! generates the code. `Channel` below is the `XX` shape: three messages,
//! both sides proving who they are along the way.
//!
//! ```rust
//! use hiss::noise::{Blake2b, ChaChaPoly, X25519};
//!
//! hiss::noise! {
//!     /// Mutual authentication; neither side pre-knows the other's key.
//!     pub Channel<X25519, ChaChaPoly, Blake2b> {
//!         -> e
//!         <- e, ee, s, es
//!         -> s, se
//!     }
//! }
//! # fn main() {}
//! ```
//!
//! ### 2. Give each side a long-term key
//!
//! `Channel` authenticates both parties, so each owns a key pair that
//! outlives the connection. Nothing is shared in advance — they exchange
//! public halves during the handshake.
//!
//! ```rust
//! # use hiss::noise::{Blake2b, ChaChaPoly, X25519};
//! # hiss::noise! {
//! #     pub Channel<X25519, ChaChaPoly, Blake2b> {
//! #         -> e
//! #         <- e, ee, s, es
//! #         -> s, se
//! #     }
//! # }
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use hiss::provider::{EphemeralOnly, ProviderExt};
//!
//! let mut alice_keys = EphemeralOnly::new(rand::rng());
//! let alice_static = alice_keys.generate::<X25519>()?;
//!
//! let mut bob_keys = EphemeralOnly::new(rand::rng());
//! let bob_static = bob_keys.generate::<X25519>()?;
//! # let _ = (&alice_static, &bob_static, &alice_keys, &bob_keys);
//! # Ok(())
//! # }
//! ```
//!
//! ### 3. Run the handshake
//!
//! Three messages, and this is all of it. Each call hands you the bytes to
//! send; putting them on a socket, a queue, or a QR code is your business —
//! `hiss` performs no I/O.
//!
//! ```rust
//! # use hiss::noise::{Blake2b, ChaChaPoly, X25519};
//! # hiss::noise! {
//! #     pub Channel<X25519, ChaChaPoly, Blake2b> {
//! #         -> e
//! #         <- e, ee, s, es
//! #         -> s, se
//! #     }
//! # }
//! # use hiss::provider::{EphemeralOnly, ProviderExt};
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # let mut alice_keys = EphemeralOnly::new(rand::rng());
//! # let alice_static = alice_keys.generate::<X25519>()?;
//! # let mut bob_keys = EphemeralOnly::new(rand::rng());
//! # let bob_static = bob_keys.generate::<X25519>()?;
//! let (msg1, alice) = Channel::initiator(alice_keys, &[]).write_message_1()?;
//! let bob = Channel::responder(bob_keys, &[]).read_message_1(&msg1)?;
//! let (msg2, bob) = bob.write_message_2(bob_static)?;
//! let (msg3, mut alice) = alice.read_message_2(&msg2)?.write_message_3(alice_static)?;
//! let mut bob = bob.read_message_3(&msg3)?;
//! # let _ = (&mut alice, &mut bob);
//! # Ok(())
//! # }
//! ```
//!
//! Every message size is a compile-time constant — `Channel::MSG1_SIZE` and
//! friends — so framing the handshake is free: read exactly that many bytes.
//!
//! ### 4. Talk
//!
//! Both ends now hold a `Transport`. `OVERHEAD` is what the authentication
//! tag costs you per message.
//!
//! ```rust
//! # use hiss::noise::{Blake2b, ChaChaPoly, X25519};
//! # hiss::noise! {
//! #     pub Channel<X25519, ChaChaPoly, Blake2b> {
//! #         -> e
//! #         <- e, ee, s, es
//! #         -> s, se
//! #     }
//! # }
//! # use hiss::provider::{EphemeralOnly, ProviderExt};
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # let mut alice_keys = EphemeralOnly::new(rand::rng());
//! # let alice_static = alice_keys.generate::<X25519>()?;
//! # let mut bob_keys = EphemeralOnly::new(rand::rng());
//! # let bob_static = bob_keys.generate::<X25519>()?;
//! # let (msg1, alice) = Channel::initiator(alice_keys, &[]).write_message_1()?;
//! # let bob = Channel::responder(bob_keys, &[]).read_message_1(&msg1)?;
//! # let (msg2, bob) = bob.write_message_2(bob_static)?;
//! # let (msg3, mut alice) = alice.read_message_2(&msg2)?.write_message_3(alice_static)?;
//! # let mut bob = bob.read_message_3(&msg3)?;
//! use hiss::noise::Transport;
//!
//! let mut wire = [0u8; 32 + Transport::<Channel>::OVERHEAD];
//! let mut got = [0u8; 32];
//!
//! let n = alice.send(b"ping", &mut wire)?;
//! let m = bob.receive(&wire[..n], &mut got)?;
//! assert_eq!(&got[..m], b"ping");
//!
//! let n = bob.send(b"pong", &mut wire)?;
//! let m = alice.receive(&wire[..n], &mut got)?;
//! assert_eq!(&got[..m], b"pong");
//! # Ok(())
//! # }
//! ```
//!
//! # Suite and breadth
//!
//! The default suite is **P-256 / ChaCha20-Poly1305 / BLAKE2b** —
//! [`P256`](noise::P256), [`ChaChaPoly`](noise::ChaChaPoly), and
//! [`Blake2b`](noise::Blake2b). Eleven fundamental patterns are provided as
//! markers in [`noise::pattern`], each combined with a suite
//! through [`Noise<P, Cu, Ci, H>`](noise::Noise):
//! [`N`](noise::pattern::N), [`K`](noise::pattern::K),
//! [`Kpsk0`](noise::pattern::Kpsk0), [`IKpsk1`](noise::pattern::IKpsk1),
//! [`IK`](noise::pattern::IK), [`NK`](noise::pattern::NK),
//! [`IX`](noise::pattern::IX), [`XK`](noise::pattern::XK),
//! [`NN`](noise::pattern::NN), [`XX`](noise::pattern::XX), and
//! [`X`](noise::pattern::X). Three
//! Diffie-Hellman curves are supported —
//! [`P256`](noise::P256), [`X25519`](noise::X25519) (the Noise `25519`
//! curve), and [`X448`](noise::X448) (the Noise `448` curve) — with
//! Ed25519 reserved for identity and signing.
//!
//! # Providers
//!
//! The handshake performs no cryptography itself; it delegates to a
//! *provider*. The provider traits form a small hierarchy:
//!
//! * [`CryptoKeyProvider<C: Curve>`](provider::CryptoKeyProvider) is the
//!   key-generation base, refined for awaitable backends by
//!   [`CryptoKeyProviderAsync`](provider::CryptoKeyProviderAsync).
//! * [`DhProvider<C: DhCurve>`](provider::DhProvider) (and
//!   [`DhProviderAsync`](provider::DhProviderAsync)) add the ECDH the
//!   handshake actually consumes.
//! * [`SigningProvider`](provider::SigningProvider) (and
//!   [`SigningProviderAsync`](provider::SigningProviderAsync)) cover
//!   identity signing, which lives *around* the channel rather than
//!   inside the Noise handshake.
//!
//! Two backends implement these traits:
//!
//! * [`EphemeralOnly<R>`](provider::EphemeralOnly) — pure software, over
//!   a caller-supplied CSPRNG `R`, via `eccoxide`/`cryptoxide`.
//! * `AppleSecureEnclave` (Apple platforms) — P-256 keys held in the
//!   Secure Enclave; software Ed25519 over a hardware-sealed seed.
//!
//! # Security posture
//!
//! * Secret material is zeroised on drop (see [`zeroize`]) and is never
//!   required to be `Clone`.
//! * ECDSA signing is deterministic (RFC 6979), low-S, and
//!   non-malleable; there is no signing RNG.
//! * P-256 scalar multiplication is constant-time (the fixed-base comb
//!   relies on `eccoxide`'s `table` feature, enabled by default).
//! * P-256 ECDH rejects a degenerate (identity) shared secret rather
//!   than returning it; on the prime-order curve the identity is the
//!   only such point. The Noise `25519` and `448` curves perform no
//!   equivalent check — per the spec (and RFC 7748) a low-order peer key
//!   simply yields an all-zero secret rather than an error.
//!
//! This crate has **not** been independently audited and is pre-1.0.
//!
//! # Feature flags
//!
//! * `async-io` — pulls in `tokio` for `AsyncHandshake`, part of the legacy
//!   I/O driver API that is **scheduled for removal**. New code uses
//!   [`noise!`](crate::noise!) and needs no feature.
//! * `x25519-cryptoxide` (**default**) — back X25519's software DH with
//!   `cryptoxide`'s `x25519` (the faster backend). Build with
//!   `--no-default-features` to fall back to the `eccoxide` ladder; output
//!   is byte-for-byte identical, so this only changes which dependency
//!   carries the primitive.
//!
//! The Noise `fallback` modifier is an intentional non-goal, not a
//! missing feature: it is optional in the Noise spec and unnecessary for
//! the targeted use cases.
//!
//! # Modules
//!
//! * **[`curve`]** — Elliptic-curve math and key/handle types: ECDSA
//!   signing and ECDH on NIST P-256 (secp256r1) and Ed25519, plus the
//!   [`Curve`](curve::Curve) trait tying them to the type-level protocol.
//!
//! * **[`provider`]** — the backends that *perform* a curve's
//!   operations: [`EphemeralOnly`](provider::EphemeralOnly) (pure
//!   software, via `eccoxide`/`cryptoxide`) and, on Apple platforms,
//!   `AppleSecureEnclave` (P-256 in the Secure Enclave; software Ed25519
//!   with a hardware-sealed seed).
//!
//! * **[`mod@noise`]** — Compile-time Noise protocol descriptor. Encodes
//!   the handshake pattern, curve, cipher, and hash as zero-sized
//!   types so all buffer sizes and operations are known at
//!   monomorphisation time.
//!
//! * **[`psk`]** — Pre-shared keys for the `*psk*` patterns
//!   ([`Kpsk0`](noise::pattern::Kpsk0), [`IKpsk1`](noise::pattern::IKpsk1)): a
//!   fixed-size [`Psk`](psk::Psk) mixed into the handshake hash.
//!
//! * **[`zeroize`]** — Volatile zeroing of secret material.
//!   Prevents the compiler from eliding zero-fills via
//!   `ptr::write_volatile` and a compiler fence.
//!
//! Internal modules (not re-exported):
//!
//! * `asn1` — Minimal ASN.1 DER reader (and test-only writer) used
//!   to decode ECDSA signatures produced by Apple's Security
//!   framework, which returns them in X9.62 / DER format rather
//!   than raw `(r, s)` bytes.
//!
//! [noise]: https://noiseprotocol.org/
//!

#![warn(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]

// The code emitted by `noise!` references `::hiss::…` paths so it works in
// any downstream crate; this self-alias makes those paths resolve when the
// macro is invoked *inside* hiss itself (the built-in patterns).
extern crate self as hiss;

// The DER codec (`ASN1Reader`/`ASN1Writer`) is Apple/test-only, but its error
// type `Asn1Error` is part of the public `curve::p256::Error` enum on every
// platform, so the module itself is always compiled (the codec is gated inside).
mod asn1;
pub mod curve;
pub mod noise;
pub mod provider;
pub mod psk;
pub mod zeroize;

/// Define a Noise handshake in the specification's own pattern notation
/// — see the macro's documentation for the DSL and the generated API.
///
/// Naming a suite generates a documented, sans-io state machine with
/// fixed-size messages; omitting it defines a suite-generic pattern
/// marker (how [`noise::pattern`]'s built-ins are defined).
///
/// # The name you choose is the protocol name
///
/// The identifier becomes the pattern's `NAME`, and that is what goes into
/// the Noise protocol name — `Noise_<name>_<curve>_<cipher>_<hash>` — which
/// seeds the initial handshake hash. So declaring `pub Ceremony<…>` over an
/// `IKpsk1` token sequence yields `Noise_Ceremony_25519_ChaChaPoly_BLAKE2b`.
/// That is perfectly self-consistent: two peers both built this way will
/// talk to each other, and every round-trip test will pass. It will not
/// interoperate with any other Noise implementation.
///
/// **Name the type for its pattern.** If you want a name describing what the
/// channel is *for*, make it a type alias.
///
/// ```rust
/// use hiss::noise::{Blake2b, ChaChaPoly, X25519};
///
/// hiss::noise! {
///     /// Ceremony channel between two enrolled devices.
///     pub IKpsk1<X25519, ChaChaPoly, Blake2b> {
///         <- s
///         ...
///         -> e, es, s, ss, psk
///         <- e, ee, se
///     }
/// }
///
/// // Noise_IKpsk1_25519_ChaChaPoly_BLAKE2b — say what it is for over here.
/// type Ceremony = IKpsk1;
///
/// # fn main() {
/// assert_eq!(<Ceremony as hiss::noise::Pattern>::NAME, "IKpsk1");
/// # }
/// ```
///
/// # Message sizes are types, not lengths
///
/// `read_message_N` takes `&[u8; MSGn_SIZE]`, so a buffer of the wrong
/// length is rejected by the compiler rather than at run time — there is no
/// short-read or trailing-garbage case to handle, because neither can be
/// constructed:
///
/// ```compile_fail
/// use hiss::noise::{Blake2b, ChaChaPoly, X25519};
/// use hiss::provider::EphemeralOnly;
///
/// hiss::noise! {
///     pub NN<X25519, ChaChaPoly, Blake2b> { -> e <- e, ee }
/// }
///
/// fn main() {
///     let truncated = [0u8; 8];
///     // error[E0308]: mismatched types — expected `&[u8; 32]`, found `&[u8; 8]`
///     let _ = NN::responder(EphemeralOnly::new(rand::rng()), &[])
///         .read_message_1(&truncated);
/// }
/// ```
pub use hiss_macros::noise;
