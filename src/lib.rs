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
//! You need two crates. `hiss` never picks a random-number generator for
//! you, so the CSPRNG is a dependency you choose and hand in:
//!
//! ```toml
//! [dependencies]
//! hiss = "0.2"
//! rand = "0.10"
//! ```
//!
//! ### 1. Describe the handshake you want
//!
//! This one is `XX`: three messages, both sides proving who they are
//! along the way. Name the type after its pattern — the name you write
//! goes on the wire as part of the protocol identity, as
//! [`noise!`](crate::noise!) spells out.
//!
//! ```rust
//! use hiss::noise::{Blake2b, ChaChaPoly, X25519};
//!
//! hiss::noise! {
//!     /// Mutual authentication; neither side pre-knows the other's key.
//!     pub XX<X25519, ChaChaPoly, Blake2b> {
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
//! `XX` authenticates both parties, so each owns a key pair that
//! outlives the connection; nothing is shared in advance. Keep the
//! public halves — step 3 is where each side checks the other against
//! one.
//!
//! ```rust
//! # use hiss::noise::{Blake2b, ChaChaPoly, X25519};
//! # hiss::noise! {
//! #     pub XX<X25519, ChaChaPoly, Blake2b> {
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
//! let alice_pub = alice_keys.public(&alice_static)?;
//!
//! let mut bob_keys = EphemeralOnly::new(rand::rng());
//! let bob_static = bob_keys.generate::<X25519>()?;
//! let bob_pub = bob_keys.public(&bob_static)?;
//! # let _ = (&alice_static, &bob_static, &alice_keys, &bob_keys);
//! # let _ = (&alice_pub, &bob_pub);
//! # Ok(())
//! # }
//! ```
//!
//! ### 3. Run the handshake — and decide whether to trust the peer
//!
//! Each call hands you the bytes to send; moving them — socket, queue,
//! QR code — is yours, because `hiss` does no I/O.
//!
//! Completing `XX` proves the peer holds *a* static private key, never
//! that it is one you trust. `read_message_N_with` is where that
//! decision goes: the closure sees the peer's key as it decrypts, and an
//! `Err` aborts before any [`Transport`](noise::Transport) exists. Leave
//! it out and you have an encrypted channel to a stranger.
//!
//! The *prologue* is any context both sides already agree on — a protocol
//! version, a channel name — mixed into the handshake so a mismatch fails
//! it; pass `&[]` if you have none.
//!
//! ```rust
//! # use hiss::noise::{Blake2b, ChaChaPoly, X25519};
//! # hiss::noise! {
//! #     pub XX<X25519, ChaChaPoly, Blake2b> {
//! #         -> e
//! #         <- e, ee, s, es
//! #         -> s, se
//! #     }
//! # }
//! # use hiss::provider::{EphemeralOnly, ProviderExt};
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # let mut alice_keys = EphemeralOnly::new(rand::rng());
//! # let alice_static = alice_keys.generate::<X25519>()?;
//! # let alice_pub = alice_keys.public(&alice_static)?;
//! # let mut bob_keys = EphemeralOnly::new(rand::rng());
//! # let bob_static = bob_keys.generate::<X25519>()?;
//! # let bob_pub = bob_keys.public(&bob_static)?;
//! use hiss::noise::HandshakeError;
//!
//! const PROLOGUE: &[u8] = b"prologue";
//!
//! // Your trust policy: a pin, an enrolment record, an allow-list. Here, the key we expect.
//! let accept = |ok: bool| match ok {
//!     true => Ok(()),
//!     false => Err(HandshakeError::PeerRejected {
//!         reason: "unknown peer".into(),
//!     }),
//! };
//!
//! let (msg1, alice) = XX::initiator(alice_keys, PROLOGUE).write_message_1()?;
//! let bob = XX::responder(bob_keys, PROLOGUE).read_message_1(&msg1)?;
//! let (msg2, bob) = bob.write_message_2(bob_static)?;
//! let alice = alice.read_message_2_with(&msg2, |peer| accept(peer == &bob_pub))?;
//! let (msg3, mut alice) = alice.write_message_3(alice_static)?;
//! let mut bob = bob.read_message_3_with(&msg3, |peer| accept(peer == &alice_pub))?;
//! # let _ = (&mut alice, &mut bob, &msg3);
//! # Ok(())
//! # }
//! ```
//!
//! ### 4. Talk
//!
//! Both ends now hold a `Transport`. `OVERHEAD` is what the authentication
//! tag costs you per message: give `send` a buffer of
//! `plaintext.len() + OVERHEAD`, and `receive` one that fits the plaintext.
//! `b"ping"` is 4 bytes, so 4 is the size below. One record carries at most
//! 65519 bytes of plaintext — chunk anything larger yourself.
//!
//! ```rust
//! # use hiss::noise::{Blake2b, ChaChaPoly, X25519};
//! # hiss::noise! {
//! #     pub XX<X25519, ChaChaPoly, Blake2b> {
//! #         -> e
//! #         <- e, ee, s, es
//! #         -> s, se
//! #     }
//! # }
//! # use hiss::provider::{EphemeralOnly, ProviderExt};
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # use hiss::noise::HandshakeError;
//! # let mut alice_keys = EphemeralOnly::new(rand::rng());
//! # let alice_static = alice_keys.generate::<X25519>()?;
//! # let alice_pub = alice_keys.public(&alice_static)?;
//! # let mut bob_keys = EphemeralOnly::new(rand::rng());
//! # let bob_static = bob_keys.generate::<X25519>()?;
//! # let bob_pub = bob_keys.public(&bob_static)?;
//! # let accept = |ok: bool| if ok { Ok(()) } else {
//! #     Err(HandshakeError::PeerRejected { reason: "unknown peer".into() })
//! # };
//! # const PROLOGUE: &[u8] = b"prologue";
//! # let (msg1, alice) = XX::initiator(alice_keys, PROLOGUE).write_message_1()?;
//! # let bob = XX::responder(bob_keys, PROLOGUE).read_message_1(&msg1)?;
//! # let (msg2, bob) = bob.write_message_2(bob_static)?;
//! # let alice = alice.read_message_2_with(&msg2, |peer| accept(peer == &bob_pub))?;
//! # let (msg3, mut alice) = alice.write_message_3(alice_static)?;
//! # let mut bob = bob.read_message_3_with(&msg3, |peer| accept(peer == &alice_pub))?;
//! use hiss::noise::Transport;
//!
//! let mut wire = [0u8; 4 + Transport::<XX>::OVERHEAD];
//! let mut got = [0u8; 4];
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
//! **There is no default suite.** [`Noise<P, Cu, Ci, H>`](noise::Noise)
//! declares no default type parameters, and a [`noise!`](crate::noise!)
//! declaration that omits `<Curve, Cipher, Hash>` is not a shorthand for
//! one — it is *marker mode*, which generates the pattern marker alone,
//! with no state machine and no wire-size constants. Every usable
//! declaration names all three.
//!
//! Both of the specification's ciphers ship. [`ChaChaPoly`](noise::ChaChaPoly)
//! is what the Quickstart uses and what every frozen P-256 vector was
//! generated over; [`AesGcm`](noise::AesGcm) (§12.4) is pinned by the same
//! third-party `cacophony` corpus over `25519` and `448`, and is over five
//! times as fast on Apple Silicon, where `cryptoxide` reaches the ARMv8 AES
//! and `pmull` instructions — on every other target its AES-GCM is portable
//! software, and `ChaChaPoly` stays the performance default. The speed has a
//! price in space: [`Cipher`](noise::Cipher) holds each cipher's *expanded*
//! key, so an AES-GCM `CipherState` is 528 bytes on `aarch64` (992 on the
//! portable path) where a `ChaChaPoly` one is 48. For
//! the curve, reach for [`X25519`](noise::X25519) — what the Quickstart
//! uses — unless you need the Apple Secure Enclave, which speaks
//! [`P256`](noise::P256) and nothing else, or want [`X448`](noise::X448)'s
//! larger margin. All four of the Noise specification's official hashes
//! ship: [`Blake2b`](noise::Blake2b) and [`Sha512`](noise::Sha512) at
//! HASHLEN 64, [`Sha256`](noise::Sha256) and [`Blake2s`](noise::Blake2s)
//! at HASHLEN 32. **Use `Blake2b`** — it is what the Quickstart, the
//! examples and the crate's own sealed-message helper use, and the only
//! hash carrying the full seventeen-pattern frozen P-256 matrix. Pick another
//! when a peer requires it. Every one of the four is pinned as a primitive
//! against the relevant standard, and as a Noise suite by frozen
//! third-party (`cacophony`)
//! known-answer vectors over `25519` and `448` across all seventeen patterns.
//! If you use `X448`, prefer a 512-bit hash with it (`Blake2b` or
//! `Sha512`), per the specification's §13 guidance.
//!
//! Seventeen patterns are provided as markers in
//! [`noise::pattern`] — **all fifteen** of Noise's fundamental patterns plus
//! two PSK variants. Each is combined with a suite
//! through [`Noise<P, Cu, Ci, H>`](noise::Noise):
//! [`N`](noise::pattern::N), [`K`](noise::pattern::K),
//! [`Kpsk0`](noise::pattern::Kpsk0), [`IKpsk1`](noise::pattern::IKpsk1),
//! [`IK`](noise::pattern::IK), [`NK`](noise::pattern::NK),
//! [`IX`](noise::pattern::IX), [`XK`](noise::pattern::XK),
//! [`NN`](noise::pattern::NN), [`XX`](noise::pattern::XX),
//! [`X`](noise::pattern::X), [`NX`](noise::pattern::NX),
//! [`XN`](noise::pattern::XN), [`KN`](noise::pattern::KN),
//! [`KK`](noise::pattern::KK), [`KX`](noise::pattern::KX), and
//! [`IN`](noise::pattern::IN). One caveat is worth carrying up here:
//! [`IN`](noise::pattern::IN) transmits the **initiator's static key in the
//! clear**, in msg1 before any DH — the only pattern that ships here where a
//! passive observer learns the initiator's identity outright. In Noise's own
//! naming the two curves above
//! are `25519` and `448`; Ed25519 is reserved for identity and signing
//! rather than the handshake — it does not implement
//! [`DhCurve`](curve::DhCurve) at all, so naming it as a suite's curve is
//! a compile error rather than a protocol name no registry knows.
//!
//! # Providers
//!
//! A *provider* is where your private keys live and what performs the key
//! agreement — the handshake does no cryptography of its own. You
//! construct one and hand it to `initiator` / `responder`; it is the
//! `alice_keys` argument in the Quickstart. Two ship with the crate:
//!
//! * [`EphemeralOnly<R>`](provider::EphemeralOnly) — pure software over a
//!   caller-supplied CSPRNG `R`, via `eccoxide`/`cryptoxide`. Works
//!   everywhere, including WASM, and is what the Quickstart uses. The
//!   name means *no built-in persistence*, not "no long-term keys": it
//!   does generate the static key a mutual pattern authenticates you by.
//!   Storing that key between runs, and distributing the public halves
//!   your peers pin, are yours to do.
//! * `AppleSecureEnclave` (Apple platforms) — P-256 keys generated inside
//!   the Secure Enclave and never extractable; software Ed25519 over a
//!   hardware-sealed seed.
//!
//! A backend `hiss` has never heard of — an HSM, a cloud KMS, a key store
//! you already have — plugs in by implementing the provider traits,
//! without touching the Noise core:
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
//! Noise key-agrees **only via raw Diffie–Hellman**, so a backend can
//! carry the channel only if it will hand back the shared secret. One
//! that can sign but never expose a DH result fits the identity layer
//! instead.
//!
//! # Security posture
//!
//! These hold whatever provider you use:
//!
//! * Noise's 65535-byte message-length limit is enforced at the
//!   cipher-state chokepoint.
//! * Peer public keys are parsed and validated by `hiss` before a
//!   provider sees them; operations on attacker-supplied points return
//!   `Result` rather than panicking.
//! * Secret material is zeroised on drop (see [`zeroize`]) — pre-shared
//!   keys, shared secrets, cipher and symmetric state, and the datagram
//!   receive ratchet — and no provider is required to make its private
//!   key `Clone`.
//! * The Noise `25519` and `448` curves perform no low-order or
//!   contributory-key check — per the spec (and RFC 7748) a low-order
//!   peer key yields an all-zero secret rather than an error.
//!
//! Everything else — constant-time scalar multiplication, deterministic
//! signing, what happens to a private key — belongs to the backend that
//! computes it, and does not transfer between backends. See
//! [`provider`](provider#security-posture) for the per-provider posture.
//!
//! This crate has **not** been independently audited and is pre-1.0.
//!
//! # Feature flags
//!
//! There is one, and it only picks a backend for a primitive — no feature
//! turns any of this crate's API on or off.
//!
//! * `x25519-cryptoxide` (**default**) — back X25519's software DH with
//!   `cryptoxide`'s `x25519` (the faster backend). Build with
//!   `--no-default-features` to fall back to the `eccoxide` ladder; output
//!   is byte-for-byte identical, so this only changes which dependency
//!   carries the primitive.
//!
//! # Modules
//!
//! * **[`curve`]** — Elliptic-curve math and key/handle types: ECDH on
//!   NIST P-256 (secp256r1), X25519 and X448, signing on P-256 (ECDSA)
//!   and Ed25519, plus the [`Curve`](curve::Curve) trait tying them to the
//!   type-level protocol.
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
//! Plus one re-export, [`rand_core`] — the exact version whose
//! `CryptoRng` this crate's public bounds name, so a consumer can name it
//! too.
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

/// The [`rand_core`] version this crate compiled against, re-exported.
///
/// `hiss` names `rand_core`'s traits in its *public* bounds —
/// [`EphemeralOnly<R>`](provider::EphemeralOnly)'s provider impls,
/// [`Psk::generate`](psk::Psk::generate), and every
/// `*PrivateKey::generate` all take an `R: rand_core::CryptoRng`. Those
/// bounds are only satisfiable by an RNG from the *same* `rand_core`:
/// two major versions in one dependency graph are two unrelated traits,
/// with no bridging impl, and the mismatch surfaces as an unsatisfied
/// `CryptoRng` bound rather than as a version error.
///
/// Re-exporting it makes that version nameable — write
/// `hiss::rand_core::CryptoRng` in your own bounds and you cannot pick
/// the wrong one. It also tells a consumer which `rand` to reach for
/// without reading `hiss`'s manifest: `rand_core` 0.10 is what
/// `rand = "0.10"` carries.
pub use rand_core;

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
///
/// # Example: an `IKpsk1` ceremony, both roles
///
/// The whole generated API in one program: the two constructors, one
/// method per handshake message, and the identity hook where the hub
/// decides whether it knows the device that just named itself. Only the
/// sockets are missing — `msg1` and `msg2` are the bytes you would put on
/// the wire. `read_message_1_with` is IKpsk1's signature move: the `s`
/// token reveals the device *before* the `psk` token needs a key, so the
/// PSK parameter becomes a lookup over the identity just revealed, and an
/// `Err` from it aborts before any `Transport` exists.
///
/// ```rust
/// use hiss::noise::{Blake2b, ChaChaPoly, HandshakeError, Transport, X25519};
/// use hiss::provider::{EphemeralOnly, ProviderExt};
/// use hiss::psk::Psk;
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
/// const PROLOGUE: &[u8] = b"ceremony v1";
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// // Enrolment, done out of band: the device holds the hub's static public
/// // key and a PSK the hub can find again from the device's identity.
/// let mut hub_keys = EphemeralOnly::new(rand::rng());
/// let hub_static = hub_keys.generate::<X25519>()?;
/// let hub_public = hub_keys.public(&hub_static)?;
/// let mut device_keys = EphemeralOnly::new(rand::rng());
/// let device_static = device_keys.generate::<X25519>()?;
/// let device_public = device_keys.public(&device_static)?;
/// let psk = Psk::generate(rand::rng());
/// let enrolment = [(device_public, psk.clone())];
///
/// // The device — initiator. It knows `hub_public` up front (`<- s`).
/// let device = IKpsk1::initiator(device_keys, PROLOGUE, hub_public);
/// let (msg1, device) = device.write_message_1(device_static, &psk)?;
///
/// // The hub — responder. The closure runs the moment msg1's `s` token
/// // decrypts, and picks the PSK for that device (or refuses it).
/// let hub = IKpsk1::responder(hub_keys, PROLOGUE, hub_static)?;
/// let hub = hub.read_message_1_with(&msg1, |device| {
///     enrolment
///         .iter()
///         .find(|(enrolled, _)| enrolled == device)
///         .map(|(_, psk)| psk.clone())
///         .ok_or_else(|| HandshakeError::PeerRejected {
///             reason: "device not enrolled".into(),
///         })
/// })?;
/// assert_eq!(hub.remote_static(), &device_public);
///
/// // Last message: both sides come out holding a `Transport`.
/// let (msg2, mut hub) = hub.write_message_2()?;
/// let mut device = device.read_message_2(&msg2)?;
///
/// let mut wire = [0u8; 5 + Transport::<IKpsk1>::OVERHEAD];
/// let mut got = [0u8; 5];
/// let n = device.send(b"hello", &mut wire)?;
/// let m = hub.receive(&wire[..n], &mut got)?;
/// assert_eq!(&got[..m], b"hello");
/// # Ok(())
/// # }
/// ```
pub use hiss_macros::noise;
