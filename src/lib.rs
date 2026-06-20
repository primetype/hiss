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
//! # Suite and breadth
//!
//! The default suite is **P-256 / ChaCha20-Poly1305 / BLAKE2b** —
//! [`P256`](noise::P256), [`ChaChaPoly`](noise::ChaChaPoly), and
//! [`Blake2b`](noise::Blake2b). Ten fundamental patterns are provided,
//! reached as `noise::N`, `noise::IKpsk1`, and so on:
//! [`N`](noise::N), [`K`](noise::K), [`Kpsk0`](noise::Kpsk0),
//! [`IKpsk1`](noise::IKpsk1), [`IK`](noise::IK), [`NK`](noise::NK),
//! [`IX`](noise::IX), [`XK`](noise::XK), [`NN`](noise::NN), and
//! [`XX`](noise::XX). Two Diffie-Hellman curves are supported —
//! [`P256`](noise::P256) and [`X25519`](noise::X25519) (the Noise
//! `25519` curve) — with Ed25519 reserved for identity and signing.
//!
//! # Drivers
//!
//! A handshake is advanced over a transport by one of two drivers. Both
//! own the I/O object and step the handshake through its messages:
//!
//! * [`SyncHandshake`](noise::SyncHandshake) drives the handshake over a
//!   blocking [`std::io::Read`] + [`std::io::Write`]. Always available,
//!   no runtime required.
//! * `AsyncHandshake` (feature `async-io`) drives it over
//!   `tokio::io::AsyncRead` + `AsyncWrite`, yielding an
//!   `AsyncTransport` once the handshake completes.
//!
//! There is no separate sans-io or "buffer core" API. The
//! buffer / no-syscall case is simply an in-memory `Io` — a
//! [`std::io::Cursor`], a [`Vec`], or a `&mut [u8]` — handed to the
//! synchronous driver, as the [Quickstart](#quickstart) below shows.
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
//! * P-256 scalar multiplication is constant-time.
//! * P-256 ECDH rejects a degenerate (identity) shared secret rather
//!   than returning it; on the prime-order curve the identity is the
//!   only such point. The Noise `25519` curve performs no equivalent
//!   check — per the spec (and RFC 7748) a low-order peer key simply
//!   yields an all-zero secret rather than an error.
//!
//! This crate has **not** been independently audited and is pre-1.0.
//!
//! # Feature flags
//!
//! * `async-io` — adds the `tokio::io` driver (`AsyncHandshake` /
//!   `AsyncTransport`). The synchronous driver needs no feature.
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
//! * **[`noise`]** — Compile-time Noise protocol descriptor. Encodes
//!   the handshake pattern, curve, cipher, and hash as zero-sized
//!   types so all buffer sizes and operations are known at
//!   monomorphisation time.
//!
//! * **[`psk`]** — Pre-shared keys for the `*psk*` patterns
//!   ([`Kpsk0`](noise::Kpsk0), [`IKpsk1`](noise::IKpsk1)): a
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
//! # Quickstart
//!
//! The [`N`](noise::N) pattern lets an initiator seal a message to a
//! recipient's known static public key. The streaming
//! [`SyncHandshake`](noise::SyncHandshake) driver owns any
//! [`std::io::Read`]/[`std::io::Write`] (a TCP socket, an in-memory
//! buffer, …) and advances the handshake over it.
//!
//! ```rust
//! use hiss::provider::{EphemeralOnly, ProviderExt};
//! use hiss::noise::{Blake2b, ChaChaPoly, Initiator, Noise, P256, Responder, SyncHandshake, pattern};
//!
//! // Spell out the protocol once as a type alias. (The ready-made
//! // `noise::N` alias is exactly this; here we name the suite in full.)
//! type Seal = Noise<pattern::N, P256, ChaChaPoly, Blake2b>;
//!
//! // Each party owns a software provider holding its own CSPRNG — `rand::rng()`
//! // here; pass a seeded RNG instead for deterministic tests. The recipient's
//! // static P-256 key has its public half known to the sender.
//! let mut provider = EphemeralOnly::new(rand::rng());
//! let recipient_static = provider.generate::<P256>()?;
//! let recipient_pub = provider.public(&recipient_static)?;
//!
//! // ── Initiator: run the handshake, then seal a payload ───────────────────────
//! let handshake = SyncHandshake::<Seal, Initiator, _, _, _, _>::initiate(
//!     EphemeralOnly::new(rand::rng()),
//!     &[],                 // prologue
//!     Vec::<u8>::new(),    // writer: anything implementing std::io::Write
//! )
//! .set_rs(recipient_pub);
//!
//! let (mut sender, wire) = handshake.e()?.es()?.into_parts();
//!
//! let payload = b"attack at dawn!!";
//! let mut sealed = [0u8; 32]; // 16-byte payload + 16-byte AEAD tag
//! let n = sender.send(payload, &mut sealed)?;
//!
//! // ── Responder: read the handshake, then open the payload ────────────────────
//! let handshake = SyncHandshake::<Seal, Responder, _, _, _, _>::respond(
//!     provider,                             // the recipient drives the responder side
//!     &[],                                  // prologue (must match)
//!     std::io::Cursor::new(wire),           // reader: anything implementing std::io::Read
//! )
//! .set_s(recipient_static)?;
//!
//! let (_revealed_ephemeral, recv) = handshake.recv().e()?;
//! let mut transport = recv.es()?;
//!
//! // Both ends derived the same session.
//! assert_eq!(sender.session_id(), transport.transport().session_id());
//!
//! let mut opened = [0u8; 16];
//! transport.transport().receive(&sealed[..n], &mut opened)?;
//! assert_eq!(&opened, payload);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![warn(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]

#[cfg(any(target_os = "macos", target_os = "ios", test))]
mod asn1;
pub mod curve;
pub mod noise;
pub mod provider;
pub mod psk;
pub mod zeroize;
