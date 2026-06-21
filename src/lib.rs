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
//! [`Blake2b`](noise::Blake2b). Ten fundamental patterns are provided as
//! markers in [`noise::pattern`], each combined with a suite
//! through [`Noise<P, Cu, Ci, H>`](noise::Noise):
//! [`N`](noise::pattern::N), [`K`](noise::pattern::K),
//! [`Kpsk0`](noise::pattern::Kpsk0), [`IKpsk1`](noise::pattern::IKpsk1),
//! [`IK`](noise::pattern::IK), [`NK`](noise::pattern::NK),
//! [`IX`](noise::pattern::IX), [`XK`](noise::pattern::XK),
//! [`NN`](noise::pattern::NN), and [`XX`](noise::pattern::XX). Three
//! Diffie-Hellman curves are supported —
//! [`P256`](noise::P256), [`X25519`](noise::X25519) (the Noise `25519`
//! curve), and [`X448`](noise::X448) (the Noise `448` curve) — with
//! Ed25519 reserved for identity and signing.
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
//! # Quickstart — seal a message with the `N` pattern, step by step
//!
//! [`N`](noise::pattern::N) is a one-way, sender-anonymous seal: anyone who knows a
//! recipient's static public key can send it one confidential, authenticated
//! message, with no reply. The whole exchange is the single Noise message
//! `-> e, es`. We build it over [`X25519`](noise::X25519) in five steps —
//! each snippet is its own compiled doctest.
//!
//! ### 1. The recipient's static key pair
//!
//! `N` authenticates the recipient, so the recipient owns a long-term
//! *static* key pair and the sender must already know its public half (shared
//! out of band — a pinned constant, a QR code, a config entry).
//! [`X25519`](noise::X25519) is Diffie–Hellman over Curve25519 (RFC 7748),
//! the curve Noise calls `25519`. The private half stays in the provider;
//! only the 32-byte public half is shared.
//!
//! ```rust
//! use hiss::provider::{EphemeralOnly, ProviderExt};
//! use hiss::noise::X25519;
//!
//! // `EphemeralOnly` is the software backend; it wraps a CSPRNG.
//! let mut recipient = EphemeralOnly::new(rand::rng());
//!
//! let recipient_static = recipient.generate::<X25519>()?; // secret half — never shared
//! let recipient_pub = recipient.public(&recipient_static)?; // public half — the sender knows this
//! # let _ = (&recipient_static, &recipient_pub);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ### 2. The sender begins `N` and pins the recipient's static
//!
//! The sender drives the [`Initiator`](noise::Initiator) side. `N`'s
//! initiator is *anonymous* — it has no static key of its own — so the
//! recipient never learns who sent the message, only that the sender knew its
//! public key. `set_rs` ("remote static") supplies that known key; it is
//! `N`'s `<- s` pre-message.
//!
//! ```rust
//! # use hiss::provider::{EphemeralOnly, ProviderExt};
//! # use hiss::noise::X25519;
//! use hiss::noise::{Blake2b, ChaChaPoly, Initiator, Noise, SyncHandshake, pattern};
//! # let mut recipient = EphemeralOnly::new(rand::rng());
//! # let recipient_static = recipient.generate::<X25519>()?;
//! # let recipient_pub = recipient.public(&recipient_static)?;
//! // The full protocol name: Noise_N_25519_ChaChaPoly_BLAKE2b.
//! type NoiseN = Noise<pattern::N, X25519, ChaChaPoly, Blake2b>;
//!
//! let handshake = SyncHandshake::<NoiseN, Initiator, _, _, _, _>::initiate(
//!     EphemeralOnly::new(rand::rng()), // the sender's own RNG
//!     &[],                             // prologue: shared context, if any
//!     Vec::<u8>::new(),                // the sink the message bytes are written to
//! )
//! .set_rs(recipient_pub);
//! # let _ = (&handshake, &recipient, &recipient_static);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ### 3. Write the message (`-> e, es`) and seal the payload
//!
//! `N`'s one message is `-> e, es`. `e` generates a fresh ephemeral key and
//! writes its public half to the wire; `es` mixes
//! `DH(ephemeral, recipient-static)` into the cipher key. After `es` the
//! channel is keyed, so `into_parts` hands back the live `sender` and the
//! handshake message; the payload then rides in the first transport record.
//!
//! ```rust
//! # use hiss::provider::{EphemeralOnly, ProviderExt};
//! # use hiss::noise::{Blake2b, ChaChaPoly, Initiator, Noise, SyncHandshake, X25519, pattern};
//! # let mut recipient = EphemeralOnly::new(rand::rng());
//! # let recipient_static = recipient.generate::<X25519>()?;
//! # let recipient_pub = recipient.public(&recipient_static)?;
//! # type NoiseN = Noise<pattern::N, X25519, ChaChaPoly, Blake2b>;
//! # let handshake = SyncHandshake::<NoiseN, Initiator, _, _, _, _>::initiate(
//! #     EphemeralOnly::new(rand::rng()), &[], Vec::<u8>::new(),
//! # ).set_rs(recipient_pub);
//! let (mut sender, message) = handshake.e()?.es()?.into_parts();
//!
//! let quote = b"Not all those who wander are lost.";
//! let mut sealed = vec![0u8; quote.len() + 16]; // +16 for the AEAD tag
//! let n = sender.send(quote, &mut sealed)?;
//! # let _ = (&message, &n);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ### 4. The recipient receives the message
//!
//! The recipient drives the [`Responder`](noise::Responder) side with its
//! static *private* key (`set_s`) and replays the same tokens, recomputing
//! the identical `es` secret — so both ends arrive at the same key without
//! ever putting it on the wire.
//!
//! ```rust
//! # use hiss::provider::{EphemeralOnly, ProviderExt};
//! # use hiss::noise::{Blake2b, ChaChaPoly, Initiator, Noise, SyncHandshake, X25519, pattern};
//! use hiss::noise::Responder;
//! # let mut recipient = EphemeralOnly::new(rand::rng());
//! # let recipient_static = recipient.generate::<X25519>()?;
//! # let recipient_pub = recipient.public(&recipient_static)?;
//! # type NoiseN = Noise<pattern::N, X25519, ChaChaPoly, Blake2b>;
//! # let handshake = SyncHandshake::<NoiseN, Initiator, _, _, _, _>::initiate(
//! #     EphemeralOnly::new(rand::rng()), &[], Vec::<u8>::new(),
//! # ).set_rs(recipient_pub);
//! # let (mut sender, message) = handshake.e()?.es()?.into_parts();
//! let handshake = SyncHandshake::<NoiseN, Responder, _, _, _, _>::respond(
//!     recipient,                     // drives this side, holding the static key
//!     &[],                           // the same prologue
//!     std::io::Cursor::new(message), // read the sender's message
//! )
//! .set_s(recipient_static)?;
//!
//! let (_their_ephemeral, recv) = handshake.recv().e()?;
//! let mut transport = recv.es()?;
//! # let _ = (&sender, &mut transport);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ### 5. Decrypt
//!
//! Both ends now hold the same transport key, so the recipient opens the
//! sealed record. It is authenticated end to end: only someone who knew the
//! recipient's public key could have produced it.
//!
//! ```rust
//! # use hiss::provider::{EphemeralOnly, ProviderExt};
//! # use hiss::noise::{Blake2b, ChaChaPoly, Initiator, Noise, Responder, SyncHandshake, X25519, pattern};
//! # let mut recipient = EphemeralOnly::new(rand::rng());
//! # let recipient_static = recipient.generate::<X25519>()?;
//! # let recipient_pub = recipient.public(&recipient_static)?;
//! # type NoiseN = Noise<pattern::N, X25519, ChaChaPoly, Blake2b>;
//! # let handshake = SyncHandshake::<NoiseN, Initiator, _, _, _, _>::initiate(
//! #     EphemeralOnly::new(rand::rng()), &[], Vec::<u8>::new(),
//! # ).set_rs(recipient_pub);
//! # let (mut sender, message) = handshake.e()?.es()?.into_parts();
//! # let quote = b"Not all those who wander are lost.";
//! # let mut sealed = vec![0u8; quote.len() + 16];
//! # let n = sender.send(quote, &mut sealed)?;
//! # let handshake = SyncHandshake::<NoiseN, Responder, _, _, _, _>::respond(
//! #     recipient, &[], std::io::Cursor::new(message),
//! # ).set_s(recipient_static)?;
//! # let (_their_ephemeral, recv) = handshake.recv().e()?;
//! # let mut transport = recv.es()?;
//! let mut opened = vec![0u8; sealed.len()];
//! let m = transport.transport().receive(&sealed[..n], &mut opened)?;
//! opened.truncate(m);
//!
//! assert_eq!(&opened, quote); // "Not all those who wander are lost."
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
