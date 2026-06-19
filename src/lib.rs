//! `hiss` — the Noise Protocol Framework, resolved at compile time.
//!
//! A `Noise<Pattern, Curve, Cipher, Hash>` is zero-sized: the handshake
//! pattern, curve, cipher, and hash are encoded as types, so every
//! buffer size is a `const` and every protocol misuse — a token out of
//! order, a wrong-direction message — is a *compile error*. Get the
//! handshake wrong and it never builds.
//!
//! Secret keys live in software or behind a pluggable, hardware-backed
//! provider (Apple Secure Enclave today), and are wiped on drop. The
//! crate provides the building blocks for an authenticated, encrypted
//! transport:
//!
//! * **[`curve`]** — Elliptic-curve math and key/handle types: ECDSA
//!   signing and ECDH on NIST P-256 (secp256r1) and Ed25519, plus the
//!   [`Curve`](curve::Curve) trait tying them to the type-level protocol.
//!
//! * **[`provider`]** — the backends that *perform* a curve's
//!   operations: [`EphemeralOnly`](provider::EphemeralOnly) (pure
//!   software, via `eccoxide`/`cryptoxide`) and, on Apple platforms,
//!   [`AppleSecureEnclave`](provider::AppleSecureEnclave) (P-256 in the
//!   Secure Enclave; software Ed25519 with a hardware-sealed seed).
//!
//! * **[`noise`]** — Compile-time Noise protocol descriptor. Encodes
//!   the handshake pattern, curve, cipher, and hash as zero-sized
//!   types so all buffer sizes and operations are known at
//!   monomorphisation time.
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

#[cfg(any(target_os = "macos", target_os = "ios", test))]
mod asn1;
pub mod curve;
pub mod noise;
pub mod provider;
pub mod psk;
pub mod zeroize;
