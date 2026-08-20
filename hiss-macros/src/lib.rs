//! Proc-macro companion to the [`hiss`](https://docs.rs/hiss) crate.
//!
//! This crate provides exactly one macro, [`noise!`](macro@noise): it
//! takes a Noise handshake pattern written in the notation of the
//! [Noise specification](https://noiseprotocol.org/noise.html) and a
//! concrete suite, and generates a pair of documented, sans-io,
//! type-state handshake state machines for it.
//!
//! Use it through the `hiss` crate, which re-exports it as `hiss::noise!`
//! — the generated code references `::hiss` paths
//! and needs that crate in scope.

mod codegen;
mod parse;

use proc_macro::TokenStream;
use syn::parse_macro_input;

/// Generate a sans-io Noise handshake from its pattern, written in the
/// notation of the Noise specification.
///
/// # Syntax
///
/// ```text
/// noise! {
///     /// Doc comments become the docs of the generated pattern type.
///     pub IKpsk1<X25519, ChaChaPoly, Blake2b> {
///         <- s
///         ...
///         -> e, es, s, ss, psk
///         <- e, ee, se
///     }
/// }
/// ```
///
/// The three angle-bracketed types are the suite — the DH curve, AEAD
/// cipher, and hash, e.g. `hiss::noise::{X25519, ChaChaPoly, Blake2b}`.
/// They must be concrete: that is what lets every handshake message be
/// a fixed-size `[u8; N]` computed at compile time. Lines before `...`
/// are pre-messages (keys known before the handshake); lines after it
/// are the handshake messages. A pattern with no pre-messages (`NN`,
/// `XX`, …) simply omits the `...`.
///
/// A handshake message line may end with a bracketed byte length —
/// `-> e, es, s, ss [12]` — declaring a fixed-size **application
/// payload** carried in that message's tail (Noise sanctions a payload
/// on every handshake message; the suffix is this DSL's one extension
/// to the specification's notation, whose tables leave payloads
/// implicit).
///
/// # What is generated
///
/// For a pattern named `P` the macro emits, at the invocation site:
///
/// * `struct P` — the pattern marker, implementing `hiss`'s `Pattern`
///   and `Protocol` traits, with `P::MSG1_SIZE`, `P::MSG2_SIZE`, …
///   consts giving the exact wire size of every handshake message;
/// * one constructor per role — `P::initiator(provider, prologue, …)` /
///   `P::responder(provider, prologue, …)`, whose extra parameters are
///   exactly the pre-message keys the pattern requires of that role —
///   and then **one method per handshake message**
///   (`write_message_1`, `read_message_2`, …), each taking exactly the
///   key material its tokens consume. One state type per message per
///   role, generic only over the crypto provider; calling messages out
///   of order is a compile error. Keys the handshake has established —
///   the ephemerals, the peer's revealed static identity — are
///   observable through accessors (`remote_static()`, …) generated
///   only on the states where the key is guaranteed present;
/// * a compile-time assertion of `hiss`'s `WellFormed` guard, so a
///   pattern violating Noise §7.3 (a DH over a key not yet transmitted,
///   a re-sent key, a never-keyed cipher) fails to build.
///
/// The generated states perform **no I/O**: `write_message_N` returns
/// the finished message as a `[u8; P::MSGn_SIZE]`, and `read_message_N`
/// borrows the incoming `&[u8; P::MSGn_SIZE]` for the duration of the
/// call. Framing and transporting the messages is the caller's job.
///
/// For a message declared with a `[N]` payload suffix, the writer takes
/// `payload: &[u8; N]` as its last parameter (the payload is the tail)
/// and the reader returns the recovered `[u8; N]` by value alongside
/// the next state; `MSGn_SIZE` grows by exactly `N`. Whether the
/// payload is encrypted is **positional** — it depends on whether the
/// cipher is keyed when that message's tail closes — and the generated
/// method docs state the concrete property ("encrypted to …" vs
/// "travels in the clear") per message.
///
/// PSKs are plain `&Psk` parameters. When a *received* message reveals
/// the peer's static (`s`) before its `psk` token — IKpsk1's signature
/// move — an additional `read_message_N_with` variant is generated
/// whose PSK parameter is a lookup closure over the just-revealed
/// identity, for deployments that select a per-peer PSK (or reject
/// unknown peers) at exactly that point.
///
/// Every other *received* message that reveals the peer's static gets a
/// `read_message_N_with` variant whose closure receives the
/// just-revealed identity and returns `Ok(())` to accept the peer, or
/// an error (e.g. `HandshakeError::PeerRejected`) to abort. The closure
/// fires as soon as the static is decrypted, **before** the message's
/// remaining DH tokens are computed: on the final message a role
/// receives (XX's, X's, or IX's last) that is the last moment before
/// the handshake completes into a `Transport`; on an earlier message
/// (IK's first) it rejects an unwanted peer before spending further
/// provider work. (A read with a PSK lookup keeps that form instead:
/// the lookup closure is already the identity hook.)
///
/// # Example
///
/// The worked example — an `IKpsk1` ceremony, both roles in one program,
/// the PSK lookup keyed on the identity msg1 reveals, and the transports
/// that come out of it — is a doctest that compiles and runs. It hangs
/// off `hiss`'s re-export of this macro, [`hiss::noise!`], and so sits
/// further up that page.
///
/// It is there rather than here because a doctest can only exercise
/// generated code where the runtime types are, and this crate cannot
/// depend on `hiss` — `hiss` depends on this one. Two runnable programs
/// in the repository cover the same ground: `examples/quickstart.rs`
/// (`XX`, both roles in one process) and
/// `examples/tcp_ikpsk1_ceremony.rs` (this pattern, over a socket).
///
/// Each type this macro generates also carries its own walkthrough: a
/// `# Usage` section, per role, written against that pattern's messages
/// — and likewise a doctest that compiles, provided the suite is
/// written as `hiss::noise`'s own type names (`X25519`, `X448`, `P256`,
/// `ChaChaPoly`, `AesGcm`, `Blake2b`, `Blake2s`, `Sha256`, `Sha512`) or
/// as paths starting `hiss::`. Any other spelling still gets the
/// walkthrough, as an uncompiled sketch.
///
/// [`hiss::noise!`]: https://docs.rs/hiss/latest/hiss/macro.noise.html
#[proc_macro]
pub fn noise(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as parse::NoiseInput);
    codegen::expand(&input).into()
}
