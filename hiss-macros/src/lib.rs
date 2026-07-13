//! Proc-macro companion to the [`hiss`](https://docs.rs/hiss) crate.
//!
//! This crate provides exactly one macro, [`noise!`](macro@noise): it
//! takes a Noise handshake pattern written in the notation of the
//! [Noise specification](https://noiseprotocol.org/noise.html) and a
//! concrete suite, and generates a pair of documented, sans-io,
//! type-state handshake state machines for it.
//!
//! Use it through the `hiss` crate (feature `macros`), which re-exports
//! it as `hiss::noise!` — the generated code references `::hiss` paths
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
/// PSKs are plain `&Psk` parameters. When a *received* message reveals
/// the peer's static (`s`) before its `psk` token — IKpsk1's signature
/// move — an additional `read_message_N_with` variant is generated
/// whose PSK parameter is a lookup closure over the just-revealed
/// identity, for deployments that select a per-peer PSK (or reject
/// unknown peers) at exactly that point.
///
/// # Example
///
/// ```ignore
/// // initiator                                   // responder
/// let hs = IKpsk1::initiator(p, PROLOGUE, rs);   // let hs = IKpsk1::responder(p, PROLOGUE, s)?;
/// let (msg1, hs) =                               // let hs = hs.read_message_1(&msg1, &psk)?;
///     hs.write_message_1(static_key, &psk)?;     // // or: .read_message_1_with(&msg1, |id| lookup(id))?
///                                                // let device = hs.remote_static();
/// let transport = hs.read_message_2(&msg2)?;     // let (msg2, transport) = hs.write_message_2()?;
/// ```
#[proc_macro]
pub fn noise(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as parse::NoiseInput);
    codegen::expand(&input).into()
}
