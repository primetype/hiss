# hiss

**Static Noise.** The [Noise Protocol Framework][noise], resolved at compile time.

A `Noise<Pattern, Curve, Cipher, Hash>` is zero-sized: the handshake pattern, curve,
cipher, and hash are encoded as *types*, so every buffer size is a `const` and every
protocol misuse — a token out of order, a wrong-direction message — is a **compile
error**. Get the handshake wrong and it never builds.

Secret keys live in software or behind a pluggable, hardware-backed provider (Apple
Secure Enclave today), and are wiped on drop.

> **Status: pre-release (`0.1`), not yet published.** The API is unstable and the code
> has **not** been independently audited. See [Security](#security) before relying on it.

[noise]: https://noiseprotocol.org/

## What it offers

- **Compile-time protocol selection.** The pattern, curve, cipher, and hash are
  zero-sized type parameters; message sizes are associated constants. Misuse is rejected
  by the type system rather than at runtime.
- **A small, deliberate crypto core.** Production cryptography is `cryptoxide` +
  `eccoxide` only — no sprawling dependency surface.
- **Pluggable crypto providers.** A trait family — `CryptoKeyProvider<C>` (keygen) at the
  base, with `DhProvider<C>` adding the ECDH the handshake actually consumes and
  `SigningProvider` for identity signing, each paired with an `…Async` refinement — lets
  the same handshake run against a software backend or a hardware-backed one (Apple Secure
  Enclave). See [Providers](#providers).
- **Two streaming drivers.** A blocking `std::io` driver (`SyncHandshake`, always
  available) and an optional `tokio::io` driver (`AsyncHandshake`, behind the `async-io`
  feature). The buffer / no-syscall / one-shot case is simply passing an in-memory `Io` —
  a `Cursor`, `Vec`, or `&mut [u8]` — to the synchronous driver; there is no separate
  buffer API.

## Supported suite

This `0.1` targets one cipher suite and a fixed set of patterns:

| Axis    | Supported |
|---------|-----------|
| Patterns | `N`, `K`, `Kpsk0`, `IKpsk1`, `IK`, `NK`, `IX`, `XK`, `NN`, `XX` |
| Curves  | NIST **P-256** (secp256r1) and **X25519** (Curve25519, the Noise `25519` curve) |
| Cipher  | **ChaCha20-Poly1305** |
| Hash    | **BLAKE2b** |

Conformance is anchored against [`snow`](https://crates.io/crates/snow) via an interop
test suite. All ten fundamental patterns are present; additional hashes and ciphers
(AES-GCM) are planned for `0.2+`.

The `fallback` modifier — and the compound protocols it enables (e.g. Noise Pipes /
0-RTT-with-retry) — is an **intentional non-goal**, not a missing feature. It is optional
in the Noise spec, which presents it only as an illustrative building block, and is
unnecessary for the targeted use cases; `snow` omits it for the same reason.

## Quickstart

The `N` pattern lets an initiator seal a message to a recipient's known static public
key. The streaming `SyncHandshake` driver owns any `std::io::Read`/`Write` (a TCP
socket, an in-memory buffer, …) and advances the handshake over it.

```rust
use hiss::provider::{EphemeralOnly, ProviderExt};
use hiss::noise::{Blake2b, ChaChaPoly, Initiator, Noise, P256, Responder, SyncHandshake, pattern};

// Spell out the protocol once as a type alias. (The ready-made
// `noise::N` alias is exactly this; here we name the suite in full.)
type Seal = Noise<pattern::N, P256, ChaChaPoly, Blake2b>;

// Each party owns a software provider holding its own CSPRNG — `rand::rng()`
// here; pass a seeded RNG instead for deterministic tests. The recipient's
// static P-256 key has its public half known to the sender.
let mut provider = EphemeralOnly::new(rand::rng());
let recipient_static = provider.generate::<P256>()?;
let recipient_pub = provider.public(&recipient_static)?;

// ── Initiator: run the handshake, then seal a payload ───────────────────────
let handshake = SyncHandshake::<Seal, Initiator, _, _, _, _>::initiate(
    EphemeralOnly::new(rand::rng()),
    &[],                 // prologue
    Vec::<u8>::new(),    // writer: anything implementing std::io::Write
)
.set_rs(recipient_pub);

let (mut sender, wire) = handshake.e()?.es()?.into_parts();

let payload = b"attack at dawn!!";
let mut sealed = [0u8; 32]; // 16-byte payload + 16-byte AEAD tag
let n = sender.send(payload, &mut sealed)?;

// ── Responder: read the handshake, then open the payload ────────────────────
let handshake = SyncHandshake::<Seal, Responder, _, _, _, _>::respond(
    provider,                             // the recipient drives the responder side
    &[],                                  // prologue (must match)
    std::io::Cursor::new(wire),           // reader: anything implementing std::io::Read
)
.set_s(recipient_static)?;

let (_revealed_ephemeral, recv) = handshake.recv().e()?;
let mut transport = recv.es()?;

// Both ends derived the same session.
assert_eq!(sender.session_id(), transport.transport().session_id());

let mut opened = [0u8; 16];
transport.transport().receive(&sealed[..n], &mut opened)?;
assert_eq!(&opened, payload);
# Ok::<(), Box<dyn std::error::Error>>(())
```

The buffer / no-syscall case is just an in-memory `Io` (a `Cursor`, `Vec`, or
`&mut [u8]`), as the example above shows; with the `async-io` feature the same chain runs
over `tokio::io` via `AsyncHandshake`. The mutual-authentication patterns (`K`, `Kpsk0`, `IKpsk1`, `IK`) follow the
same builder shape with additional pre-message setters; `NK` is interactive and
responder-authenticated (the initiator is anonymous) and likewise pre-knows the
responder's static key via `set_rs`. `XK` is a three-message, mutually-authenticated
handshake with strong initiator-identity privacy: it pre-knows the responder's static
via `set_rs`/`set_s` like `IK`, but defers the initiator's own static to an
encrypted third flight, so the initiator's identity is hidden from a passive
eavesdropper. `IX` is interactive and mutually authenticated
but has **no pre-message setters** — neither side pre-knows the other's static; both
transmit their static keys during the handshake as `s` tokens (the initiator's in the
clear, the responder's encrypted). `NN` is the **unauthenticated** interactive pattern:
both parties are anonymous (no static keys, no pre-message setters), so it offers
confidentiality only against a passive eavesdropper — there is no protection against an
active man-in-the-middle — with full forward secrecy once the ephemerals are mixed.
`XX` is the **canonical** three-message, mutually-authenticated pattern: like `IX` it has
**no pre-message setters** — neither side pre-knows the other's static — but unlike `IX`
**both** statics are transmitted *encrypted* during the handshake (after `ee` keys the
cipher), so **both identities are hidden from a passive eavesdropper**. Both parties send
their static keys via `s` tokens; full forward secrecy follows the `ee` DH.

## Providers

Standard Noise authenticates and key-agrees **only via raw ECDH** — there is no signature
token in the handshake. A backend can therefore serve the Noise **DH (key-agreement)**
role only if it can yield a value Noise can mix (the raw shared secret, or the result of
Noise's exact HKDF over it). Backends that can only *sign* fit a separate
identity/attestation layer **around** the channel, not inside it.

| Backend | DH (Noise channel) | Identity / signing | Status |
|---------|:------------------:|:------------------:|--------|
| Software (`eccoxide`)        | ✅ | ✅ | **implemented** |
| Apple Secure Enclave (macOS/iOS) | ✅ | ✅ | **implemented** |
| Android Keystore / StrongBox | ✅ | ✅ | planned (`0.2+`) |
| Linux TPM2                   | ✅ (policy-permitting) | ✅ | planned (`0.2+`) |
| AWS KMS                      | ✅ (`DeriveSharedSecret`) | ✅ | planned (`0.2+`) |
| Windows CNG / Azure / GCP KMS | ❌ (no raw ECDH) | ✅ | identity role only |
| PKCS#11 HSM, YubiKey, Ledger | ❌ (no raw ECDH export) | — | out of scope |

A DH-capable backend is selected through the `DhProvider` / `DhProviderAsync` traits
(both refining the `CryptoKeyProvider` keygen base), so additional backends can be added
without touching the Noise core.

## Platforms

- **All platforms:** the software backend (`EphemeralOnly`) and the blocking
  `std::io` handshake driver.
- **macOS / iOS:** the Apple Secure Enclave backend. Its blocking Security-framework calls
  are offloaded to a Tokio blocking thread pool for the async provider path.

## Cargo features

| Feature | Default | Effect |
|---------|:-------:|--------|
| `async-io` | no | Adds the `tokio::io` streaming handshake driver (`AsyncHandshake`), pulling in `tokio` with its I/O extension traits. The blocking `std::io` driver needs no feature and no runtime. |

## Security

**This crate has not been independently audited and is pre-1.0. Do not use it to protect
anything you cannot afford to lose.** That said, the crypto core is built to be
responsible:

- **Constant-time P-256 scalar multiplication** via `eccoxide`'s constant-time backend.
- **Deterministic ECDSA** (RFC 6979) with low-S normalization; no signing RNG.
- **Peer-key and DH-output validation** — operations on attacker-supplied points return
  `Result` rather than panicking; a degenerate (point-at-infinity) shared secret is
  rejected.
- **Noise's 65535-byte message-length limit** is enforced at the cipher-state chokepoint.
- **Secret material is zeroized on drop** and is never required to be `Clone`.

> **Note for would-be packagers:** the constant-time P-256 support currently pins
> `eccoxide` to a specific git revision. A crates.io release of `eccoxide` carrying that
> fix is required before `hiss` can itself be published.

Please report security issues privately to the maintainers rather than opening a public
issue.

## Minimum supported Rust version

`hiss` uses the Rust 2024 edition and declares an MSRV of **1.85**. The MSRV is not yet
enforced in CI.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for
inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed
as above, without any additional terms or conditions.
