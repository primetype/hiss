# hiss

**Encrypted, authenticated channels between two peers you control — with the handshake
checked by the compiler, and private keys that can stay in an Apple Secure Enclave.**

Built on the [Noise Protocol Framework][noise]. You write the handshake you want in
Noise's own notation; `hiss` generates the code for it, sizes every message at compile
time, and refuses to build a handshake that is malformed.

> **Status: `0.1` — unstable API, not independently audited.** See
> [How this is tested](#how-this-is-tested) and [Security](#security) before relying on
> it. Note that `0.1.0` on crates.io predates the `noise!` macro described below; this
> README documents the unreleased tree.

[noise]: https://noiseprotocol.org/

## Quickstart

Two peers authenticate each other and exchange an encrypted message in each direction,
neither knowing the other's key in advance. Four steps, each one a doctest that compiles
and runs. Assembled into a single program it is
[`examples/quickstart.rs`](examples/quickstart.rs) — `cargo run --example quickstart`.

**1. Describe the handshake you want.** You write it in the Noise specification's own
notation and `hiss` generates the code. This one is `XX`: three messages, both sides
proving who they are along the way. Name the type after its pattern — the name you write
goes on the wire as part of the protocol identity.

```rust
use hiss::noise::{Blake2b, ChaChaPoly, X25519};

hiss::noise! {
    /// Mutual authentication; neither side pre-knows the other's key.
    pub XX<X25519, ChaChaPoly, Blake2b> {
        -> e
        <- e, ee, s, es
        -> s, se
    }
}
```

**2. Give each side a long-term key.** `XX` authenticates both parties, so each owns
a key pair that outlives the connection. Nothing is shared in advance — they exchange
public halves during the handshake.

```rust
use hiss::provider::{EphemeralOnly, ProviderExt};

let mut alice_keys = EphemeralOnly::new(rand::rng());
let alice_static = alice_keys.generate::<X25519>()?;

let mut bob_keys = EphemeralOnly::new(rand::rng());
let bob_static = bob_keys.generate::<X25519>()?;
```

**3. Run the handshake.** Three messages, and this is all of it. Each call hands you the
bytes to send; putting them on a socket, a queue, or a QR code is your business — `hiss`
performs no I/O.

```rust
let (msg1, alice) = XX::initiator(alice_keys, &[]).write_message_1()?;
let bob = XX::responder(bob_keys, &[]).read_message_1(&msg1)?;
let (msg2, bob) = bob.write_message_2(bob_static)?;
let (msg3, mut alice) = alice.read_message_2(&msg2)?.write_message_3(alice_static)?;
let mut bob = bob.read_message_3(&msg3)?;
```

Every message size is a compile-time constant — `XX::MSG1_SIZE` and friends — so
framing the handshake is free: read exactly that many bytes.

**4. Talk.** Both ends now hold a `Transport`. `OVERHEAD` is what the authentication tag
costs you per message.

```rust
use hiss::noise::Transport;

let mut wire = [0u8; 32 + Transport::<XX>::OVERHEAD];
let mut got = [0u8; 32];

let n = alice.send(b"ping", &mut wire)?;
let m = bob.receive(&wire[..n], &mut got)?;
assert_eq!(&got[..m], b"ping");

let n = bob.send(b"pong", &mut wire)?;
let m = alice.receive(&wire[..n], &mut got)?;
assert_eq!(&got[..m], b"pong");
```

Putting those messages on a real socket — framing, a trust decision on the peer's key,
a PSK ceremony — is worked end to end in
[`examples/tcp_ikpsk1_ceremony.rs`](examples/tcp_ikpsk1_ceremony.rs).

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
- **You write the pattern; the macro writes the code.** `noise!` takes a handshake
  pattern in the Noise specification's own notation and generates its state machine —
  one method per message, every message a fixed-size `[u8; N]` known at compile time.
  It performs no I/O: it hands you bytes and you move them however you already move
  bytes.

## Supported suite

This `0.1` targets one cipher suite and a fixed set of patterns:

| Axis    | Supported |
|---------|-----------|
| Patterns | `N`, `K`, `Kpsk0`, `IKpsk1`, `IK`, `NK`, `IX`, `XK`, `NN`, `XX`, `X` |
| Curves  | NIST **P-256** (secp256r1), **X25519** (Curve25519, the Noise `25519` curve), and **X448** (the Noise `448` curve) |
| Cipher  | **ChaCha20-Poly1305** |
| Hash    | **BLAKE2b** |

Conformance is anchored against [`snow`](https://crates.io/crates/snow) via an interop
test suite. All eleven fundamental patterns are present; additional hashes and ciphers
(AES-GCM) are planned for `0.2+`.

The `fallback` modifier — and the compound protocols it enables (e.g. Noise Pipes /
0-RTT-with-retry) — is an **intentional non-goal**, not a missing feature. It is optional
in the Noise spec, which presents it only as an illustrative building block, and is
unnecessary for the targeted use cases; `snow` omits it for the same reason.

## Which pattern?

**If you are not sure, use `XX`** — the Quickstart's pattern. It needs nothing arranged in
advance, authenticates both sides, and hides both identities from anyone watching the
wire. Move off it only when a row below describes your situation better.

Both sides get confidentiality and forward secrecy in every pattern; what differs is who
proves their identity, and what has to be arranged beforehand.

**Interactive — both sides talk:**

| Pattern | Msgs | Whose identity is proven | Must be arranged in advance | Reach for it when |
|---------|:----:|--------------------------|-----------------------------|-------------------|
| **`XX`** | 3 | both | nothing | **The default.** Neither side pre-knows the other, and both identities stay hidden from a passive eavesdropper |
| `IK` | 2 | both | initiator knows the responder's public key | You already ship the server's key inside the client — fewest round trips for mutual authentication |
| `IKpsk1` | 2 | both, plus a shared secret | responder's public key **and** a pre-shared key | `IK` for devices enrolled in a ceremony that issued them a per-device secret |
| `XK` | 3 | both | initiator knows the responder's public key | Like `IK`, but the initiator's identity must stay hidden from an eavesdropper — costs an extra round trip |
| `IX` | 2 | both | nothing | Mutual authentication with nothing pre-shared, when the initiator's identity need not be private — it goes out in the clear |
| `NK` | 2 | responder only | initiator knows the responder's public key | Anonymous client, known server, and you want a reply |
| `NN` | 2 | **neither** | nothing | Only with authentication layered on top. An active machine-in-the-middle defeats it outright |

**One-way — a single sealed message, no reply:**

| Pattern | Msgs | Whose identity is proven | Must be arranged in advance | Reach for it when |
|---------|:----:|--------------------------|-----------------------------|-------------------|
| `N` | 1 | recipient only | sender knows the recipient's public key | Sealing something to a known public key; the sender stays anonymous |
| `X` | 1 | both | sender knows the recipient's public key | Like `N`, but the message also proves who sent it — the sender's key travels encrypted |
| `K` | 1 | both | **both** public keys, exchanged out of band | Two peers who have already swapped keys; no identity goes on the wire at all |
| `Kpsk0` | 1 | both, plus a shared secret | both public keys **and** a pre-shared key | `K` bound to a secret established during a ceremony |

## When you get it wrong

"It refuses to build" is only worth anything if the refusal tells you something. Two
kinds of mistake are caught, both before your code runs.

A slip in the pattern itself:

```text
error: token `e` appears twice in the same message
 --> src/main.rs:3:15
  |
3 |         -> e, e
  |               ^
```

And — more usefully — a pattern that parses fine but is not a sound protocol:

```text
error[E0277]: this Noise pattern never keys the cipher: it performs no DH
              (ee/es/se/ss) and no psk token, so it provides no confidentiality
              or authentication
 --> src/main.rs:3:9
  |
3 |     pub Bad<X25519, ChaChaPoly, Blake2b> {
  |         ^^^ pattern finalises with an unkeyed cipher
```

That second one is the point. It is not a type error dressed up — it is the compiler
telling you your protocol is insecure, at the definition, before anything else compiles.
The same guard rejects a Diffie–Hellman over a key that has not been transmitted yet, a
key sent twice, and a Diffie–Hellman in a pre-message — the rules of Noise §7.3, checked
by the type system.

Both messages are pinned by tests — the first by `tests/ui/duplicate_token.stderr`, the
second by a `compile_fail` doctest on `WellFormed` — so they are regression-locked, not
aspirational. Reproduced here with the fixture paths replaced by a plausible `src/main.rs`,
one over-long line wrapped, and the trait-bound detail below the second error trimmed;
the diagnostic text itself is verbatim.

## Providers

A *provider* holds the private keys and performs the key agreement. The default is
software; on macOS and iOS you can move the private key into the Secure Enclave, where it
is generated and where it stays — the process never sees the key material, only a handle
to it.

Swapping the provider is the whole change. Everything after the first two lines is
identical to the [Quickstart](#quickstart):

```rust
use hiss::noise::{Blake2b, ChaChaPoly, P256};
use hiss::provider::{AppleSecureEnclave, ProviderExt};

hiss::noise! {
    pub XX<P256, ChaChaPoly, Blake2b> {
        -> e
        <- e, ee, s, es
        -> s, se
    }
}

// Generated inside the enclave, persisted to the Keychain, never extractable.
let mut keys = AppleSecureEnclave::new("uk.co.example.app");
let static_key = keys.generate::<P256>()?;

// From here nothing is Apple-specific.
let (msg1, hs) = XX::initiator(keys, &[]).write_message_1()?;
```

The suite names `P256` because the Secure Enclave implements that curve and no other.
This snippet is a compiled doctest on `AppleSecureEnclave`, marked `no_run` — running it
needs enclave hardware and a provisioned entitlement.

### Which backends can do this

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

- **All platforms:** the software backend (`EphemeralOnly`).
- **macOS / iOS:** the Apple Secure Enclave backend. Its blocking Security-framework calls
  are offloaded to a Tokio blocking thread pool for the async provider path.

## Cargo features

| Feature | Default | Effect |
|---------|:-------:|--------|
| `x25519-cryptoxide` | **yes** | Backs X25519's software Diffie–Hellman with `cryptoxide`'s implementation (the faster backend). `--no-default-features` falls back to the `eccoxide` ladder; the output is byte-for-byte identical, so this only changes which dependency carries the primitive. |

`hiss` has one feature, and it only picks a backend for a primitive. There is no
feature that turns the library's API on or off: `noise!` needs none, because
`hiss-macros` is a required dependency and the macro is re-exported as
`hiss::noise!`.

## How this is tested

No audit has happened. This is what stands in for one — every row runs in CI on each
commit.

| Check | What it establishes |
|-------|---------------------|
| **Interoperability with [`snow`](https://crates.io/crates/snow)** | 22 tests over P-256 and 5 over X25519 run one side of a handshake with `hiss` and the other with `snow`, then require both to derive the same handshake hash and to exchange transport messages in both directions. A one-byte disagreement between the two implementations fails the suite. |
| **Frozen known-answer vectors** | 11 tests replay byte-for-byte expectations across all eleven patterns, with ephemerals pinned by a scripted RNG, checking every handshake ciphertext, the final handshake hash, and the transport ciphertexts. **These were generated from `snow`, not from a standards body** — P-256 is not in the Noise specification, so no third-party vectors exist for it. Treat them as a regression lock, not independent conformance. |
| **Wycheproof** | 484 ECDSA and 355 ECDH `secp256r1` vectors from Google's Project Wycheproof, vendored verbatim at a pinned commit and run as library unit tests. Third-party and adversarial: malformed points, edge-case scalars, signature malleability. |
| **Negative tests** | 26 tests assert the *failures*. Twenty-one are tamper sweeps — every byte of every handshake message of every pattern, plus every byte of a transport record; the rest reject a non-canonical ephemeral, a wrong PSK, a replay, and an out-of-order record, and pin all twenty on-wire message sizes. There is deliberately no truncation sweep: a wrong-length message is a compile error, not a runtime rejection, so that case is pinned by a `compile_fail` doctest instead. |
| **Compile-fail tests** | 12 `trybuild` cases pin the compiler diagnostics for malformed patterns, so "it will not build" stays true *and* keeps saying something useful. Separate `compile_fail` doctests cover the §7.3 pattern guard and the wrong-length message case. |
| **Coverage floor** | CI fails the build below 80% lines / 75% regions. |

Alongside these, each commit is gated on `clippy` with warnings denied, a documentation
build with warnings denied, and a build on the declared MSRV.

None of that is an audit, and none of it is a substitute for one.

## Security

**This crate has not been independently audited and is pre-1.0. Do not use it to protect
anything you cannot afford to lose.** That said, the crypto core is built to be
responsible:

- **Constant-time P-256 scalar multiplication** via `eccoxide`'s constant-time backend.
- **Deterministic ECDSA** (RFC 6979) with low-S normalization; no signing RNG.
- **Peer-key and DH-output validation** — operations on attacker-supplied points return
  `Result` rather than panicking. On **P-256** a degenerate (point-at-infinity) shared
  secret is rejected; the Noise **`25519`/`448`** curves perform no low-order or
  contributory-key check — per RFC 7748 a low-order peer key simply yields an all-zero
  shared secret rather than an error.
- **Noise's 65535-byte message-length limit** is enforced at the cipher-state chokepoint.
- **Secret material is zeroized on drop** and is never required to be `Clone`.

Please report security issues privately to the maintainers rather than opening a public
issue.

## Minimum supported Rust version

`hiss` uses the Rust 2024 edition and declares an MSRV of **1.96**, enforced in CI by
the `msrv` job (`cargo check --all-features --all-targets` on the pinned toolchain).

The MSRV tracks a recent stable, **floored at `stable − 3`**: it is bumped only once it
would fall more than three releases behind current stable. It is set at the current
stable today and will begin moving once stable advances past 1.99. The declared value
lives in `Cargo.toml` (`rust-version`); keep it and the `msrv` CI job in lockstep.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for
inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed
as above, without any additional terms or conditions.
