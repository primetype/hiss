# hiss

**Encrypted, authenticated channels between two peers you control — with the handshake
checked by the compiler, and private keys that can stay in an Apple Secure Enclave.**

Built on the [Noise Protocol Framework][noise]: you write the handshake in Noise's own
notation; `hiss` generates it, sizes every message at compile time, and rejects malformed ones.

> **Status: `0.3` — pre-1.0: unstable API, not independently audited.** See
> [How this is tested](#how-this-is-tested) and [Security](#security) before relying on it.

[noise]: https://noiseprotocol.org/

## Quickstart

Two peers authenticate each other and exchange an encrypted message in each direction,
neither knowing the other's key in advance. Four steps, each a doctest that compiles and
runs; assembled, they are [`examples/quickstart.rs`](examples/quickstart.rs).

`hiss` never picks a random-number generator for you, so the CSPRNG is yours to choose:

```toml
[dependencies]
hiss = "0.3"
rand = "0.10"
```

**1. Describe the handshake you want.** This one is `XX`: three messages, both sides
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
a key pair that outlives the connection; nothing is shared in advance. Keep the public
halves — step 3 is where each side checks the other against one.

```rust
use hiss::provider::{EphemeralOnly, ProviderExt};

let mut alice_keys = EphemeralOnly::new(rand::rng());
let alice_static = alice_keys.generate::<X25519>()?;
let alice_pub = alice_keys.public(&alice_static)?;

let mut bob_keys = EphemeralOnly::new(rand::rng());
let bob_static = bob_keys.generate::<X25519>()?;
let bob_pub = bob_keys.public(&bob_static)?;
```

**3. Run the handshake — and decide whether to trust the peer.** Each call hands you the
bytes to send; moving them — socket, queue, QR code — is yours, because `hiss` does no I/O.

Completing `XX` proves the peer holds *a* static private key, never that it is one you
trust. `read_message_N_with` is where that decision goes: the closure sees the peer's key
as it decrypts, and an `Err` aborts before any `Transport` exists. Leave it out and you
have an encrypted channel to a stranger.

The *prologue* is any context both sides already agree on — a protocol version, a channel
name — mixed into the handshake so a mismatch fails it; pass `&[]` if you have none.

```rust
use hiss::noise::HandshakeError;

const PROLOGUE: &[u8] = b"prologue";

// Your trust policy: a pin, an enrolment record, an allow-list. Here, the key we expect.
let accept = |ok: bool| match ok {
    true => Ok(()),
    false => Err(HandshakeError::PeerRejected {
        reason: "unknown peer".into(),
    }),
};

let (msg1, alice) = XX::initiator(alice_keys, PROLOGUE).write_message_1()?;
let bob = XX::responder(bob_keys, PROLOGUE).read_message_1(&msg1)?;
let (msg2, bob) = bob.write_message_2(bob_static)?;
let alice = alice.read_message_2_with(&msg2, |peer| accept(peer == &bob_pub))?;
let (msg3, mut alice) = alice.write_message_3(alice_static)?;
let mut bob = bob.read_message_3_with(&msg3, |peer| accept(peer == &alice_pub))?;
```

**4. Talk.** Both ends now hold a `Transport`. `OVERHEAD` is what the authentication tag
costs you per message: give `send` a buffer of `plaintext.len() + OVERHEAD`, and `receive`
one that fits the plaintext. `b"ping"` is 4 bytes, so 4 is the size below. One record
carries at most 65519 bytes of plaintext — chunk anything larger yourself.

```rust
use hiss::noise::Transport;

let mut wire = [0u8; 4 + Transport::<XX>::OVERHEAD];
let mut got = [0u8; 4];

let n = alice.send(b"ping", &mut wire)?;
let m = bob.receive(&wire[..n], &mut got)?;
assert_eq!(&got[..m], b"ping");

let n = bob.send(b"pong", &mut wire)?;
let m = alice.receive(&wire[..n], &mut got)?;
assert_eq!(&got[..m], b"pong");
```

Framed on a real socket, same trust check: [`tcp_xx_channel.rs`](examples/tcp_xx_channel.rs);
plus a PSK ceremony: [`tcp_ikpsk1_ceremony.rs`](examples/tcp_ikpsk1_ceremony.rs).

## Why this and not `snow`

[`snow`](https://crates.io/crates/snow) is the established Rust Noise implementation, and
this README leans on it: the `hiss-interop` suite runs `hiss` against it, and the frozen
vectors were generated from it. Neither crate has been audited — snow says so on its own front
page. Three things differ.

**The pattern is a type, not a string.** In `snow`, the pattern is data: the builder
parses `"Noise_XX_25519_ChaChaPoly_BLAKE2s"` at runtime, and every session is the same
`HandshakeState` type, whose `read_message` / `write_message` take `&mut self` and accept
calls in any order. In `hiss`, the `noise!` block compiles the pattern into its own state
machine: `XX` from the Quickstart is a type, each message is its own method, and each call
consumes the state before it. Wrong order, a skipped message, or using the channel before
the handshake finishes will not compile — nor will [a pattern that never keys the
cipher](#when-you-get-it-wrong).

**Message sizes are constants.** In `snow`, nothing tells you a message's size before it
arrives, so buffers are sized for the ceiling — snow's own example opens
`let mut buf = [0u8; 65535]`. In `hiss`, the macro has already computed every handshake
message's exact size and hangs each on the pattern type as an associated constant:
`XX::MSG1_SIZE` is a compile-time `usize`, so framing a handshake is a `read_exact` into
`[u8; XX::MSG1_SIZE]` — no length prefix, no scratch buffer.

**Private keys can stay in hardware.** `snow`'s builder takes the static private key as
bytes, so the key passes through your process's memory wherever it actually lives. In
`hiss`, every key operation goes through a *provider*; on macOS and iOS that provider can
be the Apple Secure Enclave, which generates the static key internally and never releases
it — your process only ever holds a handle. See [Providers](#providers).

**Choose snow** if you need more of Noise than this covers — the **23 deferred
patterns** (spec §7.6), the `fallback` modifier, more ciphers (AES-GCM, XChaChaPoly),
and swappable crypto backends including `ring`. Three axes where it is no longer
ahead: the **fundamental** patterns, all fifteen of which hiss now ships; the hashes —
snow's set is the specification's four, and so is hiss's; and PSK placement — `noise!`
takes a `psk` token anywhere in a message, and every position a `pskN` modifier can
name (`psk0`–`psk3`) is pinned by a third-party `cacophony` vector.

One choice that isn't a comparison: production cryptography here is `cryptoxide` and
`eccoxide`, nothing else.

## Supported suite

This release targets a narrow suite matrix and a fixed set of patterns:

| Axis    | Supported |
|---------|-----------|
| Patterns | `N`, `K`, `Kpsk0`, `IKpsk1`, `IK`, `NK`, `IX`, `XK`, `NN`, `XX`, `X`, `NX`, `XN`, `KN`, `KK`, `KX`, `IN`, `NNpsk0`, `NNpsk2`, `XXpsk3` |
| Curves  | NIST **P-256** (secp256r1), **X25519** (Curve25519, the Noise `25519` curve), and **X448** (the Noise `448` curve) |
| Cipher  | **ChaCha20-Poly1305** |
| Hash    | **BLAKE2b**-512, **SHA-512**, **SHA-256**, **BLAKE2s** — the Noise specification's four |

That pattern row is **all fifteen** of Noise's fundamental patterns plus five PSK
variants — one for every position a `pskN` modifier can name, `psk0` through `psk3`
(there is no `psk4` to support: no fundamental pattern has a fourth message). The
`noise!` macro itself takes a `psk` token anywhere in any message; the five variants
are the placements with a vector behind them. Conformance is anchored against
[`snow`](https://crates.io/crates/snow) — by the frozen vectors snow generated, which
every build replays, and by the live interop suite in `hiss-interop`, which runs
occasionally. What is planned beyond
this — and what is deliberately not — is in [TODO.md](TODO.md).

There is no default suite — every `noise!` declaration names its curve, cipher and hash,
and one that omits them generates a bare pattern marker rather than a working protocol.
The cipher row has one entry, so the choices are the curve and the hash. For the curve,
**use `X25519`**, as the Quickstart does, unless you need the Apple Secure Enclave, which
speaks `P256` and nothing else, or want `X448`'s larger margin. For the hash, **use
`Blake2b`** — it is what the Quickstart uses and the only one with the full
seventeen-pattern frozen P-256 matrix; the other three are there for peers that require
them. All four are covered by primitive vectors from the relevant standard and by frozen
**third-party** (`cacophony`) Noise vectors over `25519` and `448` across all twenty
patterns, plus live `snow` interop on `XX` in `hiss-interop`. With `X448`, prefer a
512-bit hash
(`Blake2b` or `Sha512`).

## Which pattern?

**If you are not sure, use `XX`** — the Quickstart's pattern. It needs nothing arranged in
advance, authenticates both sides, and hides both identities from anyone watching the
wire. Move off it only when a row below describes your situation better.

**Interactive — both sides talk.** Every one of these mixes both ephemerals (`ee`), so
once that token lands the session has full forward secrecy. What differs is who proves
their identity, and what has to be arranged beforehand.

| Pattern | Msgs | Whose identity is proven | Must be arranged in advance | Reach for it when |
|---------|:----:|--------------------------|-----------------------------|-------------------|
| **`XX`** | 3 | both | nothing | **The default.** Neither side pre-knows the other, and both identities stay hidden from a passive eavesdropper |
| `IK` | 2 | both | initiator knows the responder's public key | You already ship the server's key inside the client — fewest round trips for mutual authentication |
| `IKpsk1` | 2 | both, plus a shared secret | responder's public key **and** a pre-shared key | `IK` for devices enrolled in a ceremony that issued them a per-device secret |
| `XK` | 3 | both | initiator knows the responder's public key | Like `IK`, but the initiator's identity must stay hidden from an eavesdropper — costs an extra round trip |
| `IX` | 2 | both | nothing | Mutual authentication with nothing pre-shared, when the initiator's identity need not be private — it goes out in the clear |
| `NK` | 2 | responder only | initiator knows the responder's public key | Anonymous client, known server, and you want a reply |
| `NN` | 2 | **neither** | nothing | Only with authentication layered on top. An active machine-in-the-middle defeats it outright |

**One-way — a single sealed message, no reply.** There is no `ee` here, so forward
secrecy is one-sided: the fresh ephemeral per message protects a captured message against
later compromise of the *sender's* keys, but whoever compromises the recipient's static
private key — plus the pre-shared key, for `Kpsk0` — can still decrypt it.

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
second by a `compile_fail` doctest on `WellFormed` — so they stay true as the crate
changes. (Diagnostic text verbatim; paths and line wrapping tidied for print.)

## Providers

A *provider* is where your private keys live and what performs the key agreement. `hiss`
never picks one for you: you construct it and hand it to `initiator` / `responder`, which
is the `alice_keys` argument in the Quickstart. Two ship with the crate:

| Provider | Platforms | Where the private key lives | Curves |
|----------|-----------|-----------------------------|--------|
| `EphemeralOnly` | everywhere, including WASM | in your process memory, zeroized on drop | P-256, X25519, X448 (DH); Ed25519 (signing only) |
| `AppleSecureEnclave` | macOS, iOS | inside the enclave — your process only ever holds a handle | P-256 |

`EphemeralOnly` is the default, and what the Quickstart uses. Its name means *no built-in
persistence*, not "no long-term keys": it does generate the static key that `XX`
authenticates you by. Storing that key between runs, and distributing the public halves
your peers pin, are yours to do — `EphemeralOnly` will not do them behind your back.

Moving to the enclave is a two-line change in your code; the enclave itself still needs
setting up, which on macOS means a team-prefixed keychain entitlement carried by an
embedded provisioning profile (the `hiss::provider::apple` module docs list what it
takes). Everything after those two lines is identical to the [Quickstart](#quickstart):

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

### Bring your own

A provider is just a pair of traits, so a backend `hiss` has never heard of — an HSM, a
cloud KMS, a key store you already have — plugs in without touching the Noise core.
Implement `CryptoKeyProvider` (your key handle, your error type, generate a key, extract a
public key) and `DhProvider` (one method: `dh`), or their `_async` mirrors if the backend
genuinely suspends. Signing lives on separate traits that the Noise handshake never calls.

One hard requirement, and it is Noise's rather than hiss's: the handshake key-agrees
**only via raw Diffie–Hellman**, so a backend qualifies only if it will hand back the
shared secret. A backend that can sign but never expose a DH result cannot carry the
channel — it fits an identity layer *around* it instead.

## Platforms

- **All platforms:** the software backend (`EphemeralOnly`).
- **macOS / iOS:** the Apple Secure Enclave backend.

`hiss` depends on **no async runtime** on any platform. The `*Async` provider traits exist
for backends that genuinely await I/O; where the underlying calls are blocking — as
Apple's Security-framework calls are — those futures do the work on the thread that polls
them. Keeping that off your executor is the application's call, not the library's.

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
| **Interoperability with [`snow`](https://crates.io/crates/snow)** | 28 tests over P-256 and 5 over X25519 run one side of a handshake with `hiss` and the other with `snow`, then require both to derive the same handshake hash and to exchange transport messages in both directions. A one-byte disagreement between the two implementations fails the suite. These live in the separate `hiss-interop` crate and run weekly plus on demand — **not** on every `cargo test`, and not as a release gate; what runs per-commit is the frozen vectors above. |
| **Frozen known-answer vectors (P-256, `snow`-generated)** | 17 tests replay byte-for-byte expectations across all seventeen patterns, with ephemerals pinned by a scripted RNG, checking every handshake ciphertext, the final handshake hash, and the transport ciphertexts. **These were generated from `snow`, not from a standards body** — P-256 is not in the Noise specification, so no third-party vectors exist for it. Treat them as a regression lock, not independent conformance. |
| **Frozen third-party vectors (`cacophony`)** | 320 tests replay a 160-vector subset of the community `cacophony` corpus — all twenty patterns, in both roles, over `{25519, 448} × ChaChaPoly × {BLAKE2b, BLAKE2s, SHA256, SHA512}` — checking every handshake ciphertext, every recovered payload, revealed statics, the final handshake hash, and every transport message. Neither hiss nor `snow` produced these vectors, they are the only cross-implementation check `448` has (snow's own harness skips its `448` vectors), and they pin every `pskN` placement, `psk0`–`psk3`. Provenance and licence chain: `tests/vectors/cacophony/PROVENANCE.md`. |
| **Wycheproof** | 484 ECDSA and 355 ECDH `secp256r1` vectors from Google's Project Wycheproof, vendored verbatim at a pinned commit and run as library unit tests. Third-party and adversarial: malformed points, edge-case scalars, signature malleability. |
| **Negative tests** | 26 tests assert the *failures*. Twenty-one are tamper sweeps — every byte of every handshake message of the eleven patterns swept, plus every byte of a transport record; the rest reject a non-canonical ephemeral, a wrong PSK, a replay, and an out-of-order record, and pin the twenty on-wire message sizes of those eleven. (The sweeps stop at eleven deliberately: every message token list in the other six already appears among them, so extending would re-test identical machinery.) There is deliberately no truncation sweep: a wrong-length message is a compile error, not a runtime rejection, so that case is pinned by a `compile_fail` doctest instead. |
| **Compile-fail tests** | 12 `trybuild` cases pin the compiler diagnostics for malformed patterns, so "it will not build" stays true *and* keeps saying something useful. Separate `compile_fail` doctests cover the §7.3 pattern guard and the wrong-length message case. |
| **Coverage floor** | CI fails the build below 80% lines / 75% regions. |

Alongside these, each commit is gated on `clippy` with warnings denied, a documentation
build with warnings denied, and a build on the declared MSRV.

None of that is an audit, and none of it is a substitute for one.

## Security

**This crate has not been independently audited and is pre-1.0. Do not use it to protect
anything you cannot afford to lose.** That said, the crypto core is built to be
responsible:

A cryptographic property belongs to whatever actually computes it. Some of these are the
crate's own and hold under any provider; the rest are a *backend's*, and do not transfer
to the other one. They are listed apart for that reason — a guarantee about the software
provider says nothing about the Secure Enclave.

**Under any provider:**

- **Noise's 65535-byte message-length limit** is enforced at the cipher-state chokepoint.
- **Peer public keys are parsed and validated by `hiss`** before a provider ever sees
  them; operations on attacker-supplied points return `Result` rather than panicking.
- **Secret material is zeroized on drop** — pre-shared keys, shared secrets, cipher state
  and symmetric state, and the datagram receive ratchet all wipe their bytes — and no
  provider is required to make its private key `Clone`.
- **The Noise `25519` and `448` curves perform no low-order or contributory-key check.**
  Per RFC 7748 a low-order peer key yields an all-zero shared secret rather than an error.

**`EphemeralOnly` — software, every platform:**

- **Constant-time P-256 scalar multiplication** via `eccoxide`'s constant-time backend.
- **Deterministic ECDSA** (RFC 6979), low-S normalized, no signing RNG.
- **A degenerate (point-at-infinity) P-256 ECDH result is rejected** rather than returned.
- **Private keys are zeroized on drop** — they are raw scalars sitting in your memory.

**`AppleSecureEnclave` — macOS, iOS:** its P-256 arithmetic is the platform's, so none of
the four above are `hiss`'s to promise, and `hiss` does not verify them.

- **ECDSA is randomized, not RFC 6979, and not low-S** — the framework derives its own
  nonce, and `hiss` decodes the DER it returns without normalizing. Signing the same
  message twice yields different signatures.
- **The DH result is taken as given**, beyond checking it is 32 bytes; `hiss` adds no
  degeneracy check of its own on this path. (A parsed public key cannot hold the identity
  on either provider, so the software check above is defence in depth, not a fix.)
- **A P-256 private key is never in your process to zeroize** — you hold a `SecKey`
  handle. Its Ed25519 keys *are* software, over a hardware-sealed seed, and do zeroize.

The Noise handshake never signs, so the ECDSA rows concern the identity layer around a
channel rather than the channel itself.

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
