# Security Policy

`hiss` is a maximally-static implementation of a curated subset of the
[Noise Protocol Framework](https://noiseprotocol.org/), with a pluggable
crypto-provider abstraction (software and Apple Secure Enclave backends).

> ⚠️ **`hiss` is pre-1.0 (`0.1.x`) and has not been independently audited.**
> Do not use it to protect anything you cannot afford to lose. The API and the
> security posture described here may change before 1.0.

This document states what `hiss` defends against, what it does not, how to report
a vulnerability, and the concrete cryptographic posture of each backend — with the
validated evidence behind every claim.

## Reporting a vulnerability

**Please report security issues privately. Do not open a public issue or PR for a
suspected vulnerability.**

Use GitHub's private vulnerability reporting:

➡️ **<https://github.com/primetype/hiss/security/advisories/new>**

(Repository → **Security** tab → **Report a vulnerability**.)

Please include enough detail to reproduce — the affected backend/pattern, a proof
of concept or failing test if you have one, and the version/commit. We will
acknowledge the report, work with you on an assessment, and coordinate a fix and
disclosure. As a pre-1.0 project run by a small team there is no formal SLA, but we
treat cryptographic issues as the highest priority.

If you cannot use GitHub advisories, contact the maintainer listed in
[`Cargo.toml`](Cargo.toml).

### Supported versions

| Version | Supported |
|---------|-----------|
| `0.1.x` (latest) | ✅ |
| anything older   | ❌ |

Being pre-1.0, only the most recent `0.1.x` release receives fixes; there are no
backports.

## Scope

`hiss` deliberately implements a **small, curated surface** rather than the full
Noise matrix. The security claims below apply only to this surface:

| Component | Supported |
|-----------|-----------|
| Handshake patterns | `N`, `K`, `Kpsk0`, `IKpsk1`, `IK`, `NK`, `IX`, `XK`, `NN`, `XX` (a 10-pattern subset) |
| Noise DH curves | NIST **P-256** (the Noise DH curve), **X25519** (the Noise `25519` curve, Curve25519 / RFC 7748), and **X448** (the Noise `448` curve, RFC 7748) |
| Signing curve | **Ed25519** (standalone signing; not used as a Noise DH curve) |
| AEAD cipher | **ChaCha20-Poly1305** |
| Hash | **BLAKE2b-512** |
| Backends | **Software** (default, all platforms incl. WASM) and **Apple Secure Enclave** (macOS/iOS, opt-in) |

> **The non-P-256 DH curves carry a narrower assurance surface.** All three DH
> curves (`P-256`, `25519`, `448`) are fully shipped Noise handshake curves, but
> the validation behind them differs:
>
> - **Contributory-behaviour / low-order check.** P-256 ECDH **rejects** a
>   degenerate (point-at-infinity) shared secret. **X25519 and X448 do not perform
>   any low-order or contributory key check** — per RFC 7748 a low-order peer key
>   simply yields an **all-zero shared secret** rather than an error. This is
>   spec-conformant (the check is optional in RFC 7748), but it means the Curve25519
>   / Curve448 paths give the caller no signal on a degenerate DH.
> - **Frozen known-answer coverage is P-256-only.** The frozen Noise KAT corpus
>   exists for **P-256 only**. X25519 is validated by **byte-for-byte interop with
>   [snow](https://crates.io/crates/snow)** across the `N` / `IK` / `XX` patterns;
>   X448 has a single self round-trip (`XX`). There are **no frozen X25519/X448
>   KAT vectors yet**. See [Validated test vectors](#validated-test-vectors).
>
> Ed25519 is exposed for **standalone** signing (and a Curve25519 DH) through the
> provider API; it is not used as the curve inside a Noise pattern.

## Threat model

### Adversary

We assume an active network attacker who can read, drop, reorder, replay, and
inject ciphertext on the wire, and who may know the long-term static public keys of
the parties. The attacker does **not** know the private keys held by an honest party
or a pre-shared key (PSK) they do not possess, and does not control the honest
party's host OS or RNG.

### In scope

- Confidentiality and integrity of payloads, to the degree each handshake pattern
  provides (see the table below).
- Sender/recipient authentication, to the degree each pattern provides.
- Rejection of tampered, truncated, over-length, replayed, and out-of-order
  messages (systematically tested; see [Validated test vectors](#validated-test-vectors)).
- Rejection of malformed or invalid peer public keys without panicking. For
  **P-256**, rejection extends to a **degenerate (identity) DH output**; for
  **X25519 / X448**, a low-order peer key yields an **all-zero shared secret**
  rather than an error (per RFC 7748 — see the [Scope](#scope) note).
- Deterministic, non-malleable ECDSA signing (RFC 6979 + low-S).
- Constant-time secret-scalar **point** multiplication in the software P-256
  backend (subject to the upstream caveat in [Side-channel posture](#side-channel-posture-per-backend)).

### Out of scope

- A compromised host OS, a malicious or broken RNG supplied by the caller, or
  physical/hardware attacks beyond what the platform or Secure Enclave mitigates.
- Traffic analysis (message sizes and timing of the application protocol itself).
- Patterns, curves, ciphers, or hashes outside the [Scope](#scope) table.
- Replay protection for the one-way patterns (`N`/`K`/`Kpsk0`) — they are one-shot
  seals by construction; replay resistance is a property only of the interactive
  `IK` / `IKpsk1` / `NK` / `IX` / `XK` / `NN` / `XX` handshakes. See the per-pattern table.
- Anything a caller does with secret bytes after copying them out of a `hiss` type
  (e.g. via `seed()`).

### Per-pattern security properties

These follow the payload-security properties defined by the Noise specification for
the one-way and interactive patterns. `hiss`'s conformance is validated by
byte-for-byte agreement with [snow](https://crates.io/crates/snow), the reference
Noise implementation — **not** by an independent standards-body vector set, because
P-256 is not part of the Noise spec (see the provenance note under
[Validated test vectors](#validated-test-vectors)). The full per-pattern matrix is
exercised on P-256; X25519 is exercised against snow across `N` / `IK` / `XX`, and
X448 has a single `XX` self round-trip (see [Validated test vectors](#validated-test-vectors)).

| Pattern | Flow | Sender authentication | Confidentiality to recipient | Forward secrecy | Replay resistance | PSK |
|---------|------|-----------------------|------------------------------|-----------------|-------------------|-----|
| **N** | one message (`-> e, es`) | **none** — sender is anonymous | encrypted to the recipient's known static key | sender-side only (fresh ephemeral per message); **lost if the recipient's static key is compromised** | **no** (one-way) | — |
| **K** | one message (`-> e, es, ss`) | sender's static key, **vulnerable to key-compromise impersonation** (auth rests on the static–static `ss` DH) | encrypted to the recipient's known static key | sender-side only | **no** (one-way) | — |
| **Kpsk0** | one message (`-> psk, e, es, ss`) | sender's static key **plus a PSK** (a second factor) | recipient's static key **plus the PSK** — an attacker needs the relevant private key *and* the PSK | sender-side only | **no** (one-way) | position 0 |
| **IKpsk1** | two messages (`-> e, es, s, ss, psk` / `<- e, ee, se`) | **mutual** — responder authenticated to the initiator via `es`/`ss` (the DHs that bind the responder's static key); initiator authenticated to the responder via `ss` then `se` — **plus a PSK** | recipient's static key plus the PSK; the initiator's identity is hidden from a passive eavesdropper | **full** once both ephemerals are mixed (`ee`) | **yes** (responder contributes a fresh ephemeral) | position 1 |
| **IK** | two messages (`-> e, es, s, ss` / `<- e, ee, se`) | **mutual** — responder authenticated to the initiator via `es`/`ss` (the DHs that bind the responder's static key); initiator authenticated to the responder via `ss` then `se` | encrypted to the recipient's known static key; the initiator's identity is hidden from a passive eavesdropper | **full** once both ephemerals are mixed (`ee`) | **yes** (responder contributes a fresh ephemeral) | — |
| **NK** | two messages (`-> e, es` / `<- e, ee`) | **none for the initiator — it is anonymous** (no static key); the **responder is authenticated to the initiator** via the `es` DH that binds the responder's known static key | encrypted to the responder's known static key | **full** once both ephemerals are mixed (`ee`) | **yes** (responder contributes a fresh ephemeral) | — |
| **IX** | two messages (`-> e, s` / `<- e, ee, se, s, es`) | **mutual** — no pre-known statics: the initiator is authenticated to the responder via `se`, the responder to the initiator via `es`; both statics are sent in-handshake | payload encrypted after `ee`; **the initiator's static identity is sent in the clear in msg1 (before any DH) and is exposed to a passive eavesdropper**; the responder's static is sent in msg2 after `ee` and is encrypted | **full** once both ephemerals are mixed (`ee`) | **yes** (responder contributes a fresh ephemeral) | — |
| **XK** | three messages (`-> e, es` / `<- e, ee` / `-> s, se`) | **mutual** — the responder is authenticated to the initiator via the `es` DH that binds the responder's known static key; the initiator is authenticated to the responder via `se` | encrypted to the responder's known static key; **the initiator's static identity is sent encrypted in msg3 (after `ee`) and is hidden from a passive eavesdropper** | **full** once both ephemerals are mixed (`ee`) | **yes** (responder contributes a fresh ephemeral) | — |
| **NN** | two messages (`-> e` / `<- e, ee`) | **none — both parties are anonymous** (no static keys); **no protection against an active man-in-the-middle** | only against a **passive** eavesdropper — there are no static keys, so a passive observer cannot read the traffic but an active MITM can impersonate either side | **full** once both ephemerals are mixed (`ee`) | **yes** (responder contributes a fresh ephemeral) | — |
| **XX** | three messages (`-> e` / `<- e, ee, s, es` / `-> s, se`) | **mutual** — no pre-known statics: the initiator is authenticated to the responder via `se`, the responder to the initiator via `es`; both statics are sent in-handshake | payload encrypted after `ee`; **both statics are sent encrypted (the responder's in msg2, the initiator's in msg3, both after `ee`), so both identities are hidden from a passive eavesdropper** | **full** once both ephemerals are mixed (`ee`) | **yes** (responder contributes a fresh ephemeral) | — |

Notes:

- `N`, `K`, and `Kpsk0` are **one-way seals** (a single message, no response). They
  provide no replay protection and only sender-side forward secrecy; they are
  intended for encrypting data at rest to a known public key (for example, sealing a
  per-pair PSK to a device's own Secure Enclave key). Because there is no recipient
  ephemeral, compromise of the recipient's static private key exposes past payloads.
- `IK` and `IKpsk1` are the **interactive mutually-authenticated handshakes**
  (`IKpsk1` layers a PSK on top of `IK`). Forward secrecy and replay resistance are
  established only after the second message (the `ee` DH).
- `NK` is an **interactive, responder-authenticated** handshake: the initiator is
  **anonymous** (it carries no static key), and only the responder is authenticated —
  to the initiator — via the `es` DH that binds the responder's known static key. Like
  the other interactive patterns, forward secrecy and replay resistance follow the
  second message (the `ee` DH).
- `IX` is an **interactive, mutually-authenticated** handshake with **no pre-messages**:
  neither party knows the other's static key in advance, so both transmit their statics
  *during* the handshake. The trade-off is identity privacy for the initiator — its
  static is sent in msg1 **before any DH runs, in the clear**, so a passive eavesdropper
  learns the initiator's identity (the responder's static, sent in msg2 after `ee`, is
  encrypted). Forward secrecy and replay resistance follow the second message (the `ee`
  DH). Use `IX` when neither side can pre-share the other's static and exposing the
  initiator's identity is acceptable; prefer `IK` when the responder's static is known in
  advance and initiator identity privacy matters.
- `XK` is an **interactive, mutually-authenticated, three-message** handshake with strong
  **initiator-identity privacy**. The initiator pre-knows the responder's static (pre-message
  `<- s`) and authenticates the responder early via the `es` DH; the initiator's own static is
  transmitted **encrypted in msg3, after `ee` keys the cipher**, so it is hidden from a passive
  eavesdropper, and is authenticated via `se`. Compared with `IK` (which sends the initiator's
  static in msg1), `XK` spends an extra round trip to give the initiator's identity full
  forward-secret confidentiality. Forward secrecy and replay resistance follow the second
  message (the `ee` DH).
- `NN` is the **unauthenticated** interactive handshake: **both parties are anonymous**
  (there are no static keys and no pre-messages), so it provides **no authentication of
  either side and no protection against an active man-in-the-middle** — an attacker who
  sits on the wire can complete a separate handshake with each party and relay traffic.
  Confidentiality holds **only against a passive eavesdropper**; forward secrecy and
  replay resistance follow the second message (the `ee` DH). Use `NN` only when an
  authenticated pattern is genuinely impossible, or layer authentication above it.
- `XX` is the **canonical interactive, mutually-authenticated, three-message** handshake
  with **no pre-messages**: neither party knows the other's static key in advance, so both
  transmit their statics *during* the handshake. Unlike `IX`, **both** statics are sent
  **encrypted** — the responder's in msg2 and the initiator's in msg3, each **after `ee`
  keys the cipher** — so **both identities are hidden from a passive eavesdropper**. The
  initiator is authenticated to the responder via `se` and the responder to the initiator
  via `es`. Forward secrecy and replay resistance follow the second message (the `ee` DH).
  Prefer `XX` over `IX` when initiator identity privacy matters and neither side can
  pre-share the other's static; prefer `IK`/`XK` when the responder's static is known in
  advance.
- A PSK (`Kpsk0`, `IKpsk1`) is an **additional** authentication and confidentiality
  factor layered on top of the asymmetric authentication — not a replacement for it.

## Side-channel posture (per backend)

### Software P-256 (default backend, all platforms)

Every **secret-scalar point multiplication** — key generation (`public()`), ECDH
(`dh()`), and the ECDSA signing nonce's `k·G` — routes to a **constant-time** routine
in the underlying `eccoxide` curve library: a fixed-base comb (`mul_base`) for
base-point multiplies and a fixed-window algorithm with a constant-time table scan
(`scale_am3_ct`) for variable-base multiplies. There is no secret-dependent branch
or table index on these paths.

Honest caveats:

- **This is an upstream property.** `hiss` does not implement or independently verify
  constant-time behaviour; it relies on the `eccoxide` release it depends on —
  currently the **crates.io `eccoxide` 0.4**, whose P-256 backend carries the
  constant-time scalar multiplication. The guarantee is therefore only as strong as
  that upstream code.
- **The fixed-base comb relies on `eccoxide`'s `table` feature** (enabled by default
  in this crate's `eccoxide` dependency). Without it the fixed-base multiply is still
  correct and constant-time, just not the precomputed comb — this is a performance,
  not a constant-time, difference.
- **Scope is point multiplication.** ECDSA signing also performs a secret-scalar
  modular inversion (`k⁻¹`) and scalar arithmetic. In `eccoxide` 0.4 the inversion
  is a fixed addition-chain exponentiation (no secret-dependent branching by
  construction); the residual trust is `eccoxide`'s underlying scalar field being
  constant-time, which is **not** independently verified here.
- **Verification is intentionally variable-time.** ECDSA signature *verification*
  computes `u1·G + u2·Q` with a variable-time multiply (`mul_vartime`). Every input on
  the verify path — public key, signature, message hash — is public, so this is safe
  and faster; no secret is involved.

### Apple Secure Enclave (macOS/iOS, opt-in)

P-256 static private keys are generated **inside the Secure Enclave** and stored in
the Data Protection Keychain as non-exportable key references; the private key bytes
never leave the hardware. Side-channel resistance for those operations is the
platform's responsibility.

Honest caveats:

- **Ed25519 is not enclave-backed.** The Secure Enclave has no Ed25519 support, so
  Ed25519 signing is performed in **software** (via `cryptoxide`). For the Enclave
  provider, only the Ed25519 *seed's at-rest storage* is hardware-protected: the seed
  is sealed (Noise-`N` to the device's Secure-Enclave P-256 key) into a 129-byte
  envelope and stored as a data-protection Keychain item, identically on macOS and
  iOS. Protection of that item is `AfterFirstUnlockThisDeviceOnly` — i.e. device
  first-unlock, **not** a per-use biometric prompt.
- The Keychain seal/store/load round-trip is **not exercised in CI** (it needs a
  codesigned binary with the keychain entitlement and real Secure Enclave hardware);
  that test is marked `#[ignore]`.

### Ed25519 (software)

Ed25519 signing and verification are delegated to `cryptoxide`. `hiss` does not add an
independent constant-time audit of that implementation.

## Validated test vectors

The crypto and protocol layers are pinned against the following corpora, run as
in-tree tests:

| Suite | Count / scope | Source & format |
|-------|---------------|-----------------|
| Wycheproof ECDSA (secp256r1, SHA-256) | **484** vectors | Project Wycheproof, DER/ASN.1; every vector decoded and verified |
| Wycheproof ECDH (secp256r1) | **355** vectors | Project Wycheproof, `ecpoint` encoding |
| RFC 6979 deterministic ECDSA | Appendix A.2.5 (P-256/SHA-256) KAT | RFC 6979; raw `(r, s)` pinned for `"sample"` and `"test"` |
| NIST ECC CDH | P-256 `Count=0` | NIST CAVP ECDH vector |
| Noise handshake KATs (**P-256**) | patterns `N` / `K` / `Kpsk0` / `IKpsk1` / `IK` / `NK` / `IX` / `XK` / `NN` / `XX` | frozen, replayed byte-for-byte (handshake ciphertexts + handshake hash + transport) |
| Noise interop, **X25519** | patterns `N` / `IK` / `XX` | byte-for-byte agreement with `snow` (no frozen KAT vectors) |
| Noise round-trip, **X448** | pattern `XX` | single self round-trip (no frozen KAT vectors, no snow interop) |
| Negative / boundary sweeps | per-pattern, deterministic | every-byte tamper, every-prefix truncation, over-length, ciphertext bit-flip, replay, out-of-order, wrong-PSK → all rejected |

The Wycheproof corpora are third-party authoritative. The negative sweeps are
generated deterministically (each driver runs a genuine handshake that must complete
first, so the tests are non-vacuous).

> **Provenance of the Noise KATs (read this).** P-256 is **not** a curve in the Noise
> specification, and no third-party P-256 Noise test vectors exist. The frozen `hiss`
> Noise KATs are therefore **"agreement with snow"** — they assert byte-for-byte
> equality with the [snow](https://crates.io/crates/snow) reference implementation, not
> with a standards body. A latent bug shared with snow would not be caught by these
> vectors. The frozen KAT corpus is **P-256-only**: X25519 is covered by live snow
> interop (`N` / `IK` / `XX`) and X448 by a single `XX` self round-trip, but neither
> curve has a frozen KAT file yet — adding standards-body X25519/X448 vectors is future
> work.

## Signature malleability and encoding

- **Deterministic nonces.** ECDSA signing uses **RFC 6979** deterministic nonces
  (HMAC-SHA256 DRBG); no randomness is involved in signing, eliminating the
  catastrophic private-key leak from nonce reuse or a biased RNG.
- **Low-S on signing.** Produced signatures are normalized to the canonical **low-S**
  form (`s = min(s, n − s)`), so `hiss` never emits a malleable high-S signature.
- **Verification accepts high-S.** Verification follows standard ECDSA and accepts
  both low-S and high-S encodings (matching the Wycheproof `valid` expectations). A
  caller that needs strict low-S on *inbound* signatures must enforce it itself.
- **Strict DER (Apple path only).** When parsing DER signatures produced by Apple's
  Security framework, the ASN.1 reader is strict: it rejects long-form/indefinite
  lengths, non-minimal integer encodings, trailing data, and negative `r`/`s` (per
  X.690 §8.3.2). The pure-software P-256 path uses the fixed 64-byte `r‖s`
  representation and does not parse DER at all.

## Randomness requirements

`hiss` **pulls in no entropy source of its own.** `getrandom` is not a runtime
dependency of the published crate.

- The software provider is `EphemeralOnly<R>`, owning a **caller-supplied**
  `R: CryptoRng + RngCore`. **You must supply a cryptographically secure RNG.**
- With `rand` 0.9, `OsRng` is fallible (`TryRngCore`) and does **not** implement
  `RngCore`; seed a real CSPRNG, e.g. `StdRng::from_os_rng()`.
- P-256 key generation **rejection-samples** the secret scalar into `[1, n−1]`. On a
  broken RNG it fails with a typed `ScalarSamplingFailed` error after a bounded number
  of retries (per-iteration miss probability `< 2⁻³²`) rather than returning a biased
  key. (With a sound CSPRNG this path is effectively unreachable.)
- `Psk::generate` is **infallible**: any 32 random bytes form a valid PSK, so there is
  no error path to surface.

## Secret handling and zeroization

Primary secret types are wiped on drop using volatile writes followed by a
best-effort compiler fence:

- P-256 and Ed25519 private keys
- `Psk`
- `SharedSecret`
- `CipherState` (AEAD key + nonce)
- `SymmetricState` (chaining key; handshake mix/`split` intermediates are wiped inline)

**Honest limits:**

- **The fence is best-effort.** It defeats dead-store elimination of the wipe, but it
  is not a hardware memory barrier and gives no guarantee against secret copies that
  the compiler placed in CPU registers or spilled to the stack.
- **Library-owned intermediates are not zeroized.** Secret values materialized inside
  the underlying libraries — `eccoxide` `Scalar`/`Point` values created during DH,
  signing, and key generation, and `cryptoxide`-internal expansion buffers — are
  **not** wiped, because `hiss` cannot reach inside those library-owned types. This is
  a known, accepted limitation that depends on upstream support to close.
- **`seed()` exposes raw secret bytes.** `SoftwareEd25519PrivateKey::seed()` returns
  the raw 32-byte seed (needed to persist/seal the key). The owning key zeroizes on
  drop, but any bytes a caller copies out are the caller's responsibility.

## Known limitations and non-goals

- **Not audited; pre-1.0.** No external cryptographic audit has been performed; the
  API and posture may change before 1.0.
- **Curated surface.** Only the patterns, curves, cipher, and hash in [Scope](#scope)
  are implemented — not the full Noise matrix.
- **No `fallback` / compound protocols.** The Noise `fallback` modifier (`XXfallback`,
  Noise Pipes / 0-RTT-with-retry) is intentionally not implemented. It is optional in the
  spec and unnecessary for the targeted use cases — a deliberate scoping decision, not an
  oversight. `snow` omits it likewise.
- **Noise KAT provenance.** The frozen P-256 Noise vectors are agreement-with-snow,
  not standards-body vectors; X25519 has live snow interop only and X448 a single
  self round-trip — no frozen X25519/X448 KATs yet (see above).
- **Upstream constant-time dependency.** Constant-time P-256 rests on `eccoxide`'s
  released crates.io `0.4`; the property is only as strong as that upstream backend,
  which `hiss` does not independently verify.
- **Unproven Enclave path.** The Apple Keychain seal/store/load path is not exercised
  in CI (requires codesigned binary + Secure Enclave hardware).

---

*This document describes the security posture of `hiss` as of `0.1.x`. If you find a
discrepancy between this document and the code, that is itself a bug worth reporting.*
