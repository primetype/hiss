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
| Handshake patterns | `N`, `K`, `Kpsk0`, `IKpsk1`, `IK`, `NK`, `IX`, `XK`, `NN`, `XX`, `X`, `NX`, `XN`, `KN`, `KK`, `KX`, `IN` — **all fifteen** of the specification's fundamental patterns plus two PSK variants |
| Noise DH curves | NIST **P-256** (the Noise DH curve), **X25519** (the Noise `25519` curve, Curve25519 / RFC 7748), and **X448** (the Noise `448` curve, RFC 7748) |
| Signing curve | **Ed25519** (standalone signing; not a Noise DH curve — and as of this release not a `DhCurve` at all, so the type system enforces it) |
| AEAD cipher | **ChaCha20-Poly1305** |
| Hash | **BLAKE2b-512**, **SHA-512**, **SHA-256**, **BLAKE2s** — the Noise specification's four (§12.5 SHA256, §12.6 SHA512, §12.7 BLAKE2s, §12.8 BLAKE2b) |
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
> - **Frozen known-answer coverage now spans all three, but from different
>   sources.** X25519 and X448 carry frozen **third-party** (`cacophony`) Noise
>   vectors across all seventeen patterns and all four hashes, and X25519
>   additionally has byte-for-byte live interop with
>   [snow](https://crates.io/crates/snow) — which runs in the separate
>   `hiss-interop` crate, on a cron and on demand, not under `cargo test`.
>   P-256 keeps its own frozen corpus, but
>   that one is agreement-with-snow by necessity — P-256 is not in the Noise
>   specification, so no third-party P-256 Noise vectors exist. See
>   [Validated test vectors](#validated-test-vectors).
>
> Ed25519 is exposed for **standalone** signing through the provider API; it is not
> used as the curve inside a Noise pattern, and cannot be.

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

> **Mutual authentication is conditional on the application checking the peer's
> static key.** Completing IK / IKpsk1 / IX / XK / XX proves the peer holds the
> private half of *a* static key — not that you trust that identity. hiss
> surfaces the verified key via `Transport::remote_static()` (and the handshake
> state's `remote_static()` accessor) but does **not** check it against any
> policy for you; the application must compare it to its own trust store /
> allow-list and reject unknown peers. See `examples/tcp_xx_channel.rs`.

### Out of scope

- A compromised host OS, a malicious or broken RNG supplied by the caller, or
  physical/hardware attacks beyond what the platform or Secure Enclave mitigates.
- Traffic analysis (message sizes and timing of the application protocol itself).
- Patterns, curves, ciphers, or hashes outside the [Scope](#scope) table.
- Replay protection for the one-way patterns (`N`/`K`/`Kpsk0`/`X`) — they are one-shot
  seals by construction; replay resistance is a property only of the interactive
  `IK` / `IKpsk1` / `NK` / `IX` / `XK` / `NN` / `XX` handshakes. See the per-pattern table.
- Anything a caller does with secret bytes after copying them out of a `hiss` type
  (e.g. via `seed()`).

### Per-pattern security properties

These follow the payload-security properties defined by the Noise specification for
the one-way and interactive patterns. Two different things establish `hiss`'s
conformance to them, and they are worth keeping apart.

**What every build checks** is the **frozen** corpora: the P-256 known-answer
vectors across the full per-pattern matrix, and the third-party `cacophony` corpus
replayed over X25519 and X448 across all seventeen patterns in both roles. These are
files of bytes; replaying them needs no second Noise implementation, so they run on
every `cargo test` and in every release gate.

**Where the P-256 bytes came from** is byte-for-byte agreement with
[snow](https://crates.io/crates/snow), the reference implementation — **not** an
independent standards-body vector set, because P-256 is not part of the Noise spec
(see the provenance note under
[Validated test vectors](#validated-test-vectors)). That agreement is a statement
about generation time. It is *re-checked* live — including X25519 across
`N` / `IK` / `XX` — by the suite in the separate `hiss-interop` crate, which runs
weekly and on demand rather than per-commit.

| Pattern | Flow | Sender authentication | Confidentiality to recipient | Forward secrecy | Replay resistance | PSK |
|---------|------|-----------------------|------------------------------|-----------------|-------------------|-----|
| **N** | one message (`-> e, es`) | **none** — sender is anonymous | encrypted to the recipient's known static key | sender-side only (fresh ephemeral per message); **lost if the recipient's static key is compromised** | **no** (one-way) | — |
| **K** | one message (`-> e, es, ss`) | sender's static key, **vulnerable to key-compromise impersonation** (auth rests on the static–static `ss` DH) | encrypted to the recipient's known static key | sender-side only | **no** (one-way) | — |
| **Kpsk0** | one message (`-> psk, e, es, ss`) | sender's static key **plus a PSK** (a second factor) — but the static-key half is the same static–static `ss` DH as `K`'s and is **equally vulnerable to key-compromise impersonation**; the PSK is what an attacker additionally needs, not a repair of `ss`. (The specification tabulates no psk-modified pattern, so this is read across from `K`, whose msg1 this is with `psk` prepended.) | recipient's static key **plus the PSK** — an attacker needs the relevant private key *and* the PSK | sender-side only | **no** (one-way) | position 0 |
| **IKpsk1** | two messages (`-> e, es, s, ss, psk` / `<- e, ee, se`) | **mutual** — responder authenticated to the initiator via `es`/`ss` (the DHs that bind the responder's static key); initiator authenticated to the responder via `ss` then `se` — **plus a PSK** | recipient's static key plus the PSK; the initiator's identity is hidden from a passive eavesdropper | **full** once both ephemerals are mixed (`ee`) | **yes for the handshake** (the responder contributes a fresh ephemeral) — but the **msg1 (0-RTT) payload is replayable** on its own, since nothing of the responder's contributes to it, and it is authenticated only by the static–static `ss` DH, so it is **KCI-forgeable**; both harden once msg2 lands. The PSK does **not** stop the replay: an attacker replays recorded ciphertext and needs no PSK knowledge | position 1 |
| **IK** | two messages (`-> e, es, s, ss` / `<- e, ee, se`) | **mutual** — responder authenticated to the initiator via `es`/`ss` (the DHs that bind the responder's static key); initiator authenticated to the responder via `ss` then `se` | encrypted to the recipient's known static key; the initiator's identity is hidden from a passive eavesdropper | **full** once both ephemerals are mixed (`ee`) | **yes for the handshake** (the responder contributes a fresh ephemeral) — but the **msg1 (0-RTT) payload is replayable** on its own, since nothing of the responder's contributes to it, and it is authenticated only by the static–static `ss` DH, so it is **KCI-forgeable**; both harden once msg2 lands | — |
| **NK** | two messages (`-> e, es` / `<- e, ee`) | **none for the initiator — it is anonymous** (no static key); the **responder is authenticated to the initiator** via the `es` DH that binds the responder's known static key | encrypted to the responder's known static key | **full** once both ephemerals are mixed (`ee`) | **yes for the handshake** (the responder contributes a fresh ephemeral) — but the **msg1 payload is replayable** on its own, for the same reason as `IK`'s; unlike `IK` it carries no sender authentication at all, so there is no KCI clause | — |
| **IX** | two messages (`-> e, s` / `<- e, ee, se, s, es`) | **mutual** — no pre-known statics: the initiator is authenticated to the responder via `se`, the responder to the initiator via `es`; both statics are sent in-handshake | payload encrypted after `ee`; **the initiator's static identity is sent in the clear in msg1 (before any DH) and is exposed to a passive eavesdropper**; the responder's static is sent in msg2 after `ee` and is encrypted | **full** once both ephemerals are mixed (`ee`) | **yes** (responder contributes a fresh ephemeral) | — |
| **XK** | three messages (`-> e, es` / `<- e, ee` / `-> s, se`) | **mutual** — the responder is authenticated to the initiator via the `es` DH that binds the responder's known static key; the initiator is authenticated to the responder via `se` | encrypted to the responder's known static key; **the initiator's static identity is sent encrypted in msg3 (after `ee`) and is hidden from a passive eavesdropper** | **full** once both ephemerals are mixed (`ee`) | **yes for the handshake** (the responder contributes a fresh ephemeral) — but the **msg1 payload is replayable** on its own, exactly as `NK`'s is, and likewise carries no sender authentication | — |
| **NN** | two messages (`-> e` / `<- e, ee`) | **none — both parties are anonymous** (no static keys); **no protection against an active man-in-the-middle** | only against a **passive** eavesdropper, and only from msg2 onward — there are no static keys, so a passive observer cannot read the traffic once `ee` keys the cipher, but an active MITM can impersonate either side. A payload declared on msg1 (`-> e`) closes **before any DH** and therefore travels **in cleartext**, readable by anyone | **full** once both ephemerals are mixed (`ee`) | **yes** (responder contributes a fresh ephemeral) | — |
| **XX** | three messages (`-> e` / `<- e, ee, s, es` / `-> s, se`) | **mutual** — no pre-known statics: the initiator is authenticated to the responder via `se`, the responder to the initiator via `es`; both statics are sent in-handshake | payload encrypted after `ee`; **both statics are sent encrypted (the responder's in msg2, the initiator's in msg3, both after `ee`), so both identities are hidden from a passive eavesdropper** | **full** once both ephemerals are mixed (`ee`) | **yes** (responder contributes a fresh ephemeral) | — |
| **X** | one message (`-> e, es, s, ss`) | sender's static key, **vulnerable to key-compromise impersonation** (auth rests on the static–static `ss` DH); the sender's static is sent **encrypted in-band** (after `es`), not pre-shared | encrypted to the recipient's known static key; **the sender's identity is hidden from a passive eavesdropper** (its static rides encrypted after `es`) | sender-side only (fresh ephemeral per message); **lost if the recipient's static key is compromised** | **no** (one-way) | — |
| **NX** | two messages (`-> e` / `<- e, ee, s, es`) | **responder only** — the initiator is anonymous (it has no static key); the responder is authenticated to the initiator via `es` | payload encrypted after `ee`; **the responder's static is sent encrypted in msg2, so it is hidden from a passive eavesdropper — but any anonymous initiator can ask for it**, since nothing gates the handshake | **full** once both ephemerals are mixed (`ee`) | **yes** (responder contributes a fresh ephemeral) | — |
| **XN** | three messages (`-> e` / `<- e, ee` / `-> s, se`) | **initiator only** — the responder is anonymous (it has no static key); the initiator is authenticated to the responder via `se` | payload encrypted after `ee`; the initiator's static is sent encrypted in msg3, so it is hidden from a passive eavesdropper — but it is **sent to a responder that was never authenticated**, and an active MITM can impersonate that responder outright | **full** once both ephemerals are mixed (`ee`) | **yes** (responder contributes a fresh ephemeral) | — |
| **KN** | two messages (`-> e` / `<- e, ee, se`), initiator's static pre-shared (`-> s`) | **initiator only** — authenticated via `se`; **the responder is never authenticated** | payload encrypted after `ee`, but the responder's identity is unverified, so the responder-to-initiator direction has only **weak** forward secrecy until the responder receives a transport message; nothing identifying is transmitted, though an **active** attacker impersonating the initiator who later obtains a candidate for the initiator's *private* key can confirm it | **full** once both ephemerals are mixed (`ee`) | **yes** (responder contributes a fresh ephemeral) | — |
| **KK** | two messages (`-> e, es, ss` / `<- e, ee, se`), **both** statics pre-shared (`-> s`, `<- s`) | **mutual** — the responder via `es`/`ss`, the initiator via `ss` then `se`. The **msg1 (0-RTT) payload's** authentication rests on the static–static `ss` DH alone and is therefore **KCI-forgeable**; it hardens once msg2 lands | encrypted to the recipient's known static key; **nothing identifying is transmitted**, but a **passive** attacker can test candidate (responder private key, initiator public key) pairs against a recording | **full** once both ephemerals are mixed (`ee`) | **yes for the handshake** (the responder contributes a fresh ephemeral) — but the **msg1 (0-RTT) payload is replayable** on its own, exactly as `IK`'s is | — |
| **KX** | two messages (`-> e` / `<- e, ee, se, s, es`), initiator's static pre-shared (`-> s`) | **mutual** — the initiator via `se`, the responder via `es` | payload encrypted after `ee`; the responder's static is sent encrypted in msg2 but with only **weak** forward secrecy — the initiator's alleged ephemeral may have been forged by an active attacker, who could later compromise the **initiator's** static key, decrypt msg2, and learn which responder answered. The initiator's own pre-shared key carries `KN`'s active-attacker caveat | **full** once both ephemerals are mixed (`ee`) | **yes** (responder contributes a fresh ephemeral) | — |
| **IN** | two messages (`-> e, s` / `<- e, ee, se`) | **initiator only** — authenticated via `se`; **the responder is never authenticated** | payload encrypted after `ee`; **the initiator's static identity is sent in the clear in msg1 (before any DH) and is exposed to a passive eavesdropper** — the weakest identity exposure of any pattern this crate ships. The responder's identity is unverified, so its own sends have only **weak** forward secrecy until it receives a transport message | **full** once both ephemerals are mixed (`ee`) | **yes** (responder contributes a fresh ephemeral) | — |

Notes:

- `N`, `K`, `Kpsk0`, and `X` are **one-way seals** (a single message, no response). They
  provide no replay protection and only sender-side forward secrecy; they are
  intended for encrypting data at rest to a known public key (for example, sealing a
  per-pair PSK to a device's own Secure Enclave key). Because there is no recipient
  ephemeral, compromise of the recipient's static private key exposes past payloads.
- `X` is a **one-way, sender-authenticated seal with sender-identity hiding**. Like `K`
  it authenticates the sender via the static–static `ss` DH, but where `K` pre-shares
  *both* statics out of band, `X` pre-knows only the recipient's static (`<- s`) and
  transmits the **sender's** static **encrypted in-band** (after `es` keys the cipher),
  so the sender's identity is hidden from a passive eavesdropper. Its single message is
  the same token sequence as `IK`'s msg1 with no responder reply.
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

- `NX` and `XN` are the **half-authenticated** `XX` variants: one side has no static
  key at all. In `NX` the **initiator** is unauthenticated, so any anonymous caller can
  make the responder identify itself; in `XN` the **responder** is unauthenticated, so
  the initiator hands over its identity without knowing who received it. Both are
  therefore vulnerable to an active man-in-the-middle **impersonating the anonymous
  side** — the authenticated half is genuinely authenticated, the other half is not
  there to be.

- `KN`, `KK` and `KX` **pre-share the initiator's static** (`-> s`), which means it is
  never transmitted — **not** that it is private. The specification distinguishes two
  cases here and so should we. For `KN` and `KX` it is an **active** attacker: one who
  impersonates the initiator without holding its private key and later obtains a
  candidate for that **private** key can confirm the guess. For `KK` it is a
  **passive** attacker: one who records a handshake can test candidate **(responder
  private key, initiator public key) pairs**. Different attacker, different secret.

- `KK` is the **zero-RTT** pattern — the only interactive one here whose first message
  already carries an encrypted payload — and that payload is both **KCI-vulnerable**
  (its authentication is the static–static `ss` DH, forgeable by anyone holding the
  responder's private key) and **replayable** (nothing of the responder's contributes
  to msg1). This is the same warning the one-way `K` row carries, for the same reason,
  and it applies to `IK` and `IKpsk1`'s msg1 payloads too. Both properties harden once
  msg2 lands.

- **The `K`/`I` responder caveat.** For every pattern whose name begins with `K` or
  `I` — `KN`, `KK`, `KX`, `IN`, and the already-shipped `IK`, `IKpsk1` and `IX` — the
  responder is only guaranteed **weak** forward secrecy for the transport messages it
  sends until it receives a transport message from the initiator. The initiator's
  static is either pre-shared or arrives early, so the responder starts sending before
  it has evidence binding the initiator's ephemeral to a key it has verified. It does
  **not** apply to the one-way `K`/`Kpsk0`, whose responder never sends.

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
| Noise handshake KATs (**P-256 / BLAKE2b**) | all **seventeen** patterns | frozen, replayed byte-for-byte (handshake ciphertexts + handshake hash + transport) |
| Noise handshake KATs (**P-256 / SHA-256**) | patterns `N` / `IKpsk1` / `XX` | frozen, replayed byte-for-byte |
| Noise handshake KATs, **third-party** (`cacophony`) | 17 patterns × {`25519`, `448`} × ChaChaPoly × {BLAKE2b, BLAKE2s, SHA256, SHA512} — **136** vectors | frozen, replayed byte-for-byte (handshake ciphertexts + recovered payloads + revealed statics + handshake hash + every transport message); **every pattern additionally replayed in the responder role** on all eight suites — 136 initiator + 136 responder = **272** tests. The thirteen interactive patterns pin responder-written bytes; the four one-way patterns have no responder write, so theirs pin the recipient read path and its transport receives. See `tests/vectors/cacophony/PROVENANCE.md` |
| FIPS 180-4 SHA-256 digests | `""`, `"abc"`, the 448-bit message | NIST, pinned as hex |
| RFC 4231 HMAC-SHA-256 | cases 1, 2, 3, 6 | RFC 4231 §4, pinned as hex |
| FIPS 180-4 SHA-512 digests | `""`, `"abc"`, the 896-bit message | NIST, pinned as hex |
| RFC 4231 HMAC-SHA-512 | cases 1, 2, 3, 6 | RFC 4231 §4, pinned as hex |
| RFC 7693 BLAKE2s digest | `"abc"` | RFC 7693 Appendix B, pinned as hex |
| HMAC-BLAKE2s | RFC 4231 inputs 1, 2, 3, 6 | **not** standards-body vectors — none exist for HMAC-BLAKE2; cross-generated and agreed by two implementations independent of `cryptoxide` |
| Noise interop, **X25519** | patterns `N` / `IK` / `XX` | byte-for-byte agreement with `snow`, live (unfrozen). Runs in **`hiss-interop`** — a weekly cron plus `workflow_dispatch` — **not** under `cargo test` and not a release gate |
| Noise round-trip, **X448** | pattern `XX` | hiss↔hiss self round-trip; `snow` has no `448` resolver, so no live interop is possible |
| Negative / boundary sweeps | per-pattern, deterministic | every-byte tamper, every-prefix truncation, over-length, ciphertext bit-flip, replay, out-of-order, wrong-PSK → all rejected |

The Wycheproof corpora are third-party authoritative. The negative sweeps are
generated deterministically (each driver runs a genuine handshake that must complete
first, so the tests are non-vacuous).

> **Provenance of the Noise KATs (read this).** There are two corpora here and they
> are not equally strong.
>
> The **P-256** corpora — BLAKE2b and SHA-256 — are **"agreement with snow"**: they
> assert byte-for-byte equality with the [snow](https://crates.io/crates/snow)
> reference implementation, not with a standards body. That is unavoidable rather
> than lazy: P-256 is **not** a curve in the Noise specification, so no third-party
> P-256 Noise vectors exist anywhere. A latent bug shared with snow would not be
> caught by them. They are regenerated by the `#[ignore]` generators in
> `hiss-interop`; the procedure, and the additions-only discipline that governs
> the resulting diff, are in `hiss-interop/README.md`.
>
> The **`cacophony`** corpus is third-party: 136 frozen vectors over `25519` and
> `448`, from a community corpus neither `hiss` nor `snow` produced, acquired from
> `snow`'s package and verified byte-identical to the copy in the Cacophony Haskell
> implementation's own repository. The assertions are stricter than `snow`'s own
> harness, which does not even deserialize the `handshake_hash` field. For **X448**
> this is the only cross-implementation check that exists at all: `snow`'s default
> resolver returns `None` for `448`, so `snow` skips every `448` vector it ships.
>
> Scope that claim honestly: these are **third-party relative to `snow`**, not
> standards-body vectors. `hiss` did not audit the Cacophony implementation and its
> generation was not reviewed here. What they buy is agreement with a *second,
> independent* implementation. `tests/vectors/cacophony/PROVENANCE.md` records the
> pins, the filter and the licence chain.
>
> Residual: these replays call only the plain readers; the `read_message_N_with`
> per-peer-PSK and verification-closure variants are never exercised against
> third-party vectors.
>
> The primitives underneath are separately anchored: the SHA-256, SHA-512 and
> BLAKE2s rows above are NIST / RFC 4231 / RFC 7693 vectors — except HMAC-BLAKE2s,
> for which **no standards body publishes vectors at all**. RFC 7693 defines no
> HMAC and Wycheproof ships no HMAC-BLAKE2 file, so those four values are
> cross-generated and agreed by two implementations independent of `cryptoxide`.
> They are not presented as standards-body vectors. The stronger check on that path
> is the `cacophony` corpus, which runs `Blake2s::hmac` on every `mix_key` of 22
> handshakes against an implementation `hiss` did not write.

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
  `R: CryptoRng` (`rand_core` 0.10, re-exported as `hiss::rand_core`).
  **You must supply a cryptographically secure RNG.**
- With `rand` 0.10, `SysRng` — the system source — is fallible (`TryRng`, with
  `Error = SysError`) and so does **not** implement the infallible `CryptoRng`
  the bound wants; seed a real CSPRNG, e.g. `rand::make_rng::<StdRng>()`.
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
  not standards-body vectors. X25519 and X448 now carry frozen **third-party**
  (`cacophony`) vectors, but "third-party" there means *independent of snow*, not
  *from a standards body* — nobody in this chain audited the Cacophony
  implementation.
- **Upstream constant-time dependency.** Constant-time P-256 rests on `eccoxide`'s
  released crates.io `0.4`; the property is only as strong as that upstream backend,
  which `hiss` does not independently verify.
- **Unproven Enclave path.** The Apple Keychain seal/store/load path is not exercised
  in CI (requires codesigned binary + Secure Enclave hardware).

---

*This document describes the security posture of `hiss` as of `0.1.x`. If you find a
discrepancy between this document and the code, that is itself a bug worth reporting.*
