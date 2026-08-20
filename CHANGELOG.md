# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.0] - 2026-08-20

### Added

- **`hiss::noise::AesGcm`**, the Noise specification's second cipher — §12.4
  `AESGCM`: AES-256-GCM, a 96-bit nonce of four zero bytes and the
  **big**-endian counter, a 128-bit tag appended. `NAME = "AESGCM"`,
  `TAG_SIZE = 16`, so a `noise!` declaration can name it and speak
  `Noise_<pattern>_<curve>_AESGCM_<hash>`. Purely additive: no existing
  protocol name, wire size or handshake hash moves, and `ChaChaPoly` remains
  what the Quickstart, the examples and `seal.rs` use. Backed by
  `cryptoxide::aes_gcm`, released in cryptoxide 0.6.3, which becomes the
  floor. No hiss feature gates it: the crate's rule that no feature turns API
  on or off stands, cryptoxide has no dependencies of its own to save, and a
  suite type that only sometimes exists would be the first name in the
  macro's respelling list that could make an emitted `# Usage` doctest fail
  to compile in a consumer.

  What stands behind it, three legs. The third-party `cacophony` corpus: the
  160 `AESGCM` vectors that mirror the 160 `ChaChaPoly` ones — all twenty
  patterns over `{25519, 448} × {BLAKE2b, BLAKE2s, SHA256, SHA512}` — replayed
  in **both roles** by the same harness (`tests/noise_cacophony.rs`, now 656
  tests from a 320-vector corpus). The 66 Wycheproof AES-GCM vectors matching
  §12.4's parameters, run against the primitive as a library unit test,
  ciphertext *and* tag pinned on every valid vector and every invalid one
  rejected. And 40 live `snow` interop handshakes in `hiss-interop` — `N`,
  `NN`, `XX`, `IK`, `Kpsk0` × all four hashes × both role assignments —
  against RustCrypto's independently written AES-GCM, four transport messages
  per direction. The corpus's six-message vectors are what pin the nonce byte
  order: counter 0 encodes identically little- and big-endian, so a
  wrong-endian `AESGCM` agrees with everyone through the handshake and first
  diverges at transport message 2 (one-way patterns; 4 for interactive
  ones). Bespoke tests cover what no corpus reaches: every single-bit tag
  flip, truncation, AD and counter binding, and the failure-path zeroing.

  One thing worth knowing. cryptoxide's AES-GCM **verifies the tag before
  writing any plaintext** — pinned by a test — which is the opposite of
  `ChaChaPoly`'s decrypt-then-verify, so `AesGcm` zeroes `output` on failure
  not to scrub unverified plaintext but so a reused buffer cannot hand a
  caller the *previous* message; `Cipher::decrypt`'s documented contract now
  states the mechanism-neutral rule both ciphers meet.

- **`hiss-macros`: `AesGcm` joins `HISS_SUITE_TYPES`**, so a `noise!`
  declaration naming it gets a compiled `# Usage` doctest rather than an
  uncompiled sketch. Shipped as `hiss-macros` 0.3.2, which hiss 0.4.0
  requires — a hiss carrying `AesGcm` over an older macro crate would
  document it as a sketch. `scripts/downstream-build.sh`'s `IKpsk0` arm now
  spells `AesGcm`, so every suite type stays covered by the sketch-degrade
  guard.

- **Benchmarks.** `benches/noise.rs` measures `transport_1KiB` over both
  ciphers; `hiss-interop/benches/comparison.rs` gains `AESGCM` arms for hiss
  and `snow`, plus encrypt-only and decrypt-only groups, and
  `hiss-interop/.cargo/config.toml` pins the snow arms to RustCrypto's
  opt-in aarch64 hardware paths so the comparison is against its best. A
  second interop bench, `suite_25519_aesgcm_sha256`, fixes one suite end to
  end — `Noise_*_25519_AESGCM_SHA256`, `N`/`IK`/`XX` handshakes and transport
  at 64 B, 1 KiB, 16 KiB and 65519 B — hiss against snow, with throughput.

### Changed

- **Breaking: `hiss::noise::Cipher` takes an expanded key.** The trait gains an
  associated `type Key: Send + Sync + 'static` and a
  `fn key(&[u8; 32]) -> Self::Key`, and `encrypt`/`decrypt` now take
  `key: &Self::Key` where they took `&[u8; 32]`. The AEAD's key schedule
  therefore runs where a Noise key is *created* — each `MixKey` and
  `MixKeyAndHash`, the `Split`, every `Rekey()` — instead of once per message.
  Two opaque public types come with it, `ChaChaPolyKey` and `AesGcmKey`. What
  breaks: an out-of-tree `Cipher` implementation, and any direct call to
  `ChaChaPoly::encrypt(&[u8; 32], …)`. Nothing else — `hiss-macros` reaches
  `Cipher` only through `TAG_SIZE` and is unaffected, so it stays at 0.3.2.

  Why: `AesGcm` re-expanded the AES-256 round keys and derived the GHASH
  subkey for every single message. On an M-series Mac that is ~117 ns against
  ~160 ns for the rest of a 1 KiB seal. Hoisting it took `benches/noise.rs`'s
  `transport_1KiB` round trip from 594 ns to 365 ns, and in `hiss-interop`'s
  one-suite bench the 64-byte round trip from 314 ns to 84 ns and the 1 KiB one
  from 611 ns to 372 ns. `ChaChaPoly` has no schedule to hoist and does not
  move (1.96 µs against 2.03 µs, inside the noise); its `CipherState` is still
  exactly 48 bytes, pinned by a test.

  It is a scrubbing fix as much as a speed one. cryptoxide zeroes the round
  keys and `H` in its own `Drop` impls, but with ordinary stores — built under
  fat LTO, every one of those stores is gone from the disassembly, which means
  the pre-0.4.0 per-message schedule was scrubbed by nothing at all in an LTO
  build. `Cipher::Key` now *contracts* that a key scrubs itself on drop, and
  `AesGcmKey` meets it by running cryptoxide's destructor and then wiping the
  bytes itself with volatile writes.

  The price is memory, and it is not small: a `CipherState<AesGcm>` is 528
  bytes on `aarch64` and 992 on the portable fixsliced path, against 48 for
  `ChaChaPoly`. On a `P256`/`AESGCM`/`SHA256` `IK`, a `Transport` measures
  1280 / 2200 bytes against 312 over `ChaChaPoly`, and a ratcheting
  `DatagramRecv` — which retains two epoch keys — 1040 / 1992 against 104.

  Nothing on the wire moves: protocol names, message sizes, handshake hashes
  and ciphertexts are untouched, and every frozen vector, all 656 cacophony
  replays and the live `snow` interop pass byte-for-byte unchanged. That is
  the equivalence proof for the change.

- **cryptoxide requirement `>=0.6.0, <0.7` → `>=0.6.3, <0.7`**, for
  `aes_gcm`. 0.6.3 is inside the previous range, so no consumer is cut off.

- **`tests/vectors/cacophony/cacophony.json` grows from 160 to 320 vectors** —
  the `AESGCM` half of the corpus under the same pins and the same filter
  extended to both ciphers. Every vendored vector is replayed, and a new
  coverage test asserts the corpus is exactly the instantiated
  pattern × suite matrix, so a vector nothing replays cannot sit in the KAT
  directory unnoticed.

### Removed

- **`hiss-aesgcm-lab/`** and its workflow — the temporary, out-of-workspace
  crate that validated AES-GCM against a `rev`-pinned unreleased cryptoxide.
  Its exit condition fired with cryptoxide 0.6.3; its `Cipher` impl, vectors,
  tests and bench arms moved into hiss and `hiss-interop` as described above.
  Repository infrastructure only — nothing a consumer of the crate resolved.

## [0.3.2] - 2026-08-14

### Added

- **The staged msg1 read: `read_message_1_intro` → mid-state → `complete()`.**
  A first message whose token sequence ends `…, s, ss` (IK's shape — a msg1
  with a *trailing* `psk`, IKpsk1's shape, is deliberately excluded: its
  `complete()` would need the PSK re-supplied mid-read, and the per-peer
  lookup closure already serves it) now also generates a suspending read
  pair alongside the untouched one-shot and `_with` styles: `read_message_1_intro` processes the message through its
  `s` token — exactly one DH, `es` — returning the peer's **claimed** static
  by value together with a `{Pattern}{Role}Msg1Intro` mid-state that owns
  the message's un-read tail as a fixed-size array (`MSG1_INTRO_TAIL`, a
  `WireSize`-derived const: the declared payload plus its tag). The
  mid-state is a self-contained owned value — no borrow of the input,
  nothing re-supplied later, `#[must_use]`, deliberately not `Clone` —
  built to be parked across event-loop turns while the application judges
  the identity (exposed again via `claimed_static()`); dropping it abandons
  the handshake at exactly the DH already paid, with scrubbing inherited
  from the handshake state's own `Drop` impls. `complete(self)` pays the
  proving `ss`, decrypts the payload, and verifies the tag, returning
  exactly what the one-shot read would have — transcript byte-identical —
  or, on failure, consuming the state so a failed read cannot be retried,
  even by mistake.

  Why: a synchronous identity hook (the `Verify` closure) cannot serve a
  staged accept that **suspends** on the claimed identity — think
  human-in-the-loop accept decisions parked across turns — without
  re-paying `es` afterwards, and a downstream DoS cost ladder priced at
  "1 DH to inspect, 2 cumulative to authenticate" (slither's, and anyone
  else's shaped like it) cannot absorb a 3-DH accepted read.

  What stands behind it: no new runtime crypto — intro+complete is the
  one-shot read's exact `support` call sequence split across two methods —
  plus a seed-twin equivalence test (same claimed static, same payload,
  byte-identical msg2 and session id), DH-cost pins through a counting
  provider (intro = 1; reject-by-drop = 1 total; complete = 2), a
  tampered-tail test (intro passes, `complete` fails and consumes), a
  one-way `X` staged read completing into the `Transport`, and the
  Cacophony IK corpus replayed **through the split path** on all eight
  suites — a third-party oracle that suspension leaves no trace in the
  transcript. Qualifying patterns' emitted `# Usage` docs gain a third,
  staged walkthrough, compiled downstream by a fifth `downstream-build.sh`
  arm (payload shape) and the existing IKpsk0 arm (psk shape).

- **`DatagramSend::next_counter()`** — a `&self` accessor for the counter the
  next **successful** `encrypt_next` will seal under (the current cipher-state
  `n`). Until now that counter was only learnable from `encrypt_next`'s return
  value, which is one seal too late for a protocol whose cleartext header
  carries the counter *and* is the seal's associated data: the header must be
  built first, so downstream code was forced to mirror hiss-owned state and
  assert it back into agreement. The accessor's guarantees are documented and
  pinned by tests: it equals the counter the following successful seal
  returns — across many seals and across an epoch-ratchet boundary (the
  ratchet changes the key, never the counter) — a failed seal leaves it
  unchanged, and at `u64::MAX` it still reads `u64::MAX` while the seal
  itself refuses with `NonceOverflow`. Read-only: the counter stays owned by
  `hiss`, and nothing lets a caller choose it.

- **Per-curve canonical-encoding pins.** Every shipped public-key type already
  exposes its canonical encoding through `AsRef<[u8]>` — P-256's 65-byte
  uncompressed SEC1 form (any accepted input, compressed included, normalises
  to it at construction), the raw 32/56-byte u-coordinates for X25519/X448,
  and the 32-byte RFC 8032 form for Ed25519. Those octets are wire-relevant
  the moment a downstream protocol keys a MAC over them or compares them for
  tie-breaks, so each curve now carries a test pinning the encoding —
  length, P-256's leading `0x04` tag, and the exact bytes for an
  authoritative fixed key (RFC 7748 §6.1/§6.2, RFC 8032 §7.1, RFC 6979
  A.2.5) — so a refactor that changes the encoding trips a test instead of
  silently re-keying a downstream MAC.

### Fixed

- **`SymmetricState` now zeroes `h` on drop, as its comment always promised.**
  The `Drop` impl's comment declared the handshake hash zeroed "for defence in
  depth", but the code only zeroed `ck` — the cipher keys already self-scrub.
  `h` is not secret (it is the public transcript hash), so nothing was
  exposed; the code merely did less than it said. It now does what it says.

## [0.3.1] - 2026-08-13

No library changes. README corrections for the crates.io page, and additional
third-party test coverage pinning every `pskN` placement against the
cacophony vectors.

## [0.3.0] - 2026-08-13

### Added

- **`hiss::noise::Sha256`**, a second `Hash` implementation — `NAME = "SHA256"`,
  HASHLEN 32 — so a `noise!` declaration can name it and speak
  `Noise_<pattern>_<curve>_ChaChaPoly_SHA256`. Purely additive: no existing
  protocol name, wire size or handshake hash moves, and `Blake2b` remains what
  the Quickstart, the examples and `seal.rs` use.

  What stands behind it: FIPS 180-4 digest vectors and RFC 4231 HMAC-SHA-256
  cases 1/2/3/6 for the primitive; frozen `snow`-generated KATs over
  `P256 / ChaChaPoly / SHA256` for `N`, `IKpsk1` and `XX`
  (`tests/vectors/noise/p256_chachapoly_sha256.json`); and live `snow` interop
  on `XX` in both directions. `IKpsk1` is the load-bearing one — at HASHLEN 32
  its 35-byte protocol name is the first in this crate to exceed HASHLEN, so
  the hashing branch of `SymmetricState::initialize` is now checked against an
  oracle rather than only a synthetic unit test.

- **`scripts/downstream-build.sh` now fails when a `noise!` walkthrough
  degrades to an uncompiled sketch.** A suite type missing from the macro's
  `HISS_SUITE_TYPES` list silently turns the emitted `# Usage` doctest into a
  ` ```text ` sketch; rustdoc then collects one doctest fewer and every gate,
  including `cargo test --doc`, stays green. The gate now greps the downstream
  crate's rendered docs for the sketch marker.

- **Third-party Noise known-answer vectors (`cacophony`).** 136 frozen vectors
  over `{25519, 448} × ChaChaPoly × {BLAKE2b, BLAKE2s, SHA256, SHA512}` × all
  seventeen patterns, replayed byte-for-byte in `tests/noise_cacophony.rs` —
  **every pattern in both roles on all eight suites, 136 initiator + 136
  responder replays, 272 tests**.

  Two things about this are worth stating plainly. It is the **first
  third-party Noise-level coverage in the crate**: the P-256 corpus is
  agreement-with-`snow` by necessity, because P-256 is not in the Noise
  specification and no third-party P-256 vectors exist. And **X448 had no
  cross-implementation validation of any kind before this** — `snow`'s default
  resolver returns `None` for `448`, so `snow`'s own harness skips every `448`
  vector it ships. That extends to hiss's **responder** path on X448, which
  nothing checked before: the responder-written bytes for the seven interactive
  patterns, and the recipient read path for the four one-way ones (which have
  no responder write, so their replay pins reads and transport receives rather
  than wire bytes). The assertions are also stricter than `snow`'s: they pin
  the `handshake_hash`, a field `snow`'s deserializer does not even declare.

  Provenance, pins and the licence chain are in
  `tests/vectors/cacophony/PROVENANCE.md`. "Third-party" there means
  *independent of `snow`* — not vectors from a standards body.

- **The six missing fundamental patterns: `NX`, `XN`, `KN`, `KK`, `KX`, `IN`.**
  With them `hiss` ships **all fifteen** of the Noise specification's
  fundamental patterns (twelve interactive plus the three one-way) alongside its
  two PSK variants — seventeen markers in `hiss::noise::pattern`. Each token
  sequence is spec §7.5 verbatim.

  Coverage lands with them rather than after them: all six are replayed in
  **both roles** against the third-party `cacophony` corpus on all eight suites
  (the vendored subset grows 88 → 136 vectors, 176 → 272 tests), and all six
  join the frozen `snow`-generated P-256 corpus (11 → 17 vectors, 14 → 20
  tests).

  Two carry warnings worth reading before use. **`IN` transmits the initiator's
  static key in the clear** in msg1, before any DH — a passive observer learns
  the initiator's identity outright, the weakest identity exposure of anything
  here. **`KK` is zero-RTT**, so its msg1 payload is authenticated only by the
  static–static `ss` DH (KCI-forgeable) and is replayable until msg2 lands.
  `SECURITY.md` carries the full per-pattern table.

- **`hiss::noise::Blake2s`**, a third `Hash` implementation — `NAME =
  "BLAKE2s"`, HASHLEN 32. Purely additive.

  What stands behind it: RFC 7693 Appendix B's `BLAKE2s("abc")` digest for the
  primitive, four HMAC cases cross-generated against two implementations
  independent of `cryptoxide` (no standards body publishes HMAC-BLAKE2
  vectors), the 34 BLAKE2s `cacophony` handshakes above, and live `snow`
  interop on `XX` in both directions. One of those handshakes is load-bearing:
  `Noise_IKpsk1_25519_ChaChaPoly_BLAKE2s` is 37 bytes, longer than HASHLEN 32,
  so the hashing branch of `SymmetricState::initialize` now has a
  **third-party** oracle where SHA-256 got only a `snow`-agreement one.

- **`hiss::noise::Sha512`**, a fourth `Hash` implementation — `NAME =
  "SHA512"`, HASHLEN 64. Purely additive.

  What stands behind it: FIPS 180-4 digest vectors and RFC 4231 HMAC-SHA-512
  cases 1/2/3/6 for the primitive, the 34 SHA-512 `cacophony` handshakes, and
  live `snow` interop on `XX` in both directions.

  With `Blake2b`, `Sha256` and `Blake2s` this completes the Noise
  specification's **four official hashes** (§12.5 SHA256, §12.6 SHA512, §12.7
  BLAKE2s, §12.8 BLAKE2b); `ChaChaPoly` remains the only cipher. It also gives
  `X448` a second 512-bit hash to pair with, as §13 recommends.

- **`scripts/downstream-build.sh` now spells every `HISS_SUITE_TYPES` entry.**
  The sketch-degrade guard above only fires for a suite type some arm actually
  writes, so entries no arm spelled were guarded by nothing — which was all
  four arms being `X25519`, leaving `P256` and `X448` unchecked. The four arms
  now cover three curves, one cipher and four hashes between them, with no
  fifth arm and no extra build time. This is also the first time the emitted
  walkthroughs are type-checked on a curve other than `X25519`.

### Fixed

- **`SECURITY.md`'s payload-security table understated three shipped patterns.**
  These are corrections to documentation of behaviour that has always been this
  way — the defects predate this release and did not arrive with the new
  patterns.

  `IK` and `IKpsk1` were listed with unqualified replay resistance ("yes — the
  responder contributes a fresh ephemeral"). That is true of the completed
  handshake but not of the **msg1 (0-RTT) payload**, which `hiss` ships as a
  first-class feature via the `[N]` suffix: per Noise §7.7 that payload is
  source 1 / destination 2 — authenticated only by the static–static `ss` DH, so
  **KCI-forgeable**, and **replayable**, since nothing of the responder's
  contributes to it. For `IKpsk1` the PSK does not help: an attacker replays
  recorded ciphertext and needs no PSK knowledge. `NK` and `XK` (msg1 = source 0
  / destination 2) inherit the replay half and not the KCI half, and their rows
  now say so; `Kpsk0`'s row now carries the same KCI note `K`'s always had,
  since it is `K`'s msg1 with `psk` prepended.

- **The §7.5 `K`/`I` responder caveat was missing for `IK`, `IKpsk1` and `IX`.**
  Their forward-secrecy cells said "**full** once both ephemerals are mixed",
  which understates it: for every pattern whose name begins with `K` or `I`, the
  responder has only **weak** forward secrecy for the transport messages it
  sends until it receives one from the initiator. Now stated once, in the notes,
  covering all seven such patterns.

- **`NN`'s confidentiality claim was unscoped.** It read "a passive observer
  cannot read the traffic", which a payload declared on msg1 falsifies — `-> e`
  closes before any DH, so that payload travels in cleartext (§7.7 destination
  0, the property `tests/noise_macro_shapes.rs` already pins). Now scoped to
  msg2 onward.

### Removed

- **`Ed25519` is no longer a Noise DH curve.** `impl DhCurve for Ed25519`,
  `SoftwareEd25519PrivateKey::dh`, and the `DhProvider` / `DhProviderAsync`
  implementations for `Ed25519` on both shipped providers are gone.

  **Why.** `Noise_<pattern>_Ed25519_<cipher>_<hash>` is in no Noise registry —
  the specification's DH list is `25519` and `448`, and the wiki's unofficial
  list is `secp256k1`, `FourQ`, `P256`, `P384`, `P521`. A protocol built on it
  interoperated with nothing, and the agreement underneath was the
  Ed25519→X25519 birational map, which `hiss` already ships under its
  registered name. The removal also makes a sentence in `lib.rs` true that was
  false before it: Ed25519 really is reserved for identity and signing now,
  enforced by the type system rather than by convention.

  **Migration.** Replace the curve with `hiss::noise::X25519` — the same
  agreement, a registry-valid protocol name, and covered by frozen third-party
  KATs as of this release. If you were calling `SoftwareEd25519PrivateKey::dh`
  or `DhProvider::<Ed25519>::dh` directly, use `SoftwareX25519PrivateKey` /
  `DhProvider::<X25519>`. Note that the X25519 private scalar is **not** the
  Ed25519 seed, so keys do not carry over — generate or import an X25519 key.

  **Ed25519 signing is unaffected**: `SigningProvider<Ed25519>` /
  `SigningProviderAsync<Ed25519>`, `Ed25519PublicKey::verify`,
  `SoftwareEd25519PrivateKey::{generate, from_seed, sign, seed}` and the Apple
  sealed-seed path are all unchanged. `hiss::curve::ed25519::Ed25519` stays
  exported; what changed is that it no longer satisfies `DhCurve`, so naming it
  as a suite's curve is a compile error.

### Changed

- **`cryptoxide` moved from `>=0.5.1, <0.6` to `>=0.6.0, <0.7`, and `hiss` now
  carries its own HMAC-BLAKE2.** Consumer-visible as a dependency floor, not as
  an API change: nothing in `hiss`'s public surface moves, and no `cryptoxide`
  type appears in any `hiss` signature. A consumer pinning `cryptoxide` 0.5.x
  elsewhere in their graph now gets two majors of it, or a resolution failure.

  cryptoxide 0.6.0 deleted the `mac` module and the generic `Hmac<D: Digest>`,
  replacing them with `hmac::Context<A: Algorithm>` — for which it ships
  `Algorithm` impls covering exactly `Sha1`, `Sha256` and `Sha512`. There is no
  HMAC-BLAKE2 of either width, and the orphan rule forbids implementing
  cryptoxide's trait for cryptoxide's type. So `src/noise/hash.rs` now holds a
  private module with a marker type per BLAKE2 variant, and `hiss` owns the
  RFC 2104 key schedule behind `Blake2b::hmac` and `Blake2s::hmac` — the key
  padding, the ipad/opad derivation and the inner/outer contexts — which it
  previously delegated. `Blake2b` is Noise's recommended hash, so this is the
  most load-bearing code in the change. HMAC-SHA-256/512 still delegate to
  cryptoxide; the four `hash`/`hash_two` implementations moved to the
  `hashing::*` submodules, which is a rename.

  Nothing about the protocol moves: no wire bytes, no protocol name, no
  handshake hash. The 292 frozen known-answer replays (272 `cacophony` +
  20 P-256) pass byte-identical, and live interop against `snow` is unchanged
  across all four hashes.

  **What stands behind it.** RFC 4231 cases 1/2/3/6 for HMAC-SHA-256 and
  HMAC-SHA-512, the same four inputs cross-generated for HMAC-BLAKE2s, and
  RFC 6979 A.2.5 for the P-256 HMAC-DRBG, whose digest and HMAC calls moved
  with everything else. New for this change: `blake2b_hmac_cross_checked`
  gives HMAC-BLAKE2b the cross-generated coverage BLAKE2s already had —
  values agreed on by Python's `hmac` over `hashlib.blake2b` and RustCrypto's
  `hmac::SimpleHmac` over `blake2::Blake2b512`, neither of which shares an
  author with `hiss`. Its case 6 closes a real gap: a key longer than
  BLAKE2b's 128-byte block reaches the hash-the-key branch, and **no handshake
  can get there** — `mix_key` only ever keys HMAC with a 64-byte chaining key,
  so none of the 292 replays touches it. The branch is reachable only through
  the public `Hash` trait. `tests/primitive_diag.rs`'s hand-rolled ipad/opad
  oracle grew a matching 131-byte-key case.

  No MSRV change: cryptoxide's own MSRV is 1.78, well under `hiss`'s 1.96.

- **`rand_core` moved from 0.9 to 0.10 — a breaking change to the public API.**
  `rand_core`'s traits are named in `hiss`'s public bounds, so this is not an
  internal dependency bump: an RNG handed to `EphemeralOnly::new`,
  `Psk::generate` or any `*PrivateKey::generate` must now implement the
  **0.10** traits. Two `rand_core` majors in one graph are two unrelated
  traits with no bridging impl, so a consumer still on `rand = "0.9"` gets an
  unsatisfied `CryptoRng` bound rather than a version error. The fix is
  `rand = "0.10"`, which is what `cargo add rand` has resolved to since
  February — the pairing the README advertises was the one a new consumer
  could *not* get.

  Nothing about the protocol moves: no wire bytes, no protocol name, no
  handshake hash. The 292 frozen known-answer replays (272 `cacophony` +
  20 P-256) pass byte-identical, because they are driven by a scripted RNG
  rather than by `rand`.

  **The bounds simplified while passing through.** 0.10 inverts the trait
  hierarchy — `CryptoRng: Rng` where 0.9 had `CryptoRng: RngCore` — so the
  23 sites spelled `RngCore + CryptoRng` (18 `EphemeralOnly` provider impls
  plus five `generate` constructors) are now plain `R: CryptoRng`. The
  conjunction was always redundant; this only changes how it is spelled, and
  `&mut R` still satisfies it via `rand_core`'s `DerefMut` blankets.

  Two call-site renames a consumer will meet in their own code, not in
  `hiss`'s API: `SeedableRng::from_os_rng()` is removed in favour of
  `rand::make_rng::<R>()`, and `rand::Rng` — the extension trait — is now
  `rand::RngExt`. `hiss`'s examples, benchmarks and tests moved with them.
  Custom RNGs are affected more sharply: `RngCore` survives only as a
  deprecated method-less stub, so an `impl RngCore for MyRng` no longer
  compiles at all. Implement `TryRng` with `Error = Infallible` (plus the
  `TryCryptoRng` marker) and let the blankets supply `Rng`/`CryptoRng` — the
  shape the test suite's `ScriptedRng` now uses.

- **`hiss::rand_core` — the crate now re-exports the `rand_core` it compiled
  against.** Public bounds over a foreign trait were previously unnameable: a
  consumer writing their own generic wrapper around `EphemeralOnly` had to
  read `hiss`'s manifest to learn which `rand_core` to declare, and getting it
  wrong surfaced as an unsatisfied trait bound with no mention of versions.
  Writing `hiss::rand_core::CryptoRng` now makes the mismatch impossible to
  express. This is the change that would have made the 0.9-vs-0.10 break above
  diagnosable from the compiler output alone, which is why it lands with it.

- **The `snow` interop suite moved to a new `hiss-interop` crate, and `snow`
  left `[dev-dependencies]`.** Dev-only in effect — no published API, wire
  format or vector changes — but two consequences are worth stating plainly.

  **The dependency graph a contributor compiles drops 63 packages, 195 → 132**
  (32%): the whole RustCrypto stack (`aes-gcm`, `curve25519-dalek`, `p256`,
  `ecdsa`, `elliptic-curve`, `sha2`, `blake2`, `chacha20poly1305`, …), `ring`,
  and ten `windows-*` crates. That makes the README's "production cryptography
  here is `cryptoxide` and `eccoxide`, nothing else" true of what you build,
  not only of what ships.

  **And the interop suite no longer runs on every `cargo test`.** It runs
  weekly, on pushes to `main`, and on `workflow_dispatch`, via the new
  `Interop` workflow — so per-commit coverage genuinely shrinks by those 35
  tests. What did *not* shrink is what they were checking: hiss's conformance
  is pinned by frozen corpora that need no second implementation at runtime
  (272 `cacophony` replays, 20 P-256 known-answer replays, 26 negative sweeps),
  and those still run everywhere they did before. `snow` agreement is now
  stated for what it is — how the P-256 vectors were *generated*, plus an
  occasional live re-check.

  Also moved: the `#[ignore]` vector regenerators (they link `snow`; the
  replays they feed do not) and the hiss-vs-snow comparison benchmark. hiss
  keeps a hiss-only `benches/noise.rs`, so `cargo bench` remains a meaningful
  release gate. `tests/snow_diag.rs` split in two and the half that stayed is
  now `tests/primitive_diag.rs` — its old name no longer described it.

- **`tempfile` removed from `[dev-dependencies]`.** Unrelated to the above and
  unused: it had zero references in any `.rs`, `.sh` or `.yml` file in the
  repo. It remains in the graph transitively via `proptest`, so this changes
  no resolution — it just stops claiming a direct requirement that was not one.

- **`hiss-macros` moved from `syn = "2"` to `syn = "3"`.** `hiss-macros` is a
  regular dependency, so syn sits in every consumer's build graph — and
  `serde_derive`, `thiserror-impl` and `tokio-macros` all require syn 3
  already, so staying on 2 made a consumer with any of them compile *both*
  majors. The macro's parsing surface (`Ident`, `LitInt`, `Path`,
  `Visibility`, token punctuation, `braced!`/`bracketed!`) has no overlap
  with syn 3.0's breaking changes: the migration is the requirement line, no
  code moved, and the UI-diagnostic snapshots (`tests/ui/`) are byte-stable.
  One duplicate remains out of our hands — `packtool-macro` still parses with
  syn 2.

- **The Apple provider no longer offloads to a tokio runtime; the `*Async`
  provider traits poll in place.** The `cfg(macos/ios)` dependency on `tokio`
  is gone — `hiss` now pulls in no async runtime on any platform.
  `CryptoKeyProviderAsync` / `DhProviderAsync` / `SigningProviderAsync` are
  unchanged in signature and remain the integration point for genuinely
  asynchronous backends; what changed is the contract's fine print:
  implementing them is not a promise to yield, and `AppleSecureEnclave`'s
  async surface now **blocks in place** for the duration of the keychain /
  Secure Enclave call instead of hopping to a blocking pool. Callers on a
  cooperative executor that treated those calls as yield points should treat
  them as they would any other short blocking FFI call — `AppleSecureEnclave`'s
  rustdoc carries the details.

- **The `cryptoxide` `<0.6` ceiling is now documented as load-bearing.** The
  requirement string itself did not move — `"0.5.1"` already meant
  `>=0.5.1, <0.6`. What was missing was the reason: cryptoxide 0.6 deletes
  `src/mac.rs` and the generic `Hmac<D: Digest>`, replacing it with an
  `hmac::Context<A: Algorithm>` that ships exactly `Sha1`, `Sha256` and
  `Sha512` — no HMAC-BLAKE2 of either width. Crossing that bound costs `hiss`
  its own HMAC-BLAKE2 implementation, for both `Blake2b::hmac` and
  `Blake2s::hmac`.

## [0.2.0]

`noise!` is now the only way to drive a handshake. The streaming I/O drivers
are gone.

### Removed

- **`SyncHandshake` and `AsyncHandshake`**, along with their `*Sending` /
  `*Receiving` / `*Transport` state types and the four constructors on
  `Noise` — `sync_initiator`, `sync_responder`, `async_initiator`,
  `async_responder`. Together these were 3,037 lines, about 19% of `src/`.

  Their replacement is the state machine `noise!` generates: one method per
  handshake message, each message a fixed-size `[u8; MSGn_SIZE]`, and no I/O.
  Framing is a `read_exact` of a compile-time constant — see
  `examples/tcp_xx_channel.rs`, which does exactly that over a real socket.

- **The `async-io` feature.** `tokio` leaves `[dependencies]` entirely; it
  remains a macOS/iOS platform dependency for the Secure Enclave offload, and
  a dev-dependency.

### Changed

- **A wrong-length handshake message is now a compile error rather than a
  runtime rejection.** `read_message_N` takes `&[u8; MSGn_SIZE]`, so a short
  or over-long buffer cannot be constructed at the call site. The
  truncation sweeps that asserted the old runtime behaviour are gone; the new
  behaviour is pinned by a `compile_fail` doctest on `noise!`.

- **The whole verification suite now runs through `noise!`.** The frozen
  known-answer vectors, both `snow` interop suites, the negative sweeps, the
  benchmarks and the in-crate unit tests previously exercised the driver, so
  the API users were told to reach for was covered only by a two-test bridge
  on a single pattern. All of it was converted; the oracles (frozen hex,
  `snow`) are unchanged, so the conversion is checked against something
  independent of the code path it replaced.

- **Benchmark numbers are not comparable across this release.** `BenchPipe`
  is gone: hiss and `snow` now both write into flat buffers, removing the I/O
  layer that used to sit inside hiss's measured region only.

### Documentation

- The `noise!` documentation now states that **the declared identifier is the
  Noise pattern name.** It becomes `Pattern::NAME`, which forms the protocol
  name seeding the initial handshake hash, so
  `noise! { pub Channel<X25519, ChaChaPoly, Blake2b> { … } }` produces
  `Noise_Channel_25519_ChaChaPoly_BLAKE2b` — self-consistent, and
  interoperable with nothing.

  Every copy-paste surface in the crate previously demonstrated that mistake
  and now names the type for its pattern: the README and crate-level
  Quickstarts and `examples/quickstart.rs` declare `pub XX`, the
  `AppleSecureEnclave` doctest declares `pub XX`, and
  `examples/tcp_ikpsk1_ceremony.rs` declares `pub IKpsk1` with the
  descriptive name on a `type Ceremony = IKpsk1` alias. The Quickstart's
  declaration is now exactly the one the `snow` interop tests drive.

- The README leads with the Quickstart, and the crate docs do too — it was
  the seventh of eight sections on docs.rs, so a reader passed six sections
  before reaching a line of usable code.

### Known issues

- **`demo/` does not build.** The browser playground is generic over pattern
  *and* curve with dispatch on a runtime selection; `noise!` requires both to
  be concrete. Porting it means monomorphising 11 patterns × 3 curves and
  rewiring the dispatch. It is excluded from the workspace, is not published,
  and is not covered by any release gate.

## [0.1.0]

Initial release.
