# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
