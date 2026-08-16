# `hiss-aesgcm-lab`

**Early validation of Noise `AESGCM` against an unreleased cryptoxide.**

This crate exists to answer one question before hiss commits to anything:
*is cryptoxide's new AES-GCM correct as a Noise §12.4 `AESGCM` cipher?*

It is **temporary by construction**. It has an expiry condition (below), and
when that condition is met the crate is deleted, not maintained.

## What this is

An out-of-workspace, unpublished crate that:

- implements hiss's `Cipher` trait over `cryptoxide_git::aes_gcm` — a
  **renamed, `rev`-pinned git dependency** on cryptoxide master
  (`src/lib.rs`);
- replays 136 third-party `AESGCM` known-answer vectors through hiss in
  **both roles** — 272 replays (`tests/cacophony_aesgcm.rs`);
- runs the applicable Wycheproof AES-GCM subset against the primitive
  (`tests/wycheproof_aesgcm.rs`);
- drives **live** hiss↔`snow` handshakes in both directions across four
  hashes and five patterns (`tests/snow_aesgcm.rs`);
- benchmarks Noise transport throughput, hiss/AESGCM against snow/AESGCM with
  hiss/ChaChaPoly as a reference arm (`benches/aesgcm_comparison.rs`).

## What this is **not**

- **Not shipped surface.** `publish = false`, excluded from hiss's packaged
  `.crate` (root `Cargo.toml`'s `[package] exclude`), and hiss's own
  `[dependencies]` and `[dev-dependencies]` are unchanged. Nothing a consumer
  of `hiss` resolves is affected by this directory existing.
- **Not a release gate.** No gate in `CLAUDE.md`'s table depends on it, and
  `cargo test` at the repo root builds nothing here. It is an *occasional
  check*, in the same category as `hiss-interop`.
- **Not a `[patch]`.** hiss keeps resolving the **released** cryptoxide from
  the registry; only this crate's `Cipher` impl sees master. See below.
- **Not a change to `hiss::noise`.** hiss exports no `AesGcm` type, and
  `"AesGcm"` is deliberately **not** in `hiss-macros`' `HISS_SUITE_TYPES` —
  that constant documents the types hiss exports, and hiss exports none. The
  consequence is cosmetic: `noise!` invocations here emit uncompiled sketches
  rather than `# Usage` doctests. Nothing in this crate is gated on doctest
  count, and the main repo's sketch-sentinel is scoped to the downstream
  consumer crate, which this is not.

## Why a separate crate, and why a renamed dependency

Two decisions worth not re-litigating.

**Why not extend `hiss-interop`?** Its manifest states that its cryptoxide and
eccoxide requirements "mirror hiss's exactly so this crate cannot resolve a
different version than the code under test". A git-master cryptoxide is
precisely what that sentence exists to prevent. Its committed lockfile also
exists so the comparison benchmark stays comparable across time, and it is
permanent where this crate has an expiry date.

**Why a renamed direct dependency rather than `[patch.crates-io]`?** A root
`[patch]` resolves the whole graph — including hiss's own ChaCha20-Poly1305,
BLAKE2, SHA-2, HMAC and Ed25519 — to master. That buys a weak pre-release
canary at the price of fault isolation: a red run could mean "master broke
BLAKE2" and you would debug AES-GCM for an hour. Cargo accepts the same
package name at the same version from two different sources, so:

```
hiss             -> cryptoxide 0.6.2  from the REGISTRY
hiss-aesgcm-lab  -> cryptoxide 0.6.2  from GIT master
```

Confirm it any time with `cargo tree -i cryptoxide@0.6.2`, which reports the
spec as *ambiguous* and prints both source URLs — that is the confirmation, not
a warning to fix. The usual hazard with two copies of one crate is type
identity; it cannot arise here, because hiss's `Cipher` trait is pure bytes
(`&[u8; 32]`, `u64`, `&[u8]`) and the two copies never meet at a type boundary.

The canary that `[patch]` would have bought is already covered better by the
weekly `Interop` cron and the `Downstream` gate, both of which re-resolve
fresh.

## Running it

```sh
cargo test                        # default: hiss's cryptoxide X25519 ladder
cargo test --no-default-features  # hiss's eccoxide Montgomery ladder
```

Both legs must be green. The second is not a duplicate — verify with:

```sh
cargo tree --no-default-features -f "{p} {f}"   # `hiss` must appear WITHOUT x25519-cryptoxide
```

### Benchmarks

```sh
cargo bench --bench aesgcm_comparison
```

Modelled on `hiss-interop/benches/comparison.rs` and using the same criterion
version, the same `N`/`BLAKE2b`/1 KiB shape and the same `transport_1KiB` group
name, so the numbers sit on the same scale as that bench's. Three arms —
hiss/AESGCM (cryptoxide git master), snow/AESGCM (RustCrypto), and
hiss/ChaChaPoly as an in-run reference — measured fused (round trip) and split
(encrypt-only, decrypt-only).

CI compiles it with `--no-run` only, following `interop.yml`: numbers from a
shared runner are not meaningful, but a bench that stops compiling is a real
break.

**Read the numbers with the host in hand.** Per the backend section below,
the hiss/AESGCM arm measures hardware AES *block* + hardware PMULL GHASH on
a Mac and all-portable on CI's x86 runner; the snow arm is RustCrypto's
hardware path on both. Never compare a figure from one host against a figure
from the other.

Measured on `aarch64-apple-darwin` (M-series), 1 KiB messages, with the
`.cargo/config.toml` cfgs in place (snow arm on RustCrypto's hardware paths),
against cryptoxide master `00b97d99`:

| Group | hiss/AESGCM | snow/AESGCM | hiss/ChaChaPoly |
|---|---|---|---|
| `transport_1KiB` (round trip) | **0.98 µs** | 1.27 µs | 2.08 µs |
| `transport_1KiB_encrypt` | **0.50 µs** | 0.64 µs | 0.98 µs |
| `transport_1KiB_decrypt` | **0.58 µs** | 0.77 µs | 1.04 µs |

Four things those numbers say — the first two are the history, kept so the
superseded figures cannot be quoted without their correction:

- **This lab's first committed measurement got the headline wrong.** It ran
  before `.cargo/config.toml` existed, so the snow arm was RustCrypto's
  *software* fallback (11.12 µs round trip), and this README concluded
  "cryptoxide and RustCrypto land within ~3%; the gap to ChaChaPoly is the
  state of both pure-Rust stacks on Apple Silicon". Wrong on both counts:
  RustCrypto's hardware path is ~8.5× faster than what was measured, and
  **hardware AES-GCM beats ChaChaPoly** — as it should on silicon with AES
  and PMULL.
- **The second measurement diagnosed the gap correctly, and upstream fixed
  it.** At rev `62056f46` the hiss/AESGCM arm was 11.10/5.78/5.79 µs, and
  this README concluded: "the real gap is cryptoxide's GHASH, nothing else
  … a PMULL/CLMUL GHASH in cryptoxide's `aes_gcm` closes roughly all of the
  ~8× to RustCrypto." cryptoxide `9cb5ee9` (2026-08-14) landed exactly that
  — a `pmull`/`pmull2` GHASH in `src/aes_gcm/ghash/aarch64.rs`, behind the
  same `all(target_arch = "aarch64", target_feature = "aes")` gate as the
  AES block path. The rev bump to `00b97d99` is that change and nothing
  else of substance; the public API is unchanged, and all 328 tests pass on
  both feature legs.
- **The prediction was right, and it undershot.** Measured: **−91%** on
  every hiss/AESGCM arm (round trip 11.115 → 0.984 µs, ~11.3×). The GHASH
  was not merely most of the gap to RustCrypto, it was more than the whole
  of it: cryptoxide is now **~23% faster than RustCrypto** on round trip
  where it was 8.4× slower, and **2.1× faster than ChaChaPoly**. The two
  arms that did not change moved −3.8%/+8.7%/+4.1% on identical code in the
  same run — that is this host's noise band, and it is what makes −91%
  unambiguous.
- **The per-message key schedule is now the thing to look at.** hiss's
  `Cipher` trait takes the key per call, so `AesGcm256::new` re-expands on
  every message. Its absolute cost did not change — re-measured at
  **116 ns**, consistent with the ≈110 ns recorded before — but its *share*
  did, because everything around it got 11× cheaper: it was **~2%** of an
  encrypt and is now **~25%** (116 ns of a 471 ns raw 1 KiB seal). The
  earlier verdict that hoisting it "would buy almost nothing" was true of
  the portable-GHASH build and is **false now**. This does not block
  anything — it is a note for the exit review, where the trait shape is the
  lever.

The ship-it advice this changes: the reason to keep AESGCM an *option*
rather than a default was cryptoxide's GHASH, and that reason is gone on
aarch64-with-`aes`. On this host AESGCM is now the fastest cipher hiss could
offer. Two things must land before that becomes a decision: the portable
path needs numbers (see below — `a7a9fee` restructured the reference backend
too, and it is what x86-64 and non-Apple aarch64 get), and none of this has
been *released* — master still reports 0.6.2, so the exit trigger has not
fired.

### AES backends: what your machine actually tests

cryptoxide picks its AES implementation at compile time — and since
`9cb5ee9`, its GHASH implementation behind the *same* cfg:

```rust
#[cfg(all(target_arch = "aarch64", target_feature = "aes"))]  // hardware
```

Measured, and it is narrower than it looks:

| Target | `target_feature="aes"` | cryptoxide AES + GHASH path |
|---|---|---|
| `aarch64-apple-darwin` | **yes** | aarch64 hardware intrinsics (AES + `pmull`) |
| `x86_64-unknown-linux-gnu` | no | portable reference |
| `aarch64-unknown-linux-gnu` | no | portable reference |

So a Mac runs the **hardware** path and a Linux CI runner runs the
**portable** one — including an arm64 Linux runner, which is not sufficient:
the `aes` target feature is on by default only on Apple Silicon. `macos-latest`
is the only hosted runner that compiles the hardware backend, which is why
`.github/workflows/aesgcm-lab.yml` uses a `{ubuntu-latest, macos-latest}`
matrix.

RustCrypto — the snow arm — splits differently. On x86-64 its AES-NI and
CLMUL paths are **runtime-detected**: no flag, always on. On aarch64, in the
versions snow resolves (`aes` 0.8.4, `polyval` 0.6.2), the hardware paths
are compile-time **opt-in** behind `--cfg aes_armv8` and
`--cfg polyval_armv8` — a default build, this lab's included until it set
them, measures RustCrypto's *software* fallback. `.cargo/config.toml` now
sets both cfgs for every aarch64 build of this crate, so the snow arm is
always RustCrypto at its best. (An ordinary snow consumer on Apple Silicon
who does not know about the flags gets the software path — worth
remembering when reading snow numbers published by anyone.)

The asymmetry that used to survive every flag — **cryptoxide's GHASH is
portable software on every target** — is gone as of `9cb5ee9`, but only
where the cfg above is satisfied. So the split now cuts the other way, and
it matters more than it did: on a Mac both stacks are hardware AES *and*
hardware carry-less multiply, and cryptoxide wins; on CI's x86 leg
cryptoxide is fully portable while RustCrypto still gets runtime-detected
AES-NI and CLMUL, so expect that arm to look roughly like the old
software-GHASH numbers. **x86-64 has no CLMUL GHASH in cryptoxide.** That
is the natural next piece of upstream feedback, and the reason the ubuntu
leg of the matrix is now the interesting one rather than a formality.

**Do not try to reach the portable path locally with
`RUSTFLAGS="-C target-feature=-aes"`.** It cannot work: `snow`'s default `std`
feature puts `ring` in the dev graph, and ring 0.17 fails const-eval under that
flag on `aarch64-apple-darwin`
(`assertion failed: (CAPS_STATIC & MIN_STATIC_FEATURES) == MIN_STATIC_FEATURES`).
`RUSTFLAGS` is package-global, so `--test` scoping does not help. The portable
path is CI's ubuntu leg's job.

The inverse gotcha exists too: a `RUSTFLAGS` environment variable
**replaces** `.cargo/config.toml`'s target rustflags wholesale, so exporting
one — for anything — silently drops the `aes_armv8`/`polyval_armv8` cfgs
and the snow arm degrades to RustCrypto's software path. If you must export
`RUSTFLAGS`, carry `--cfg aes_armv8 --cfg polyval_armv8` along in it.

## Regenerating the vectors

```sh
CACOPHONY_SRC=~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/\
  snow-0.10.0/tests/vectors/cacophony.txt \
  cargo test --test extract extract_cacophony_aesgcm_subset -- --ignored
```

Pins, filter, licence chain and the upstream byte-identity check are in
`vectors/cacophony-aesgcm/PROVENANCE.md` and
`vectors/wycheproof/PROVENANCE.md`. The main repo's `tests/vectors/` is frozen
and is **not** touched by any of this — this crate carries its own copy.

## Accepted risk: the git pin has no source escrow

`Cargo.lock` records the rev hash, not the bytes. If `typed-io/cryptoxide` is
deleted, made private, or force-pushed such that
`00b97d991e589c937afa2b98aa0f19151e3ea697` becomes unreachable, every fresh
clone of this crate fails to resolve.

This is **accepted, not mitigated**. Nothing degrades quietly — it is a hard
resolve failure — and the weekly cron makes it loud within a week rather than
at exit time. Vendoring the AES-GCM sources or pushing a mirror tag would fix
it, and both cost more than the failure mode is worth for a crate with a
scheduled exit.

## Exit criteria

**Trigger:** cryptoxide publishes a release containing `aes_gcm` (i.e. > 0.6.2,
since master still reports 0.6.2).

Nothing in this repo currently *notices* that happening — the exit is manual,
and the weekly cron does not check the registry (it must not `cargo update`,
which would defeat the rev pin).

**Migration, in order:**

1. hiss gains an `aes-gcm` feature forwarding to `cryptoxide/aes-gcm`; bump the
   cryptoxide floor to the release that ships it.
2. `src/noise/cipher.rs` gains `pub struct AesGcm` — this crate's impl moved
   verbatim, `#[doc(cfg(...))]`-badged, re-exported from `src/noise/mod.rs`.

   **Do not copy `ChaChaPoly`'s doc sentence.** hiss's trait doc justifies the
   zeroing contract with "The AEAD writes the decrypted plaintext into
   `output` *before* the authentication tag is verified" — true of ChaChaPoly,
   **false** of this AES-GCM, which verifies then writes. `AesGcm`'s docs must
   say something like: *"cryptoxide verifies the tag before writing, so
   `output` is untouched on failure; hiss zeroes it anyway so the failure
   contract is uniform across ciphers — and so a reused buffer cannot retain
   the previous message's plaintext."* Same guarantee, accurate mechanism.
   (`src/lib.rs` here already carries that wording, and
   `raw_cryptoxide_verifies_before_writing` pins the mechanism it describes.)

   **Decide the key-schedule question here.** Moving the impl verbatim keeps
   `AesGcm256::new` on every message, which the results above now measure at
   ~25% of an encrypt (it was ~2% before the PMULL GHASH). Either accept that
   and say so, or change `Cipher` so an expanded key can be hoisted — a trait
   change that touches ChaChaPoly too, and so is a decision for the exit
   review rather than something to discover afterwards.
3. Add `"AesGcm"` to `HISS_SUITE_TYPES` (`hiss-macros/src/codegen.rs`) — **now
   correct**, because hiss finally exports it. Without this, every `noise!`
   naming `AesGcm` degrades to an uncompiled sketch and the downstream gate's
   sketch-sentinel goes red. Add an AESGCM arm to
   `scripts/downstream-build.sh`'s pattern set.
4. Move `vectors/cacophony-aesgcm/` into `tests/vectors/cacophony/`, merging
   into the frozen corpus. Update `tests/vectors/cacophony/PROVENANCE.md`:
   136 → 272 vendored, and **rewrite the sentence "The remaining 808 are
   `AESGCM` suites (hiss ships no AES-GCM)"** — it becomes false. Update both
   sha256s.
5. Move `vectors/wycheproof/aes_gcm_test.json` into `tests/vectors/wycheproof/`
   (same pin, so no reconciliation needed); the 66-vector test becomes a lib
   unit test alongside the P-256/X25519 ones, and joins the Wycheproof gate row
   in `CLAUDE.md`'s table.
6. Move the live `snow` AESGCM interop into `hiss-interop/tests/`, and fold
   `benches/aesgcm_comparison.rs` into `hiss-interop/benches/comparison.rs` as
   extra arms on its existing `transport_1KiB` group — at which point that
   crate's mirror-hiss's-requirements rule is satisfiable again, because
   cryptoxide AES-GCM is released.
7. **Delete `hiss-aesgcm-lab/`**; revert the two root-`Cargo.toml` excludes and
   the `.gitignore` negation, and remove `.github/workflows/aesgcm-lab.yml`.
8. `CHANGELOG.md` gets its entry **here**, under `### Added`, in the style of
   the `Sha256` entry — naming the three validation legs that stand behind it.

## Results as of the last local run

`aarch64-apple-darwin` (hardware AES), both feature legs:

| Suite | Tests |
|---|---|
| `src/lib.rs` units — nonce endianness, failure-path zeroing, truncation, tag/ciphertext tampering, AD binding | 10 |
| `cacophony_aesgcm` — 136 vectors × 2 roles, + suite-coverage | 273 |
| `snow_aesgcm` — 5 patterns × 4 hashes × 2 directions, + 3 guards | 43 |
| `wycheproof_aesgcm` — 66 applicable vectors (39 valid, 27 invalid) | 1 |
| `extract` — vendored-subset self-check (+1 `#[ignore]` generator) | 1 |
| **Total** | **328** |
