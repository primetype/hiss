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

**Read the numbers with the host in hand.** Per the backend table above, the
hiss/AESGCM arm measures *hardware* AES on a Mac and *portable* AES on CI's
x86 runner. Never compare a figure from one against a figure from the other.

Measured once on `aarch64-apple-darwin` (hardware AES), 1 KiB messages:

| Group | hiss/AESGCM | snow/AESGCM | hiss/ChaChaPoly |
|---|---|---|---|
| `transport_1KiB` (round trip) | 11.75 µs | 11.12 µs | 1.99 µs |
| `transport_1KiB_encrypt` | 5.69 µs | 5.55 µs | 0.99 µs |
| `transport_1KiB_decrypt` | 5.86 µs | 5.51 µs | 1.01 µs |

Two things worth saying about those, because the headline gap invites a wrong
conclusion:

- **This is not a cryptoxide problem.** cryptoxide and RustCrypto land within
  ~3% of each other. AES-GCM being ~5.6× slower than ChaChaPoly at this size
  is the state of both pure-Rust stacks on Apple Silicon, not a defect in the
  implementation under test.
- **It is not the per-message key schedule either.** hiss's `Cipher` trait
  takes the key per call, so `AesGcm256::new` re-expands on every message —
  the obvious suspect. Measured directly: the key schedule is **≈110 ns**,
  about **2%** of the ≈5.6 µs. Hoisting it would buy almost nothing. (Worth
  recording because the design note that predicted this cost flagged it as a
  question for the exit review; the answer is that it is negligible.)

### AES backends: what your machine actually tests

cryptoxide picks its AES implementation at compile time:

```rust
#[cfg(all(target_arch = "aarch64", target_feature = "aes"))]  // hardware
```

Measured, and it is narrower than it looks:

| Target | `target_feature="aes"` | cryptoxide path |
|---|---|---|
| `aarch64-apple-darwin` | **yes** | aarch64 hardware intrinsics |
| `x86_64-unknown-linux-gnu` | no | portable reference |
| `aarch64-unknown-linux-gnu` | no | portable reference |

So a Mac runs the **hardware** path and a Linux CI runner runs the
**portable** one — including an arm64 Linux runner, which is not sufficient:
the `aes` target feature is on by default only on Apple Silicon. `macos-latest`
is the only hosted runner that compiles the hardware backend, which is why
`.github/workflows/aesgcm-lab.yml` uses a `{ubuntu-latest, macos-latest}`
matrix.

**Do not try to reach the portable path locally with
`RUSTFLAGS="-C target-feature=-aes"`.** It cannot work: `snow`'s default `std`
feature puts `ring` in the dev graph, and ring 0.17 fails const-eval under that
flag on `aarch64-apple-darwin`
(`assertion failed: (CAPS_STATIC & MIN_STATIC_FEATURES) == MIN_STATIC_FEATURES`).
`RUSTFLAGS` is package-global, so `--test` scoping does not help. The portable
path is CI's ubuntu leg's job.

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
`62056f46e2a5001b11d505dce37d301cb8ec7e28` becomes unreachable, every fresh
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
