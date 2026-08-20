# hiss-interop

Cross-implementation interop tests and comparison benchmarks for
[`hiss`](..), against [`snow`](https://crates.io/crates/snow).

Unpublished, out-of-workspace, and depends on `hiss` by path. It exists so
that `snow` — and the entire RustCrypto stack, `ring`, and ten `windows-*`
crates it pulls in — is **not** in the dependency graph a hiss contributor
compiles. Moving it out took that graph from 195 packages to 132.

## What is here

| Target | Covers |
|---|---|
| `tests/snow_interop.rs` | 28 tests, P-256: one side `hiss`, the other `snow`, across the pattern and hash matrix |
| `tests/snow_interop_25519.rs` | 5 tests, X25519, same shape |
| `tests/snow_aesgcm.rs` | 43 tests, X25519 × **AESGCM** × all four hashes: `N`/`NN`/`XX`/`IK`/`Kpsk0` in both role assignments against snow's RustCrypto AES-GCM, plus three guards |
| `tests/snow_diag.rs` | 2 primitive/handshake diagnostics against snow's own dependencies |
| `tests/generate_p256_vectors.rs` | the `#[ignore]` regenerators for hiss's frozen P-256 corpora |
| `benches/comparison.rs` | the hiss-vs-snow benchmark, both arms in one Criterion run — handshakes over three curves, transport over **both ciphers** (round trip, encrypt-only, decrypt-only) |
| `benches/suite_25519_aesgcm_sha256.rs` | one suite end to end, `Noise_*_25519_AESGCM_SHA256`: `N`/`IK`/`XX` handshakes and transport at 64 B / 1 KiB / 16 KiB / 65519 B, hiss vs snow, with bytes-per-second throughput |

## Running it

```sh
cargo test                        # default: hiss's cryptoxide X25519 backend
cargo test --no-default-features  # hiss's eccoxide Montgomery ladder
cargo bench                       # both benches; `--no-run` just to check they build
cargo bench --bench suite_25519_aesgcm_sha256   # the one-suite bench alone
open target/criterion/report/index.html         # criterion's HTML report (always on here)
```

Both feature legs matter here for **interop completeness** — the comparison
should exercise snow against both of hiss's backends, mirroring hiss's own
matrix. It is *not* what proves those backends agree byte-for-byte: that proof
is hiss's own and runs on every commit, via the ungated RFC 7748 known-answer
tests in `src/curve/x25519.rs` and the 328 ungated X25519 `cacophony` replays
(eight suites × forty-one) in `tests/noise_cacophony.rs`.

## Which AES-GCM the bench measures

Both AESGCM arms pick their implementation at compile time, and they do not
pick the same way:

| Host | hiss (cryptoxide) | snow (RustCrypto `aes-gcm`) |
|---|---|---|
| `aarch64-apple-darwin` (a Mac) | ARMv8 AES + `pmull` GHASH (`target_feature = "aes"` is on by default) | ARMv8 AES + PMULL — **only** with `--cfg aes_armv8 --cfg polyval_armv8`, which `.cargo/config.toml` sets for every aarch64 build of this crate |
| `x86_64` (CI's `ubuntu-latest`) | portable fixsliced AES + portable GHASH (no AES-NI/CLMUL path) | AES-NI + CLMUL, runtime-detected |
| `aarch64-unknown-linux-gnu` | portable (the `aes` target feature is **not** on by default there) | as above, with the cfgs |

So on a Mac both stacks run hardware AES and hardware carry-less multiply; on
CI hiss is fully portable while snow is hardware. **Never compare a number from
one host against a number from the other**, and state the host beside any
AESGCM figure. Last measured on an M-series Mac (cryptoxide 0.6.3, hiss 0.4.0,
2026-08-20), `transport_1KiB` round trip: hiss/AESGCM 0.38 µs,
snow/AESGCM 1.34 µs, hiss/ChaChaPoly 1.98 µs, snow/ChaChaPoly 3.15 µs.

The one-suite bench, same host and day, `Noise_*_25519_AESGCM_SHA256`
(`--warm-up-time 1 --measurement-time 3`):

| Group | hiss | snow |
|---|---|---|
| `handshake_N` / `IK` / `XX` | 80.7 / 239.3 / 199.5 µs | 88.7 / 259.8 / 218.4 µs |
| `transport_round_trip` 64 B | 83.7 ns (728 MiB/s) | 330 ns (183 MiB/s) |
| `transport_round_trip` 1 KiB | 372 ns (2.56 GiB/s) | 1.27 µs (764 MiB/s) |
| `transport_round_trip` 16 KiB | 4.62 µs (3.30 GiB/s) | 16.7 µs (935 MiB/s) |
| `transport_round_trip` 65519 B | 18.5 µs (3.29 GiB/s) | 67.0 µs (934 MiB/s) |
| `transport_encrypt` 65519 B | 8.33 µs (7.32 GiB/s) | 33.2 µs (1.84 GiB/s) |
| `transport_decrypt` 65519 B | 11.7 µs (5.23 GiB/s) | 35.0 µs (1.74 GiB/s) |

Two things the sizes show that the 1 KiB figure alone hides. The small-message
rows are where a fixed per-message cost lives, and hiss 0.4.0 is where one got
removed: hoisting the AES key schedule out of the per-message path — `Cipher`
now holds an expanded key — took the 64 B round trip from 314 ns to 84 ns and
the 1 KiB one from 611 ns to 372 ns, while the 65519 B rows, which are all bulk
rate, barely moved. Before that change the two stacks were within noise of each
other at 64 B; they are not any more. And hiss still decrypts slower than it
encrypts at every size — +20 % at 64 B, +36…48 % at 1 KiB and above — because
cryptoxide's `decrypt` makes a GHASH pass over the whole ciphertext *before*
the CTR pass (verify-then-write, see `src/noise/cipher.rs`), where its
`encrypt` stitches the two into one pass.
snow's arms are symmetric because RustCrypto's `aes-gcm` 0.10 runs CTR and
GHASH as two separate passes in *both* directions (it verifies before
writing too: `decrypt_in_place_detached` computes the tag, compares, and only
then applies the keystream) — so its encrypt pays the same two passes its
decrypt does.

The two cfgs in `.cargo/config.toml` apply to every aarch64 build of this crate
— tests included — and are inert for everything except the `aes` and `polyval`
crates. A `RUSTFLAGS` environment variable **replaces** config-file rustflags
wholesale, so if you export one, carry `--cfg aes_armv8 --cfg polyval_armv8`
along or the snow arms silently fall back to RustCrypto's software path. Do
not try `-C target-feature=-aes` to reach hiss's portable path on a Mac: `ring`
(in snow's default graph) fails const-eval under it.

## This is not a release gate

Nothing here runs under hiss's `cargo test` or any gate in `CLAUDE.md`. CI runs
it weekly, on pushes to `main`, and on `workflow_dispatch`. The scheduled run
does `cargo update` first, deliberately defeating the committed lockfile, so a
new `snow` release is noticed within a week.

**A red run here is a finding about this harness or about `snow` — not a hiss
regression.** hiss's own conformance is pinned by frozen vectors that involve
no second implementation at runtime.

`Cargo.lock` **is** committed (as `site/`'s is, and unlike hiss's own): this
crate is unpublished and has no consumers to resolve it fresh, and a comparison
benchmark whose `snow` version moves silently is not comparable across time.

## Regenerating the frozen P-256 vectors

`tests/generate_p256_vectors.rs` writes into **hiss's** corpus directory —
`CARGO_MANIFEST_DIR/../tests/vectors/noise/` — because the generators link
`snow` and the replays do not.

```sh
cargo test --test generate_p256_vectors generate_noise_kat_vectors -- --ignored
cargo test --test generate_p256_vectors generate_noise_kat_sha256_vectors -- --ignored
```

Then, from the repo root, inspect the diff:

```sh
git diff --stat tests/vectors/noise/
git diff tests/vectors/noise/
```

**Only *additions* are legitimate.** Any modification to a pre-existing vector
means `snow`'s output moved: that is a **stop-and-investigate**, not a
re-freeze. A regenerated corpus and regenerated replays passing together proves
nothing — they were produced by the same run. The point of a frozen corpus is
that it disagrees with you when something changes.

If you added a pattern, expect exactly the new entries plus a widened `note`
string, and nothing else.
