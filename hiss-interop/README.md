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
| `tests/snow_diag.rs` | 2 primitive/handshake diagnostics against snow's own dependencies |
| `tests/generate_p256_vectors.rs` | the `#[ignore]` regenerators for hiss's frozen P-256 corpora |
| `benches/comparison.rs` | the hiss-vs-snow benchmark, both arms in one Criterion run |

## Running it

```sh
cargo test                        # default: hiss's cryptoxide X25519 backend
cargo test --no-default-features  # hiss's eccoxide Montgomery ladder
cargo bench                       # the comparison; `--no-run` just to check it builds
```

Both feature legs matter here for **interop completeness** — the comparison
should exercise snow against both of hiss's backends, mirroring hiss's own
matrix. It is *not* what proves those backends agree byte-for-byte: that proof
is hiss's own and runs on every commit, via the ungated RFC 7748 known-answer
tests in `src/curve/x25519.rs` and the 136 ungated X25519 `cacophony` replays
in `tests/noise_cacophony.rs`.

## This is not a release gate

Nothing here runs under hiss's `cargo test` or any gate in `CLAUDE.md`. CI runs
it weekly, on pushes to `main`, and on `workflow_dispatch`. The scheduled run
does `cargo update` first, deliberately defeating the committed lockfile, so a
new `snow` release is noticed within a week.

**A red run here is a finding about this harness or about `snow` — not a hiss
regression.** hiss's own conformance is pinned by frozen vectors that involve
no second implementation at runtime.

`Cargo.lock` **is** committed (as `demo/`'s is, and unlike hiss's own): this
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
