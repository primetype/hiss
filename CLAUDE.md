# hiss — project instructions

## Release gates (hard rules)

A release may be cut **only when every gate below is green on the exact commit
being released**. No exceptions — if a gate fails, the release is blocked until
it is fixed, not deferred to "the next patch."

| Gate | Command | Bar |
|------|---------|-----|
| Compiles | `cargo build --all-features --all-targets` | clean build |
| Format | `cargo fmt --all --check` | no diff |
| Lints | `cargo clippy --all-features --all-targets -- -D warnings` | zero warnings |
| Docs | `cargo doc --no-deps` and `--all-features`, `RUSTDOCFLAGS=-D warnings` | no broken intra-doc links |
| Tests | `cargo test` **and** `cargo test --all-features` | all pass |
| KAT | `cargo test --all-features --test noise_kat --test noise_cacophony` (Noise known-answer vectors: snow-generated P-256 + third-party cacophony) | all pass |
| Wycheproof | P-256 / X25519 Wycheproof vectors — lib unit tests, run under `cargo test --all-features` | all pass |
| MSRV | `cargo +<MSRV> check --all-features --all-targets` | passes on the declared MSRV |
| Coverage | `cargo llvm-cov` (gated total — see `.github/workflows/coverage.yml`) | ≥ 80% lines / 75% regions |
| Benchmarks | `cargo bench` | builds and runs clean |
| Supply chain | `cargo deny check` | clean |
| Downstream | `scripts/downstream-build.sh` | fresh resolve, no lockfile, builds + runs the README quickstart, compiles the doctests `noise!` emits |

These mirror the CI pipeline (`Check` → `Test` → `Coverage`), plus `Downstream`,
which runs alongside `Check` rather than inside it — it is the one gate that
also needs a `schedule:` trigger, and a cron on `Check` would drag `Test` and
`Coverage` along with it. CI green on the release commit satisfies every gate
**except benchmarks**, which CI does not run — validate `cargo bench` locally
before releasing.

### Why the downstream gate exists

Be precise about what this gate does and does not fix, because the obvious
story is wrong. The root `Cargo.lock` is **not** committed (`.gitignore`) and
no CI job passes `--locked`, so CI already re-resolves from the index on every
run. When eccoxide 0.4.3 changed `PointAffine::decompress` from `Option` to
`CtOption` in a *patch* release that `eccoxide = "0.4"` resolved to,
`clippy-doc`, `msrv`, `Test` and `Coverage` would every one of them have gone
red on the next run. They stayed green only because no run happened between
0.4.3 landing and the fix.

Where a stale lockfile genuinely masks a broken requirement is **locally**: a
working tree keeps its untracked `Cargo.lock` indefinitely, and every gate in
the table above is run locally when cutting a release. That is the worst
possible moment to be reading a months-old pin.

So what the gate adds, concretely:

1. The local release-gate run stops being masked by a stale untracked lock.
2. hiss is consumed as an **out-of-workspace path dependency**, so its
   dev-dependencies are absent. In-repo builds unify features across the dev
   graph; a consumer gets none of that, and a feature that only ever arrives
   via a dev-dependency surfaces as a build failure only here.
3. The README quickstart is compiled *and executed* against the exact
   dependency pairing the README advertises (`hiss` + `rand = "0.9"`).
4. The `# Usage` doctests `noise!` emits are compiled — over four
   patterns chosen to reach every arm of the generator, not just one
   shape: pre-message keys (local and remote), a plain PSK and a
   per-peer lookup, declared payloads on a sent and a received message,
   the identity hook on a read that reveals `s`, and a one-way role that
   only writes. Nothing else compiles them: doctests do not run for
   binaries, and hiss's own `noise!` invocations are marker-mode, which
   emits no walkthrough. Sabotage one arm and every other gate stays
   green while this one goes red — which is the point. The arms also
   spell every suite type in the macro's `HISS_SUITE_TYPES` list, and a
   sketch-sentinel grep goes red when a walkthrough silently degrades to
   an uncompiled sketch — the exact failure of a type missing from that
   list, which leaves every other gate green.
5. The `default-features = false` consumer is covered.
6. On its weekly cron it catches an upstream break during an idle window,
   rather than at the next push — which, for a quiet week, is the release
   commit itself.

Two rules follow:

1. Every dependency requirement carries an explicit range, and widening one
   needs a green `scripts/downstream-build.sh` behind it — not a lockfile.
2. A caret bound (`"0.4"`) is not by itself protection. It already means
   `>=0.4.0, <0.5.0`; it does nothing about a breaking change shipped *within*
   the `0.4.x` line, which is exactly what happened.

### Occasional checks (not gates)

`hiss-interop/` (out-of-workspace, unpublished, own lockfile) holds everything
that links `snow`: the live interop tests, the `#[ignore]` generators behind
the frozen P-256 corpora, and the hiss-vs-snow comparison bench. It runs on
its own workflow (`interop.yml`: weekly cron with a fresh `cargo update`,
manual dispatch, push to `main`) — no gate above depends on it, and `cargo
test` in this repo builds nothing snow-shaped. Convention: **dispatch the
Interop workflow before cutting a release**; it is not a gate and does not
block, but a red run means the comparison harness — usually a moved `snow` —
needs attention before the next vector regeneration.

### MSRV policy

The MSRV is declared in `Cargo.toml` (`rust-version`) and pinned by the `msrv`
CI job — keep both in lockstep. It tracks a recent stable **floored at
`stable − 3`**: bumped only once it would fall more than three releases behind
current stable. It is currently **1.96** (set at current stable) and will begin
moving once stable advances past **1.99**.

## Releasing

Cut releases with the `release` skill (`.claude/skills/release/SKILL.md`): it
runs the gates above, updates the changelog, and publishes with `cargo release`.
