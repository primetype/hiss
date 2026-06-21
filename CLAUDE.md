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
| KAT | `cargo test --all-features --test noise_kat` (Noise known-answer vectors) | all pass |
| Wycheproof | P-256 / X25519 Wycheproof vectors — lib unit tests, run under `cargo test --all-features` | all pass |
| MSRV | `cargo +<MSRV> check --all-features --all-targets` | passes on the declared MSRV |
| Coverage | `cargo llvm-cov` (gated total — see `.github/workflows/coverage.yml`) | ≥ 80% lines / 75% regions |
| Benchmarks | `cargo bench` | builds and runs clean |
| Supply chain | `cargo deny check` | clean |

These mirror the CI pipeline (`Check` → `Test` → `Coverage`). CI green on the
release commit satisfies every gate **except benchmarks**, which CI does not run
— validate `cargo bench` locally before releasing.

### MSRV policy

The MSRV is declared in `Cargo.toml` (`rust-version`) and pinned by the `msrv`
CI job — keep both in lockstep. It tracks a recent stable **floored at
`stable − 3`**: bumped only once it would fall more than three releases behind
current stable. It is currently **1.96** (set at current stable) and will begin
moving once stable advances past **1.99**.

## Releasing

Cut releases with the `release` skill (`.claude/skills/release/SKILL.md`): it
runs the gates above, updates the changelog, and publishes with `cargo release`.
