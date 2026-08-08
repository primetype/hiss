#!/usr/bin/env bash
# Build hiss the way a *consumer* builds it: from a throwaway crate, with a
# fresh dependency resolution and no lockfile.
#
# Why this gate exists.
#
# First, what it is NOT for. This repo does not commit a root Cargo.lock
# (.gitignore) and no CI job passes --locked, so CI already re-resolves from
# the index on every run — clippy/msrv/test would have caught eccoxide 0.4.3
# on their own. The masking is *local*: a working tree keeps its untracked
# Cargo.lock indefinitely, and CLAUDE.md's release gates are run locally, so
# the one moment a stale pin is most likely to hide a broken requirement is
# the moment a release is cut. That alone justifies a gate that ignores the
# lockfile.
#
# What it adds beyond a fresh `cargo build` here:
#   * hiss is consumed as an out-of-workspace path dependency, so its
#     dev-dependencies are absent. In-repo builds unify features across the
#     dev graph; a consumer gets none of that, and a feature that only ever
#     arrives via a dev-dependency shows up as a build failure only here.
#   * The README quickstart is compiled *and executed* against the exact
#     dependency pairing the README advertises (`hiss` + `rand = "0.9"`),
#     so the advertised snippets cannot silently rot.
#   * The `default-features = false` consumer is covered (eccoxide X25519
#     backend rather than cryptoxide).
#   * On its weekly cron (.github/workflows/downstream.yml) it catches an
#     upstream release that breaks hiss while nobody is pushing — eccoxide
#     0.4.3 changed `PointAffine::decompress` from `Option` to `CtOption` in
#     a *patch* release, which `eccoxide = "0.4"` resolved to.
#
# What it does:
#   1. Generates a crate in a temp dir (outside this repo, so no ancestor
#      workspace and no inherited lockfile) that depends on `hiss` by path
#      plus `rand = "0.9"` — the dependency set the README advertises.
#   2. Stitches the four ```rust blocks of README.md's "## Quickstart" into
#      its main.rs, so the advertised snippets are compiled and executed
#      against the advertised dependency set.
#   3. Resolves and builds it WITHOUT `--offline`, so Cargo picks the newest
#      semver-compatible release of every dependency, then runs it.
#   4. Repeats with `default-features = false`, which swaps the X25519
#      backend from cryptoxide to eccoxide — a path the rest of CI treats as
#      first-class.
#
# Exits non-zero on any failure. Set KEEP=1 to leave the generated crate in
# place for inspection.
#
# Usage: scripts/downstream-build.sh   (from anywhere)
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
readme="$repo_root/README.md"

# The generated crate is edition 2024, stabilised in Rust 1.85. Any toolchain
# able to build hiss at all clears that (its MSRV is higher), but fail with a
# sentence instead of cargo's "feature `edition2024` is required" wall.
rustc_version=$(rustc --version | awk '{print $2}')
rustc_rest=${rustc_version#*.}
if [ "${rustc_version%%.*}" -lt 1 ] ||
   { [ "${rustc_version%%.*}" -eq 1 ] && [ "${rustc_rest%%.*}" -lt 85 ]; }; then
    echo "downstream-build: needs Rust >= 1.85 (edition 2024), found $rustc_version" >&2
    exit 1
fi

# A shared target dir for both variants; explicitly set so an inherited
# CARGO_TARGET_DIR cannot point the build back at this repo's target/.
work=$(mktemp -d "${TMPDIR:-/tmp}/hiss-downstream.XXXXXX")
export CARGO_TARGET_DIR="$work/target"

cleanup() {
    if [ "${KEEP:-0}" = "1" ]; then
        echo "KEEP=1 — generated crates left in $work" >&2
    else
        rm -rf "$work"
    fi
}
trap cleanup EXIT

# ── 1. Extract the README quickstart ────────────────────────────────
#
# Same section-slicing recipe as .claude/skills/goal/check-quickstart-sync.sh:
# everything between "## Quickstart" and the next "## " heading. Here the
# ```rust blocks are kept separate (block1..blockN) because block 1 is
# file-scope items and the rest are statements.
blocks="$work/blocks"
mkdir -p "$blocks"

nblocks=$(
    awk '/^## Quickstart$/{f=1;next} /^## /{if(f)exit} f' "$readme" \
      | awk -v out="$blocks" '
          /^```rust$/ { n++; inblk=1; next }
          /^```/      { inblk=0; next }
          inblk       { print > (out "/block" n) }
          END         { print n+0 }
        '
)

# The whole point of the stitching is to compile something real. If the README
# is reshaped and the extraction silently yields the wrong thing, fail loudly
# rather than "pass" on an empty program.
if [ "$nblocks" -ne 4 ]; then
    echo "downstream-build: expected 4 \`\`\`rust blocks in README.md '## Quickstart', found $nblocks" >&2
    echo "downstream-build: the extraction recipe is out of sync with the README — fix one or the other" >&2
    exit 1
fi
if ! grep -q 'hiss::noise!' "$blocks/block1"; then
    echo "downstream-build: block 1 of the quickstart no longer declares a \`hiss::noise!\` pattern" >&2
    echo "downstream-build: block 1 must be the file-scope items (use + noise!); the stitching assumes it" >&2
    exit 1
fi

# Block 1 is file scope (the `use` line and the `hiss::noise!` invocation);
# blocks 2-4 are statements and go in `main`. This mirrors how
# examples/quickstart.rs assembles the same four steps.
main_rs="$work/main.rs"
{
    cat "$blocks/block1"
    echo
    echo 'fn main() -> Result<(), Box<dyn std::error::Error>> {'
    cat "$blocks/block2" "$blocks/block3" "$blocks/block4"
    echo '    Ok(())'
    echo '}'
} > "$main_rs"

# ── 2. Build it as a downstream crate ───────────────────────────────

# $1 = crate name, $2 = the `hiss` dependency line
build_downstream() {
    local name="$1" hiss_dep="$2"
    local dir="$work/$name"

    mkdir -p "$dir/src"
    cp "$main_rs" "$dir/src/main.rs"

    # `[workspace]` keeps the crate from being absorbed into an ancestor
    # workspace. No Cargo.lock is created or copied: Cargo resolves from
    # scratch, which is the whole point.
    cat > "$dir/Cargo.toml" <<EOF
[package]
name = "$name"
version = "0.0.0"
edition = "2024"

[workspace]

[dependencies]
$hiss_dep
rand = "0.9"
EOF

    if [ -e "$dir/Cargo.lock" ]; then
        echo "downstream-build: a Cargo.lock leaked into $dir — the resolve would not be fresh" >&2
        exit 1
    fi

    echo "── $name: resolving and building (no --offline, no lockfile) ──"
    # No `--offline`: Cargo hits the index and picks the newest
    # semver-compatible release of every requirement, exactly as a real
    # downstream crate would.
    ( cd "$dir" && cargo run --quiet )
    echo "── $name: OK ──"
}

build_downstream hiss-downstream-default \
    "hiss = { path = \"$repo_root\" }"

build_downstream hiss-downstream-nodefault \
    "hiss = { path = \"$repo_root\", default-features = false }"

echo
echo "DOWNSTREAM OK — hiss builds and the README quickstart runs from a fresh"
echo "resolve of \`hiss\` + \`rand = \"0.9\"\`, with no lockfile."
