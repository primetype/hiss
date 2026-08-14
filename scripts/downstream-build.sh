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
#     dependency pairing the README advertises (`hiss` + `rand = "0.10"`),
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
#      plus `rand = "0.10"` — the dependency set the README advertises.
#   2. Stitches the four ```rust blocks of README.md's "## Quickstart" into
#      its main.rs, so the advertised snippets are compiled and executed
#      against the advertised dependency set.
#   3. Resolves and builds it WITHOUT `--offline`, so Cargo picks the newest
#      semver-compatible release of every dependency, then runs it.
#   4. Builds a lib target — the README's `hiss::noise!` invocation plus
#      four more patterns chosen to reach every arm of the walkthrough (see
#      section 1b) — and runs `cargo test --doc` over it. `noise!` emits a
#      `# Usage` walkthrough onto every pattern type it generates, as a
#      doctest, and that doctest is compiled *nowhere else*: doctests do not
#      run for binaries, and hiss's own `noise!` invocations are marker-mode,
#      which emits no walkthrough. Without this step the macro could start
#      emitting a walkthrough that does not compile and every gate would stay
#      green. A companion grep catches the other half of that: a walkthrough
#      the macro quietly demoted to an uncompiled sketch, which `cargo test
#      --doc` cannot see because it simply collects one doctest fewer.
#   5. Repeats with `default-features = false`, which swaps the X25519
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

# ── 1b. The lib target the emitted doctests need ─────────────────────
#
# `noise!` writes a `# Usage` walkthrough onto every pattern type it
# generates, as a doctest — and the shape of that walkthrough varies with the
# pattern: pre-message keys, a PSK (plain, or a per-peer lookup), declared
# payloads, an identity hook on a read that reveals `s`, a role that only
# writes — and, on a msg1 ending `…, s, ss`, the staged third walkthrough
# (`read_message_1_intro` → `complete`). The README's `XX` reaches none of
# those arms, so on its own this gate would let a walkthrough that does not
# compile ship to every consumer of every other pattern. These five cover
# the generator:
#
#   XX      (from the README) — verify hook, no pre-messages, no PSK.
#             X25519 / ChaChaPoly / Blake2b
#   IKpsk1  — pre-messages, `s` ahead of `psk` (per-peer lookup), payloads
#             on both a sent and a received message. P256 / ChaChaPoly / Sha512
#   IKpsk0  — `psk` ahead of `s`: a read taking a plain PSK *and* a
#             verification closure; msg1 ends `…, s, ss`, so its staged
#             walkthrough carries the intro-with-psk arm.
#             X448 / ChaChaPoly / Sha256
#   K       — one-way: a role that only writes, a role that only reads, and
#             a local static in both constructors (the fallible arm).
#             X25519 / ChaChaPoly / Blake2s
#   IK      — the staged walkthrough with a declared payload: intro returns
#             the claimed static, `complete()` returns the payload.
#             X25519 / ChaChaPoly / Sha512
#
# The suites are spread deliberately: between them the five arms spell
# **every** type in `hiss-macros`' `HISS_SUITE_TYPES` — three curves, one
# cipher, four hashes. The sketch-degrade guard below only fires for a type
# some arm actually writes, so this is what makes it total rather than
# per-suite. Keep it that way: a new entry in `HISS_SUITE_TYPES` that no arm
# spells is guarded by nothing.
lib_rs="$work/lib.rs"
{
    cat "$blocks/block1"
    cat <<'RS'

/// Patterns picked to reach every arm of the walkthrough `noise!` emits.
pub mod arms {
    use hiss::noise::{Blake2s, ChaChaPoly, P256, Sha256, Sha512, X25519, X448};

    hiss::noise! {
        /// Pre-messages, a per-peer PSK lookup, and declared payloads.
        pub IKpsk1<P256, ChaChaPoly, Sha512> {
            <- s
            ...
            -> e, es, s, ss, psk [12]
            <- e, ee, se [4]
        }
    }

    hiss::noise! {
        /// `psk` ahead of the `s` it protects, over X448.
        pub IKpsk0<X448, ChaChaPoly, Sha256> {
            <- s
            ...
            -> psk, e, es, s, ss
            <- e, ee, se
        }
    }

    hiss::noise! {
        /// One-way, with both statics known in advance.
        pub K<X25519, ChaChaPoly, Blake2s> {
            -> s
            <- s
            ...
            -> e, es, ss
        }
    }

    hiss::noise! {
        /// Msg1 ends `…, s, ss` with a declared payload: the staged
        /// walkthrough, payload returned at `complete()`.
        pub IK<X25519, ChaChaPoly, Sha512> {
            <- s
            ...
            -> e, es, s, ss [12]
            <- e, ee, se
        }
    }
}
RS
} > "$lib_rs"

# ── 2. Build it as a downstream crate ───────────────────────────────

# $1 = crate name, $2 = the `hiss` dependency line
build_downstream() {
    local name="$1" hiss_dep="$2"
    local dir="$work/$name"

    mkdir -p "$dir/src"
    cp "$main_rs" "$dir/src/main.rs"
    # A lib target is what the emitted `# Usage` doctests need: rustdoc does
    # not collect doctests from a binary.
    cp "$lib_rs" "$dir/src/lib.rs"

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
rand = "0.10"
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

    # The `# Usage` walkthroughs `noise!` emitted onto the quickstart's `XX`
    # type, compiled in a consumer — where they are read and where nothing
    # else ever compiles them.
    echo "── $name: compiling the doctests \`noise!\` emitted ──"
    ( cd "$dir" && cargo test --doc --quiet )

    # `noise!` degrades a walkthrough from a compiled doctest to an
    # uncompiled ```text sketch whenever it cannot respell the suite for a
    # doctest crate — i.e. when a suite type is missing from
    # HISS_SUITE_TYPES in hiss-macros/src/codegen.rs. rustdoc then collects
    # fewer doctests and the step above passes green, so the degrade is
    # otherwise invisible. Every suite spelled in this script is one
    # `noise!` can respell, so any sketch here is a bug.
    echo "── $name: checking no walkthrough degraded to a sketch ──"
    ( cd "$dir" && cargo doc --no-deps --quiet )
    if grep -rqF 'Sketches rather than doctests' "$CARGO_TARGET_DIR/doc/${name//-/_}/"; then
        echo "downstream-build: a noise! walkthrough degraded to an uncompiled sketch" >&2
        echo "downstream-build: a suite type used above is missing from HISS_SUITE_TYPES (hiss-macros/src/codegen.rs)" >&2
        exit 1
    fi
    echo "── $name: OK ──"
}

build_downstream hiss-downstream-default \
    "hiss = { path = \"$repo_root\" }"

build_downstream hiss-downstream-nodefault \
    "hiss = { path = \"$repo_root\", default-features = false }"

echo
echo "DOWNSTREAM OK — hiss builds and the README quickstart runs from a fresh"
echo "resolve of \`hiss\` + \`rand = \"0.10\"\`, with no lockfile."
