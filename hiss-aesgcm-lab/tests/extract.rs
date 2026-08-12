//! Re-derive `vectors/cacophony-aesgcm/cacophony-aesgcm.json` from an upstream
//! cacophony corpus, so the filter is **reproducible rather than trusted**.
//!
//! ```text
//! CACOPHONY_SRC=~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/\
//!   snow-0.10.0/tests/vectors/cacophony.txt \
//!   cargo test --test extract extract_cacophony_aesgcm_subset -- --ignored
//! ```
//!
//! This mirrors `tests/noise_cacophony.rs`'s `extract_cacophony_subset` in the
//! main repo — same recipe, same `PATTERNS` array as the single source of
//! truth for the filter, same assert-before-write. The one difference is the
//! suite list: `AESGCM` where the main repo takes `ChaChaPoly`. The main
//! repo's generator is **not** modified; the frozen corpus in
//! `tests/vectors/` stays exactly as it is.
//!
//! Upstream order is preserved and every value is re-emitted verbatim; only
//! whitespace, key order and the elision of absent optional keys differ, so the
//! entries stay `jq`-comparable to the source entry for entry.

mod common;

use common::{VECTORS_PATH, VectorFile, check_invariants, load_vectors, wanted_protocol_names};

#[test]
#[ignore = "regenerates the vendored corpus from an upstream cacophony.txt"]
fn extract_cacophony_aesgcm_subset() {
    let src =
        std::env::var("CACOPHONY_SRC").expect("set CACOPHONY_SRC to an upstream cacophony.txt");
    let raw = std::fs::read_to_string(&src).expect("read CACOPHONY_SRC");
    let mut file: VectorFile = serde_json::from_str(&raw).expect("valid cacophony json");

    let upstream_total = file.vectors.len();
    let wanted = wanted_protocol_names();
    file.vectors.retain(|v| wanted.contains(&v.protocol_name));

    // The filter is a claim about the corpus, so it is checked rather than
    // assumed: a source missing a cell would otherwise vendor a quietly
    // smaller matrix, and every replay would still pass.
    assert_eq!(
        file.vectors.len(),
        wanted.len(),
        "expected 17 patterns × 8 AESGCM suites = 136 (upstream had {upstream_total} vectors)"
    );
    for v in &file.vectors {
        check_invariants(v);
    }

    let mut out = serde_json::to_string_pretty(&file).expect("serialize");
    out.push('\n');
    std::fs::write(VECTORS_PATH, out).expect("write vendored corpus");
}

/// The vendored file is exactly what the filter says it is.
///
/// Unlike the extractor this is **not** `#[ignore]`d: it needs no upstream
/// corpus, so it runs on every `cargo test` and turns the vendored subset's
/// shape into a standing assertion rather than a claim in a markdown file.
#[test]
fn vendored_subset_matches_the_declared_filter() {
    let file = load_vectors();
    let wanted = wanted_protocol_names();

    assert_eq!(file.vectors.len(), 136, "136 vendored vectors");
    assert_eq!(wanted.len(), 136, "17 patterns × 8 AESGCM suites");

    // Every declared cell is present …
    for name in &wanted {
        assert!(
            file.vectors.iter().any(|v| &v.protocol_name == name),
            "missing vendored vector {name}"
        );
    }
    // … and nothing else is, so the count above cannot be met by duplicates.
    for v in &file.vectors {
        assert!(
            wanted.contains(&v.protocol_name),
            "unexpected vendored vector {}",
            v.protocol_name
        );
    }

    // Every entry satisfies the invariants the replays rely on.
    for v in &file.vectors {
        check_invariants(v);
    }

    // Every vendored vector really is an AESGCM one — the single mistake that
    // would make all 272 replays pass while proving nothing about AES-GCM is
    // vendoring the ChaChaPoly half by accident.
    for v in &file.vectors {
        assert!(
            v.protocol_name.contains("_AESGCM_"),
            "{} is not an AESGCM vector",
            v.protocol_name
        );
    }
}
