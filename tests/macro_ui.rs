//! Compile-fail (UI) tests pinning the twelve surface-syntax diagnostics the
//! `noise!` parser emits (`hiss-macros/src/parse.rs`).
//!
//! Each case in `tests/ui/*.rs` invokes `hiss::noise! { … }` with a
//! deliberately malformed pattern and is matched against its committed
//! `.stderr`. Ten of the twelve pinned messages are `compile_error!`s
//! produced during **parsing** (before code generation runs), so the
//! diagnostics are stable across compiler versions — the usual source of
//! trybuild stderr churn. The exceptions are `suite_arity`, which pins syn's
//! generic ``expected `,` `` from the suite-header parse, and
//! `payload_not_integer`, which pins syn's `expected integer literal` from
//! the `[N]` payload suffix; if those snapshots churn on a syn upgrade,
//! regenerate them with `TRYBUILD=overwrite`. In every
//! case the unresolved `X25519`/`ChaChaPoly`/`Blake2b` suite paths never
//! matter (a parse error aborts before any `::hiss` path is emitted).
//!
//! Placement: this harness and its cases live in the **root** crate, not in
//! `hiss-macros`. `hiss` is a non-virtual workspace whose CI gate commands are
//! package-scoped to the root (`cargo test --all-features`), so a suite under
//! `hiss-macros/tests/` would never execute. The cases sit in the `tests/ui/`
//! **subdirectory**, which cargo does not treat as integration-test targets:
//! they are compiled only by trybuild at test time (never by `cargo build`,
//! `clippy`, `fmt`, or the MSRV `cargo check` job), so their intentionally
//! malformed input is never linted and the stderr snapshots are only ever
//! compared under `cargo test` on stable.

#[test]
fn ui() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/*.rs");
}
