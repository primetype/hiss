# hiss one-page site

The public site for [`hiss`](../): a single page, built with **Leptos** (CSR)
+ **Trunk** + **TailwindCSS**, deployed to GitHub Pages by
`.github/workflows/site-pages.yml` (which replaced the old demo deployment —
one repo has one Pages slot).

Brand: "signal in the static" — the tokens in `styles/input.css` mirror the
brand guidelines. Laws: cyan means interactive-or-live, warn orange means
security caveat, and nothing else may use them.

## Status: phase 1 of 3

- **Phase 1 (this):** static, brand-complete shell — hero, XX device preview,
  proof strip, footer.
- **Phase 2:** the interactive device — "who has to prove themselves?"
  toggles resolving to a real pattern, replaying handshake traces **generated
  by hiss and pinned by a test**. The shipped WASM gets no hiss dependency;
  hiss arrives only as a dev-dependency of the fixture-pinning test, which CI
  runs before every deploy.
- **Phase 3:** the compiler moment (the pinned `E0277` diagnostic), OG card,
  polish.

The XX byte counts currently in `src/app.rs` (32 / 96 / 64) are literals;
phase 2 replaces them with the pinned fixture table.

## Run it

```bash
cargo install trunk --locked
rustup target add wasm32-unknown-unknown   # also handled by rust-toolchain.toml

trunk serve --open
```

## Build a static bundle

```bash
trunk build --release
```

CI passes `--public-url "/hiss/"` because a project Pages site serves under
`https://<owner>.github.io/<repo>/`.

This crate is excluded from the published `hiss` package (root `Cargo.toml`
`exclude`) and stands alone as its own cargo workspace, so it never perturbs
the core crate's build or release gates. Payload budget: 100 KB gzipped
(wasm + js + css), checked in the deploy workflow.
