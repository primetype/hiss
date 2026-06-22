# hiss browser playground

A small, self-contained web app that runs [`hiss`](../)'s **type-level Noise
Protocol** handshakes entirely in your browser (WebAssembly). Both Noise peers —
initiator and responder — live in the same page and talk over an in-memory
pipe, so every byte you see is the real wire format. No server, no network.

Built with **Leptos** (CSR) + **Trunk** + **TailwindCSS**, depending on the
`hiss` crate by path.

## What it demonstrates

- **The full pattern family.** Pick any of hiss's ten patterns
  (`N, K, Kpsk0, NN, NK, XX, IK, IKpsk1, IX, XK`) from a dropdown and watch that
  pattern's handshake play out. Because hiss makes patterns *types*, each one is
  a distinct, statically-checked code path under the hood — the dropdown just
  selects which typed handshake runs.
- **The wire.** Every handshake message is captured and shown as raw bytes, with
  its direction and length.
- **Transport encryption.** After the handshake completes, your message is
  encrypted by one peer and decrypted by the other, both directions.
- **Continuity.** Your initiator identity (a long-term P-256 static key) is
  persisted in `localStorage`, so it survives reloads. "Regenerate" mints a new
  one.

> ⚠️ **Demo-grade only.** The identity key is stored *unencrypted* in
> `localStorage` — any script in this origin can read it. This is fine for a
> playground but is **not** a model for protecting a real Noise identity. For
> hardware-backed, non-exportable keys see hiss's provider docs (e.g. the Apple
> Secure Enclave provider).

## Run it

```bash
# One-time: the build tool and the wasm target.
cargo install trunk --locked
rustup target add wasm32-unknown-unknown   # also handled by rust-toolchain.toml

# Dev server with live reload. Trunk auto-downloads the pinned tailwindcss CLI
# (see Trunk.toml) on first run.
trunk serve --open
```

Then open <http://127.0.0.1:8080>.

## Build a static bundle

```bash
trunk build --release
```

The output in `dist/` is a fully static SPA — host it anywhere (GitHub Pages,
Netlify, …). When serving under a subpath, set the public URL so asset links
resolve:

```bash
trunk build --release --public-url "/your-repo-name/"
```

## Layout

| File | Purpose |
|------|---------|
| `src/noise.rs` | Bridge to `hiss`: per-pattern handshakes over an in-memory pipe, wire capture, transport round-trip, the persistent identity. |
| `src/app.rs`   | Leptos UI: identity card, pattern picker, transcript. |
| `src/main.rs`  | Mounts the app. |
| `Trunk.toml`   | Build config + pins the tailwindcss binary version. |
| `styles/input.css` | Tailwind v4 entry (`@import` + `@source` globs over the Rust sources). |

This crate is excluded from the published `hiss` package (see the root
`Cargo.toml` `exclude`), and stands alone as its own cargo workspace so it never
perturbs the core crate's build or release gates.
