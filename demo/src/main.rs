//! Browser playground for the `hiss` Noise Protocol crate.
//!
//! A pure client-side (CSR) Leptos app: it runs `hiss`'s synchronous,
//! type-level Noise handshakes entirely in WebAssembly — both peers live in
//! the same page and talk over an in-memory pipe — and visualises every
//! handshake message on the wire. No server, no network. See [`noise`] for
//! the bridge to the crate and [`app`] for the UI.

mod app;
mod noise;

fn main() {
    // Surface Rust panics in the browser console with a readable backtrace.
    console_error_panic_hook::set_once();
    leptos::mount::mount_to_body(app::App);
}
