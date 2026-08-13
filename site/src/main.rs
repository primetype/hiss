//! The hiss one-page site.
//!
//! A pure client-side (CSR) Leptos app, deployed to GitHub Pages. Phase 1 is
//! the static, brand-complete shell; phase 2 replaces the fixed XX trace with
//! the interactive device (toggles → pattern → fixture-replayed handshake).

mod app;

fn main() {
    // Surface Rust panics in the browser console with a readable backtrace.
    console_error_panic_hook::set_once();
    leptos::mount::mount_to_body(app::App);
}
