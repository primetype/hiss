# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0]

`noise!` is now the only way to drive a handshake. The streaming I/O drivers
are gone.

### Removed

- **`SyncHandshake` and `AsyncHandshake`**, along with their `*Sending` /
  `*Receiving` / `*Transport` state types and the four constructors on
  `Noise` — `sync_initiator`, `sync_responder`, `async_initiator`,
  `async_responder`. Together these were 3,037 lines, about 19% of `src/`.

  Their replacement is the state machine `noise!` generates: one method per
  handshake message, each message a fixed-size `[u8; MSGn_SIZE]`, and no I/O.
  Framing is a `read_exact` of a compile-time constant — see
  `examples/tcp_xx_channel.rs`, which does exactly that over a real socket.

- **The `async-io` feature.** `tokio` leaves `[dependencies]` entirely; it
  remains a macOS/iOS platform dependency for the Secure Enclave offload, and
  a dev-dependency.

### Changed

- **A wrong-length handshake message is now a compile error rather than a
  runtime rejection.** `read_message_N` takes `&[u8; MSGn_SIZE]`, so a short
  or over-long buffer cannot be constructed at the call site. The
  truncation sweeps that asserted the old runtime behaviour are gone; the new
  behaviour is pinned by a `compile_fail` doctest on `noise!`.

- **The whole verification suite now runs through `noise!`.** The frozen
  known-answer vectors, both `snow` interop suites, the negative sweeps, the
  benchmarks and the in-crate unit tests previously exercised the driver, so
  the API users were told to reach for was covered only by a two-test bridge
  on a single pattern. All of it was converted; the oracles (frozen hex,
  `snow`) are unchanged, so the conversion is checked against something
  independent of the code path it replaced.

- **Benchmark numbers are not comparable across this release.** `BenchPipe`
  is gone: hiss and `snow` now both write into flat buffers, removing the I/O
  layer that used to sit inside hiss's measured region only.

### Documentation

- The `noise!` documentation now states that **the declared identifier is the
  Noise pattern name.** It becomes `Pattern::NAME`, which forms the protocol
  name seeding the initial handshake hash, so
  `noise! { pub Channel<X25519, ChaChaPoly, Blake2b> { … } }` produces
  `Noise_Channel_25519_ChaChaPoly_BLAKE2b` — self-consistent, and
  interoperable with nothing.

  Every copy-paste surface in the crate previously demonstrated that mistake
  and now names the type for its pattern: the README and crate-level
  Quickstarts and `examples/quickstart.rs` declare `pub XX`, the
  `AppleSecureEnclave` doctest declares `pub XX`, and
  `examples/tcp_ikpsk1_ceremony.rs` declares `pub IKpsk1` with the
  descriptive name on a `type Ceremony = IKpsk1` alias. The Quickstart's
  declaration is now exactly the one the `snow` interop tests drive.

- The README leads with the Quickstart, and the crate docs do too — it was
  the seventh of eight sections on docs.rs, so a reader passed six sections
  before reaching a line of usable code.

### Known issues

- **`demo/` does not build.** The browser playground is generic over pattern
  *and* curve with dispatch on a runtime selection; `noise!` requires both to
  be concrete. Porting it means monomorphising 11 patterns × 3 curves and
  rewiring the dispatch. It is excluded from the workspace, is not published,
  and is not covered by any release gate.

## [0.1.0]

Initial release.
