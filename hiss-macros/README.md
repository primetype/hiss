# hiss-macros

Proc-macro companion to the [`hiss`](https://crates.io/crates/hiss) crate:
the `noise!` macro turns a Noise handshake pattern — written in the exact
notation of the [Noise specification](https://noiseprotocol.org/noise.html)
— into a pair of documented, sans-io, type-state handshake state machines
with compile-time message sizes.

Do not depend on this crate directly. `hiss` requires it and re-exports the
macro as `hiss::noise!` — there is no feature to enable.

```rust
hiss::noise! {
    /// Ceremony channel between two enrolled devices.
    pub IKpsk1<X25519, ChaChaPoly, Blake2b> {
        <- s
        ...
        -> e, es, s, ss, psk
        <- e, ee, se
    }
}
```

## License

Licensed under either of [Apache License, Version 2.0](../LICENSE-APACHE)
or [MIT license](../LICENSE-MIT) at your option.
