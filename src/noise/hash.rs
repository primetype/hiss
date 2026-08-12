//! Hash trait for Noise protocol hashing and HMAC.
//!
//! Beyond a plain digest, this trait carries the Noise-specific
//! output length and the Noise name component. The concrete
//! implementations ([`Blake2b`], [`Blake2s`], [`Sha256`] and [`Sha512`])
//! — the specification's four official hashes — delegate the actual
//! hashing to `cryptoxide`.
//!
//! HMAC is delegated too, but only for the SHA-2 pair: `cryptoxide`'s
//! `hmac::Context<A: Algorithm>` ships `Algorithm` impls for `Sha1`,
//! `Sha256` and `Sha512` and nothing else. HMAC-BLAKE2 of either width is
//! this crate's own — a private `hmac_blake2` module in this file supplies
//! the RFC 2104 key schedule that the two BLAKE2 hashes drive that same
//! `hmac::Context` with.

/// A hash function usable in Noise handshakes.
pub trait Hash {
    /// Noise name component (e.g. `"BLAKE2b"`).
    const NAME: &'static str;

    /// Hash output size in bytes (`HASHLEN` in the Noise spec).
    const HASH_LEN: usize;

    /// Hash `data`, returning `HASH_LEN` bytes.
    fn hash(data: &[u8]) -> Vec<u8>;

    /// Compute HMAC over `data` with the given `key`, returning
    /// `HASH_LEN` bytes.
    fn hmac(key: &[u8], data: &[u8]) -> Vec<u8>;

    /// Incremental hash: `H(a || b)`, returning `HASH_LEN` bytes.
    ///
    /// Used by `mix_hash` to avoid allocating a concatenation buffer.
    fn hash_two(a: &[u8], b: &[u8]) -> Vec<u8>;
}

// ── HMAC-BLAKE2 ─────────────────────────────────────────────────
//
// Kept private: these are an implementation detail of `Blake2b::hmac` and
// `Blake2s::hmac`, not public API. `#![warn(missing_docs)]` therefore does
// not reach them, and no `cryptoxide` type appears in a hiss signature.

/// The RFC 2104 key schedule for BLAKE2b-512 and BLAKE2s-256.
///
/// `cryptoxide` 0.6 replaced the generic `Hmac<D: Digest>` with
/// `hmac::Context<A: hmac::Algorithm>` and ships `Algorithm` impls for
/// `Sha1`, `Sha256` and `Sha512` only — there is no HMAC-BLAKE2 of either
/// width, and the orphan rule forbids implementing `cryptoxide`'s trait for
/// `cryptoxide`'s type. So the two marker types below stand in for the
/// algorithm, and this module carries the key schedule that `cryptoxide`'s
/// own crate-private `init_key!` macro carries for the hashes it does ship.
///
/// The schedule is RFC 2104 verbatim: `K' = H(K)` when `K` is longer than
/// the block, otherwise `K` zero-padded to the block; the inner context
/// absorbs `K' ⊕ ipad` and the outer `K' ⊕ opad`; `hmac::Context` then feeds
/// the inner digest to the outer context.
mod hmac_blake2 {
    use cryptoxide::hashing::blake2b::{Blake2b as B2b, Context as CtxB};
    use cryptoxide::hashing::blake2s::{Blake2s as B2s, Context as CtxS};
    use cryptoxide::hmac::{Algorithm, Tag};

    /// Inner padding byte (RFC 2104).
    const IPAD: u8 = 0x36;
    /// Outer padding byte (RFC 2104).
    const OPAD: u8 = 0x5c;

    /// HMAC marker for BLAKE2b-512.
    pub(super) struct Blake2bHmac;

    impl Algorithm for Blake2bHmac {
        // Sourced from upstream rather than written as magic literals:
        // `BLOCK_BYTES` resolves to 128 and `OUTPUT_BITS / 8` to 64.
        const BLOCK_SIZE: usize = B2b::<512>::BLOCK_BYTES;
        const OUTPUT_SIZE: usize = B2b::<512>::OUTPUT_BITS / 8;

        type Context = CtxB<512>;
        // Required by the trait; `hmac::Context` never names it.
        type Output = [u8; Self::OUTPUT_SIZE];
        type MacOutput = Tag<{ Self::OUTPUT_SIZE }>;

        fn init(key: &[u8]) -> (Self::Context, Self::Context) {
            let mut k = [0u8; Self::BLOCK_SIZE];
            if key.len() <= Self::BLOCK_SIZE {
                k[..key.len()].copy_from_slice(key);
            } else {
                // RFC 2104: K' = H(K) when |K| > block size, zero-padded.
                let mut kh = B2b::<512>::new();
                kh.update_mut(key);
                // Bound so it can be zeroized: a digest of the key is
                // key-equivalent material.
                let mut kd = kh.finalize();
                k[..Self::OUTPUT_SIZE].copy_from_slice(&kd);
                crate::zeroize::zeroize_array(&mut kd);
            }

            // UNKEYED contexts. `new_keyed` is BLAKE2's *native* keyed mode,
            // a different MAC from HMAC-BLAKE2 — never use it here.
            let mut inner = B2b::<512>::new();
            let mut outer = B2b::<512>::new();

            let mut mix = [0u8; Self::BLOCK_SIZE];
            for (m, kb) in mix.iter_mut().zip(k.iter()) {
                *m = kb ^ IPAD;
            }
            inner.update_mut(&mix);
            for (m, kb) in mix.iter_mut().zip(k.iter()) {
                *m = kb ^ OPAD;
            }
            outer.update_mut(&mix);

            crate::zeroize::zeroize_array(&mut k);
            crate::zeroize::zeroize_array(&mut mix);
            (inner, outer)
        }

        fn update(context: &mut Self::Context, input: &[u8]) {
            context.update_mut(input);
        }

        // NOTE the direction: `hmac::Context::finalize` calls
        // `H::feed(&mut self.outer, &mut self.inner)`, so `context` is OUTER
        // and `other` is INNER. Swapping them silently computes the outer
        // digest fed into the inner context — garbage that is still
        // deterministic and still the right length.
        fn feed(context: &mut Self::Context, other: &mut Self::Context) {
            let inner_digest = other.finalize_reset();
            context.update_mut(&inner_digest);
        }

        fn finalize(context: &mut Self::Context) -> Self::MacOutput {
            Tag(context.finalize_reset())
        }

        fn finalize_at(context: &mut Self::Context, out: &mut [u8]) {
            context.finalize_reset_at(out);
        }
    }

    /// HMAC marker for BLAKE2s-256.
    pub(super) struct Blake2sHmac;

    impl Algorithm for Blake2sHmac {
        // `BLOCK_BYTES` resolves to 64 and `OUTPUT_BITS / 8` to 32.
        const BLOCK_SIZE: usize = B2s::<256>::BLOCK_BYTES;
        const OUTPUT_SIZE: usize = B2s::<256>::OUTPUT_BITS / 8;

        type Context = CtxS<256>;
        // Required by the trait; `hmac::Context` never names it.
        type Output = [u8; Self::OUTPUT_SIZE];
        type MacOutput = Tag<{ Self::OUTPUT_SIZE }>;

        fn init(key: &[u8]) -> (Self::Context, Self::Context) {
            let mut k = [0u8; Self::BLOCK_SIZE];
            if key.len() <= Self::BLOCK_SIZE {
                k[..key.len()].copy_from_slice(key);
            } else {
                // RFC 2104: K' = H(K) when |K| > block size, zero-padded.
                let mut kh = B2s::<256>::new();
                kh.update_mut(key);
                // Bound so it can be zeroized: a digest of the key is
                // key-equivalent material.
                let mut kd = kh.finalize();
                k[..Self::OUTPUT_SIZE].copy_from_slice(&kd);
                crate::zeroize::zeroize_array(&mut kd);
            }

            // UNKEYED contexts. `new_keyed` is BLAKE2's *native* keyed mode,
            // a different MAC from HMAC-BLAKE2 — never use it here.
            let mut inner = B2s::<256>::new();
            let mut outer = B2s::<256>::new();

            let mut mix = [0u8; Self::BLOCK_SIZE];
            for (m, kb) in mix.iter_mut().zip(k.iter()) {
                *m = kb ^ IPAD;
            }
            inner.update_mut(&mix);
            for (m, kb) in mix.iter_mut().zip(k.iter()) {
                *m = kb ^ OPAD;
            }
            outer.update_mut(&mix);

            crate::zeroize::zeroize_array(&mut k);
            crate::zeroize::zeroize_array(&mut mix);
            (inner, outer)
        }

        fn update(context: &mut Self::Context, input: &[u8]) {
            context.update_mut(input);
        }

        // Same direction note as `Blake2bHmac::feed`: `context` is OUTER,
        // `other` is INNER.
        fn feed(context: &mut Self::Context, other: &mut Self::Context) {
            let inner_digest = other.finalize_reset();
            context.update_mut(&inner_digest);
        }

        fn finalize(context: &mut Self::Context) -> Self::MacOutput {
            Tag(context.finalize_reset())
        }

        fn finalize_at(context: &mut Self::Context, out: &mut [u8]) {
            context.finalize_reset_at(out);
        }
    }
}

// ── BLAKE2b ─────────────────────────────────────────────────────

/// BLAKE2b with 512-bit output.
///
/// * HASHLEN = 64 bytes
/// * Block = 128 bytes
#[derive(Debug, Clone, Copy, Default)]
pub struct Blake2b;

impl Hash for Blake2b {
    const NAME: &'static str = "BLAKE2b";
    const HASH_LEN: usize = 64;

    fn hash(data: &[u8]) -> Vec<u8> {
        use cryptoxide::hashing::blake2b::Blake2b as B2b;

        // The const parameter is BITS, not bytes: 512 bits = HASH_LEN.
        let mut ctx = B2b::<512>::new();
        ctx.update_mut(data);
        ctx.finalize().to_vec()
    }

    fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
        use cryptoxide::hmac;

        let mut ctx = hmac::Context::<hmac_blake2::Blake2bHmac>::new(key);
        ctx.update(data);
        ctx.finalize().0.to_vec()
    }

    fn hash_two(a: &[u8], b: &[u8]) -> Vec<u8> {
        use cryptoxide::hashing::blake2b::Blake2b as B2b;

        let mut ctx = B2b::<512>::new();
        ctx.update_mut(a);
        ctx.update_mut(b);
        ctx.finalize().to_vec()
    }
}

// ── BLAKE2s ─────────────────────────────────────────────────────

/// BLAKE2s with 256-bit output.
///
/// * HASHLEN = 32 bytes
/// * Block = 64 bytes
#[derive(Debug, Clone, Copy, Default)]
pub struct Blake2s;

impl Hash for Blake2s {
    const NAME: &'static str = "BLAKE2s";
    const HASH_LEN: usize = 32;

    fn hash(data: &[u8]) -> Vec<u8> {
        use cryptoxide::hashing::blake2s::Blake2s as B2s;

        // The const parameter is BITS, not bytes: 256 bits = HASH_LEN.
        let mut ctx = B2s::<256>::new();
        ctx.update_mut(data);
        ctx.finalize().to_vec()
    }

    fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
        use cryptoxide::hmac;

        let mut ctx = hmac::Context::<hmac_blake2::Blake2sHmac>::new(key);
        ctx.update(data);
        ctx.finalize().0.to_vec()
    }

    fn hash_two(a: &[u8], b: &[u8]) -> Vec<u8> {
        use cryptoxide::hashing::blake2s::Blake2s as B2s;

        let mut ctx = B2s::<256>::new();
        ctx.update_mut(a);
        ctx.update_mut(b);
        ctx.finalize().to_vec()
    }
}

// ── SHA-256 ─────────────────────────────────────────────────────

/// SHA-256.
///
/// * HASHLEN = 32 bytes
/// * Block = 64 bytes
#[derive(Debug, Clone, Copy, Default)]
pub struct Sha256;

impl Hash for Sha256 {
    const NAME: &'static str = "SHA256";
    const HASH_LEN: usize = 32;

    fn hash(data: &[u8]) -> Vec<u8> {
        use cryptoxide::hashing::sha2::Sha256 as S256;

        let mut ctx = S256::new();
        ctx.update_mut(data);
        ctx.finalize().to_vec()
    }

    fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
        use cryptoxide::hashing::sha2::Sha256 as S256;
        use cryptoxide::hmac;

        // Shipped by cryptoxide (`hmac.rs`, gated on `sha2`) — no local
        // marker type needed for the SHA-2 pair.
        let mut ctx = hmac::Context::<S256>::new(key);
        ctx.update(data);
        ctx.finalize().0.to_vec()
    }

    fn hash_two(a: &[u8], b: &[u8]) -> Vec<u8> {
        use cryptoxide::hashing::sha2::Sha256 as S256;

        let mut ctx = S256::new();
        ctx.update_mut(a);
        ctx.update_mut(b);
        ctx.finalize().to_vec()
    }
}

// ── SHA-512 ─────────────────────────────────────────────────────

/// SHA-512.
///
/// * HASHLEN = 64 bytes
/// * Block = 128 bytes
#[derive(Debug, Clone, Copy, Default)]
pub struct Sha512;

impl Hash for Sha512 {
    const NAME: &'static str = "SHA512";
    const HASH_LEN: usize = 64;

    fn hash(data: &[u8]) -> Vec<u8> {
        use cryptoxide::hashing::sha2::Sha512 as S512;

        let mut ctx = S512::new();
        ctx.update_mut(data);
        ctx.finalize().to_vec()
    }

    fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
        use cryptoxide::hashing::sha2::Sha512 as S512;
        use cryptoxide::hmac;

        // Shipped by cryptoxide (`hmac.rs`, gated on `sha2`) — no local
        // marker type needed for the SHA-2 pair.
        let mut ctx = hmac::Context::<S512>::new(key);
        ctx.update(data);
        ctx.finalize().0.to_vec()
    }

    fn hash_two(a: &[u8], b: &[u8]) -> Vec<u8> {
        use cryptoxide::hashing::sha2::Sha512 as S512;

        let mut ctx = S512::new();
        ctx.update_mut(a);
        ctx.update_mut(b);
        ctx.finalize().to_vec()
    }
}
