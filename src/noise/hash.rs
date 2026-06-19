//! Hash trait for Noise protocol hashing and HMAC.
//!
//! Beyond a plain digest, this trait carries the Noise-specific
//! constants (`BLOCK_LEN` for HMAC) and the Noise name component. The
//! concrete implementation ([`Blake2b`]) delegates the actual hashing
//! to `cryptoxide`.

/// A hash function usable in Noise handshakes.
pub trait Hash {
    /// Noise name component (e.g. `"BLAKE2b"`).
    const NAME: &'static str;

    /// Hash output size in bytes (`HASHLEN` in the Noise spec).
    const HASH_LEN: usize;

    /// Internal block size in bytes (for HMAC computation).
    const BLOCK_LEN: usize;

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

// ── BLAKE2b ─────────────────────────────────────────────────────

/// BLAKE2b with 512-bit output.
///
/// * HASHLEN = 64 bytes
/// * Block = 128 bytes
pub struct Blake2b;

impl Hash for Blake2b {
    const NAME: &'static str = "BLAKE2b";
    const HASH_LEN: usize = 64;
    const BLOCK_LEN: usize = 128;

    fn hash(data: &[u8]) -> Vec<u8> {
        use cryptoxide::blake2b::Blake2b as B2b;
        use cryptoxide::digest::Digest;

        let mut hasher = B2b::new(Self::HASH_LEN);
        Digest::input(&mut hasher, data);
        let mut out = vec![0u8; Self::HASH_LEN];
        Digest::result(&mut hasher, &mut out);
        out
    }

    fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
        use cryptoxide::blake2b::Blake2b as B2b;
        use cryptoxide::hmac::Hmac;
        use cryptoxide::mac::Mac;

        let mut mac = Hmac::new(B2b::new(Self::HASH_LEN), key);
        mac.input(data);
        let mut out = vec![0u8; Self::HASH_LEN];
        mac.raw_result(&mut out);
        out
    }

    fn hash_two(a: &[u8], b: &[u8]) -> Vec<u8> {
        use cryptoxide::blake2b::Blake2b as B2b;
        use cryptoxide::digest::Digest;

        let mut hasher = B2b::new(Self::HASH_LEN);
        Digest::input(&mut hasher, a);
        Digest::input(&mut hasher, b);
        let mut out = vec![0u8; Self::HASH_LEN];
        Digest::result(&mut hasher, &mut out);
        out
    }
}
