//! Hash trait for Noise protocol hashing and HMAC.
//!
//! Beyond a plain digest, this trait carries the Noise-specific
//! output length and the Noise name component. The concrete
//! implementations ([`Blake2b`], [`Blake2s`], [`Sha256`] and [`Sha512`])
//! — the specification's four official hashes — delegate the actual
//! hashing to `cryptoxide`.

// `cryptoxide`'s `Digest::result` and `Mac::raw_result` copy into the slice
// they are handed and panic on a length mismatch, so every output buffer in
// every impl below is allocated at exactly `HASH_LEN`.

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
        use cryptoxide::blake2s::Blake2s as B2s;
        use cryptoxide::digest::Digest;

        let mut hasher = B2s::new(Self::HASH_LEN);
        Digest::input(&mut hasher, data);
        let mut out = vec![0u8; Self::HASH_LEN];
        Digest::result(&mut hasher, &mut out);
        out
    }

    fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
        use cryptoxide::blake2s::Blake2s as B2s;
        use cryptoxide::hmac::Hmac;
        use cryptoxide::mac::Mac;

        let mut mac = Hmac::new(B2s::new(Self::HASH_LEN), key);
        mac.input(data);
        let mut out = vec![0u8; Self::HASH_LEN];
        mac.raw_result(&mut out);
        out
    }

    fn hash_two(a: &[u8], b: &[u8]) -> Vec<u8> {
        use cryptoxide::blake2s::Blake2s as B2s;
        use cryptoxide::digest::Digest;

        let mut hasher = B2s::new(Self::HASH_LEN);
        Digest::input(&mut hasher, a);
        Digest::input(&mut hasher, b);
        let mut out = vec![0u8; Self::HASH_LEN];
        Digest::result(&mut hasher, &mut out);
        out
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
        use cryptoxide::digest::Digest;
        use cryptoxide::sha2::Sha256 as S256;

        let mut hasher = S256::new();
        Digest::input(&mut hasher, data);
        let mut out = vec![0u8; Self::HASH_LEN];
        Digest::result(&mut hasher, &mut out);
        out
    }

    fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
        use cryptoxide::hmac::Hmac;
        use cryptoxide::mac::Mac;
        use cryptoxide::sha2::Sha256 as S256;

        let mut mac = Hmac::new(S256::new(), key);
        mac.input(data);
        let mut out = vec![0u8; Self::HASH_LEN];
        mac.raw_result(&mut out);
        out
    }

    fn hash_two(a: &[u8], b: &[u8]) -> Vec<u8> {
        use cryptoxide::digest::Digest;
        use cryptoxide::sha2::Sha256 as S256;

        let mut hasher = S256::new();
        Digest::input(&mut hasher, a);
        Digest::input(&mut hasher, b);
        let mut out = vec![0u8; Self::HASH_LEN];
        Digest::result(&mut hasher, &mut out);
        out
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
        use cryptoxide::digest::Digest;
        use cryptoxide::sha2::Sha512 as S512;

        let mut hasher = S512::new();
        Digest::input(&mut hasher, data);
        let mut out = vec![0u8; Self::HASH_LEN];
        Digest::result(&mut hasher, &mut out);
        out
    }

    fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
        use cryptoxide::hmac::Hmac;
        use cryptoxide::mac::Mac;
        use cryptoxide::sha2::Sha512 as S512;

        let mut mac = Hmac::new(S512::new(), key);
        mac.input(data);
        let mut out = vec![0u8; Self::HASH_LEN];
        mac.raw_result(&mut out);
        out
    }

    fn hash_two(a: &[u8], b: &[u8]) -> Vec<u8> {
        use cryptoxide::digest::Digest;
        use cryptoxide::sha2::Sha512 as S512;

        let mut hasher = S512::new();
        Digest::input(&mut hasher, a);
        Digest::input(&mut hasher, b);
        let mut out = vec![0u8; Self::HASH_LEN];
        Digest::result(&mut hasher, &mut out);
        out
    }
}
