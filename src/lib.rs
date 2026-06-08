//! Cryptographic primitives for the Bubble protocol.
//!
//! This crate provides the building blocks used throughout Bubble's
//! trust ceremony and encrypted transport:
//!
//! * **[`curve`]** — Elliptic curve operations (ECDSA signing, ECDH
//!   key exchange) on NIST P-256 (secp256r1). Includes both a
//!   pure-software implementation (via `eccoxide`) and a macOS
//!   Secure Enclave backend.
//!
//! * **[`noise`]** — Compile-time Noise protocol descriptor. Encodes
//!   the handshake pattern, curve, cipher, and hash as zero-sized
//!   types so all buffer sizes and operations are known at
//!   monomorphisation time.
//!
//! * **[`zeroize`]** — Volatile zeroing of secret material.
//!   Prevents the compiler from eliding zero-fills via
//!   `ptr::write_volatile` and a compiler fence.
//!
//! Internal modules (not re-exported):
//!
//! * `asn1` — Minimal ASN.1 DER reader (and test-only writer) used
//!   to decode ECDSA signatures produced by Apple's Security
//!   framework, which returns them in X9.62 / DER format rather
//!   than raw `(r, s)` bytes.

#[cfg(any(target_os = "macos", target_os = "ios", test))]
mod asn1;
pub mod curve;
pub mod noise;
pub mod psk;
pub mod zeroize;

/// Compute a BLAKE2b-128 digest (16 bytes) of `data`.
///
/// Used for `message_id` derivation in DAG headers — compact,
/// collision-resistant identifier with 2^64 birthday resistance.
pub fn blake2b_128(data: &[u8]) -> [u8; 16] {
    use cryptoxide::blake2b::Blake2b;
    use cryptoxide::digest::Digest;

    let mut hasher = Blake2b::new(16);
    hasher.input(data);
    let mut out = [0u8; 16];
    hasher.result(&mut out);
    out
}

/// Compute a BLAKE2b-256 digest (32 bytes) of `data`.
///
/// Used for `content_hash` in DAG message headers.
pub fn blake2b_256(data: &[u8]) -> [u8; 32] {
    use cryptoxide::blake2b::Blake2b;
    use cryptoxide::digest::Digest;

    let mut hasher = Blake2b::new(32);
    hasher.input(data);
    let mut out = [0u8; 32];
    hasher.result(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn blake2b_128_deterministic(data in any::<Vec<u8>>()) {
            let a = blake2b_128(&data);
            let b = blake2b_128(&data);
            prop_assert_eq!(a, b);
        }

        #[test]
        fn blake2b_128_output_is_16_bytes(data in any::<Vec<u8>>()) {
            prop_assert_eq!(blake2b_128(&data).len(), 16);
        }

        #[test]
        fn blake2b_128_different_inputs_differ(
            a in any::<Vec<u8>>(),
            b in any::<Vec<u8>>(),
        ) {
            prop_assume!(a != b);
            prop_assert_ne!(blake2b_128(&a), blake2b_128(&b));
        }

        #[test]
        fn blake2b_256_deterministic(data in any::<Vec<u8>>()) {
            let a = blake2b_256(&data);
            let b = blake2b_256(&data);
            prop_assert_eq!(a, b);
        }

        #[test]
        fn blake2b_256_output_is_32_bytes(data in any::<Vec<u8>>()) {
            prop_assert_eq!(blake2b_256(&data).len(), 32);
        }

        #[test]
        fn blake2b_256_different_inputs_differ(
            a in any::<Vec<u8>>(),
            b in any::<Vec<u8>>(),
        ) {
            prop_assume!(a != b);
            prop_assert_ne!(blake2b_256(&a), blake2b_256(&b));
        }
    }
}
