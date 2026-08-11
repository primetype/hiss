//! Primitive-level diagnostics, independent of the handshake framework:
//! they exercise the raw HMAC-BLAKE2b and ECDH implementations directly,
//! each against an oracle that is not this crate.
//!
//! Both oracles are self-contained — a hand-rolled ipad/opad HMAC and a NIST
//! CAVP vector — so nothing here needs a second Noise implementation to run.
//! The diagnostics that *did* compare against `snow`'s primitives now live in
//! `hiss-interop/tests/snow_diag.rs`, which runs occasionally rather than on
//! every `cargo test`.

use hiss::noise::Blake2b;
use hiss::noise::hash::Hash;

/// HMAC-BLAKE2b written out longhand from RFC 2104, as an oracle.
///
/// Built only from `Blake2b::hash` and `Blake2b::hash_two`, which the 85
/// BLAKE2b handshake replays pin independently of the key schedule — so this
/// cannot agree with a broken `Blake2b::hmac` by construction.
fn manual_hmac_blake2b(key: &[u8], data: &[u8]) -> Vec<u8> {
    // BLAKE2b's block is 128 bytes. RFC 2104: K' = H(K) when the key is
    // longer than the block, otherwise K itself; either way zero-padded to
    // the block by the `vec![]` initialisers below.
    let block_len = 128;
    let k = if key.len() > block_len {
        Blake2b::hash(key)
    } else {
        key.to_vec()
    };

    let mut ipad = vec![0x36u8; block_len];
    let mut opad = vec![0x5cu8; block_len];
    for i in 0..k.len() {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let inner = Blake2b::hash_two(&ipad, data);
    Blake2b::hash_two(&opad, &inner)
}

/// Verify our HMAC-BLAKE2b matches a manual ipad/opad implementation
/// (RFC 2104's construction, written out longhand as the oracle).
///
/// Two cases, and the second is the point: a key longer than BLAKE2b's
/// 128-byte block reaches the hash-the-key branch of the key schedule, which
/// no Noise handshake can — `mix_key` only ever keys HMAC with a HASHLEN
/// chaining key (64 bytes), so none of the 292 replays touches it. The
/// branch is reachable from consumer code through the public `Hash` trait.
#[test]
fn hmac_blake2b_matches_manual_ipad_opad() {
    // Short key: 17 bytes, well under the block.
    let key = b"test-key-for-hmac";
    let data = b"test-data-for-hmac";
    assert_eq!(Blake2b::hmac(key, data), manual_hmac_blake2b(key, data));

    // Long key: 131 bytes, over the 128-byte block, so K' = H(K).
    let long_key = [0xaa_u8; 131];
    let long_data = b"Test Using Larger Than Block-Size Key - Hash Key First";
    assert_eq!(
        Blake2b::hmac(&long_key, long_data),
        manual_hmac_blake2b(&long_key, long_data)
    );
}

/// Verify eccoxide ECDH against NIST ECCCDH P-256 test vector (Count=0).
#[test]
fn eccoxide_dh_matches_nist_vector() {
    use eccoxide::curve::sec2::p256r1::{FieldElement, Point, PointAffine, Scalar};

    let qcavs_x =
        hex::decode("700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287").unwrap();
    let qcavs_y =
        hex::decode("db71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ac").unwrap();
    let diut =
        hex::decode("7d7dc5f71eb29ddaf80d6214632eeae03d9058af1fb6d22ed80badb62bc1a534").unwrap();
    let ziut =
        hex::decode("46fc62106420ff012e54a434fbdd2d25ccc5852060561e68040dd7778997bd7b").unwrap();

    let x = FieldElement::from_slice(&qcavs_x).unwrap();
    let y = FieldElement::from_slice(&qcavs_y).unwrap();
    let peer = Point::from(&PointAffine::from_coordinate(&x, &y).unwrap());
    let scalar = Scalar::from_slice(&diut).unwrap();

    let shared = (&scalar * &peer).to_affine().unwrap();
    let (shared_x, _) = shared.to_coordinate();

    assert_eq!(shared_x.to_bytes().as_slice(), ziut.as_slice());
}
