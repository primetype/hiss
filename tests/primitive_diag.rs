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

/// Verify our HMAC-BLAKE2b matches a manual ipad/opad implementation
/// (RFC 2104's construction, written out longhand here as the oracle).
#[test]
fn hmac_blake2b_matches_manual_ipad_opad() {
    let key = b"test-key-for-hmac";
    let data = b"test-data-for-hmac";

    let our_hmac = Blake2b::hmac(key, data);

    // Manual HMAC using ipad/opad, straight from RFC 2104.
    let block_len = 128;
    let mut ipad = vec![0x36u8; block_len];
    let mut opad = vec![0x5cu8; block_len];
    for i in 0..key.len() {
        ipad[i] ^= key[i];
        opad[i] ^= key[i];
    }
    let inner = Blake2b::hash_two(&ipad, data);
    let manual_hmac = Blake2b::hash_two(&opad, &inner);

    assert_eq!(our_hmac, manual_hmac);
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
