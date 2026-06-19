//! Wycheproof ECDSA verification vectors (secp256r1, SHA-256).
//!
//! Drives the crate's public verify path — [`P256Signature::try_from_asn1`]
//! then [`P256r1PublicKey::verify`] — over Google Project Wycheproof's
//! DER-encoded ECDSA corpus. This is the acceptance test for **both** the
//! hardened ASN.1 reader (the `InvalidEncoding` / `BerEncodedSignature` /
//! `InvalidTypesInSignature` / `MissingZero` groups all expect rejection)
//! and the ECDSA verify arithmetic.
//!
//! Vectors are vendored under `tests/vectors/wycheproof/` (Apache-2.0; see
//! that directory's `PROVENANCE.md`).

use super::{P256Signature, P256r1PublicKey};
use serde::Deserialize;

const VECTORS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/vectors/wycheproof/ecdsa_secp256r1_sha256_test.json"
));

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TestFile {
    number_of_tests: usize,
    test_groups: Vec<Group>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Group {
    public_key: PublicKey,
    tests: Vec<TestCase>,
}

#[derive(Deserialize)]
struct PublicKey {
    /// SEC1 uncompressed point as hex (`04 || x || y`).
    uncompressed: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TestCase {
    tc_id: u32,
    comment: String,
    #[serde(default)]
    flags: Vec<String>,
    msg: String,
    sig: String,
    result: String,
}

#[test]
fn wycheproof_ecdsa_secp256r1_sha256() {
    let file: TestFile = serde_json::from_str(VECTORS).expect("valid wycheproof json");

    let mut total = 0usize;
    let mut mismatches: Vec<String> = Vec::new();

    for group in &file.test_groups {
        let pk_bytes = hex::decode(&group.public_key.uncompressed).expect("hex public key");
        let pk = P256r1PublicKey::from_bytes(&pk_bytes)
            .expect("wycheproof group public keys are valid secp256r1 points");

        for case in &group.tests {
            total += 1;
            let msg = hex::decode(&case.msg).expect("hex msg");
            let sig = hex::decode(&case.sig).expect("hex sig");

            // `verify` hashes the raw message itself and takes a DER sig.
            // A parse failure is a rejection — the correct outcome for the
            // malformed-encoding `invalid` cases.
            let accepted = match P256Signature::try_from_asn1(&sig) {
                Ok(sig) => pk.verify(sig, &msg),
                Err(_) => false,
            };

            let expected = match case.result.as_str() {
                "valid" => true,
                "invalid" => false,
                other => panic!("tc{}: unexpected result {other:?}", case.tc_id),
            };

            if accepted != expected {
                mismatches.push(format!(
                    "tc{}: expected={} accepted={} | {} | flags={:?}",
                    case.tc_id, case.result, accepted, case.comment, case.flags
                ));
            }
        }
    }

    assert_eq!(total, file.number_of_tests, "consumed every vector");
    assert!(
        mismatches.is_empty(),
        "{} / {} Wycheproof ECDSA mismatches:\n{}",
        mismatches.len(),
        total,
        mismatches.join("\n"),
    );
}
