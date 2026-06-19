//! Google Project Wycheproof vectors for the P-256 software backend.
//!
//! * **ECDSA** ([`wycheproof_ecdsa_secp256r1_sha256`]) drives the verify
//!   path — [`P256Signature::try_from_asn1`] then
//!   [`P256r1PublicKey::verify`] — over the DER-encoded secp256r1/SHA-256
//!   corpus. It is the acceptance test for both the hardened ASN.1 reader
//!   (the malformed-encoding groups all expect rejection) and the verify
//!   arithmetic.
//! * **ECDH** ([`wycheproof_ecdh_secp256r1`]) drives
//!   [`P256r1PrivateKey::dh`] over the raw-EC-point corpus, checking that
//!   valid agreements match the expected shared secret and that
//!   off-curve / wrong-curve / malformed peer points are rejected.
//!
//! Vectors are vendored under `tests/vectors/wycheproof/` (Apache-2.0; see
//! that directory's `PROVENANCE.md`).

use super::{P256Signature, P256r1PrivateKey, P256r1PublicKey};
use serde::Deserialize;

/// Decode a hex big-endian integer into a 32-byte scalar, left-padding a
/// short value and stripping leading zero padding from a longer one.
/// Returns `None` if the magnitude exceeds 32 bytes.
fn scalar32(hex_str: &str) -> Option<[u8; 32]> {
    let raw = hex::decode(hex_str).ok()?;
    let mut out = [0u8; 32];
    if raw.len() <= 32 {
        out[32 - raw.len()..].copy_from_slice(&raw);
    } else {
        let (pad, tail) = raw.split_at(raw.len() - 32);
        if pad.iter().any(|&b| b != 0) {
            return None;
        }
        out.copy_from_slice(tail);
    }
    Some(out)
}

// ── ECDSA ───────────────────────────────────────────────────────

const ECDSA_VECTORS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/vectors/wycheproof/ecdsa_secp256r1_sha256_test.json"
));

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EcdsaFile {
    number_of_tests: usize,
    test_groups: Vec<EcdsaGroup>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EcdsaGroup {
    public_key: EcdsaPublicKey,
    tests: Vec<EcdsaCase>,
}

#[derive(Deserialize)]
struct EcdsaPublicKey {
    /// SEC1 uncompressed point as hex (`04 || x || y`).
    uncompressed: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EcdsaCase {
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
    let file: EcdsaFile = serde_json::from_str(ECDSA_VECTORS).expect("valid wycheproof json");

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

// ── ECDH ────────────────────────────────────────────────────────

const ECDH_VECTORS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/vectors/wycheproof/ecdh_secp256r1_ecpoint_test.json"
));

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EcdhFile {
    number_of_tests: usize,
    test_groups: Vec<EcdhGroup>,
}

#[derive(Deserialize)]
struct EcdhGroup {
    tests: Vec<EcdhCase>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EcdhCase {
    tc_id: u32,
    comment: String,
    #[serde(default)]
    flags: Vec<String>,
    /// Peer public key as a raw SEC1 EC point (hex).
    public: String,
    /// Our private scalar (hex big-endian).
    private: String,
    /// Expected shared-secret x-coordinate (hex); empty for `invalid`.
    #[serde(default)]
    shared: String,
    result: String,
}

/// Run one agreement, returning the 32-byte shared secret, or `None` if
/// any input is rejected (invalid private, un-decodable / off-curve peer
/// point, or degenerate agreement).
fn ecdh(private: &str, public: &str) -> Option<[u8; 32]> {
    let sk = P256r1PrivateKey::from_bytes(scalar32(private)?).ok()?;
    let pk = P256r1PublicKey::from_bytes(&hex::decode(public).ok()?).ok()?;
    Some(*sk.dh(&pk).ok()?.as_bytes())
}

#[test]
fn wycheproof_ecdh_secp256r1() {
    let file: EcdhFile = serde_json::from_str(ECDH_VECTORS).expect("valid wycheproof json");

    let mut total = 0usize;
    let mut mismatches: Vec<String> = Vec::new();

    for group in &file.test_groups {
        for case in &group.tests {
            total += 1;
            let got = ecdh(&case.private, &case.public);
            let expected = if case.shared.is_empty() {
                None
            } else {
                Some(scalar32(&case.shared).expect("hex shared secret"))
            };

            let ok = match case.result.as_str() {
                // Must agree and match the published secret.
                "valid" => got == expected,
                // Must be rejected (off-curve / wrong-curve / malformed).
                "invalid" => got.is_none(),
                // Policy-dependent (e.g. compressed point, which this
                // backend accepts): if we compute one it must match;
                // rejecting outright is also conformant.
                "acceptable" => got.is_none() || got == expected,
                other => panic!("tc{}: unexpected result {other:?}", case.tc_id),
            };

            if !ok {
                mismatches.push(format!(
                    "tc{}: result={} matched_expected={} | {} | flags={:?}",
                    case.tc_id,
                    case.result,
                    got == expected,
                    case.comment,
                    case.flags
                ));
            }
        }
    }

    assert_eq!(total, file.number_of_tests, "consumed every vector");
    assert!(
        mismatches.is_empty(),
        "{} / {} Wycheproof ECDH mismatches:\n{}",
        mismatches.len(),
        total,
        mismatches.join("\n"),
    );
}
