//! Wycheproof AES-GCM — the **primitive-level** leg of the validation.
//!
//! This file drives `cryptoxide_git::aes_gcm::AesGcm256` directly. hiss is not
//! involved at all: no handshake, no `Cipher` trait, no Noise framing. The
//! question it answers is narrow and worth keeping narrow — *is the primitive
//! AES-256-GCM?* — against a corpus written by Google, i.e. by none of
//! cryptoxide, hiss or `snow`.
//!
//! Scope, pins and the measured census live in
//! `vectors/wycheproof/PROVENANCE.md`. The short version: Noise **§12.4**
//! AESGCM is AES-256 / 96-bit nonce / 128-bit tag, which selects **66** of the
//! file's 316 tests — 39 `valid` and 27 `invalid`.
//!
//! **What this corpus does not cover:** every vector at the pinned commit has
//! `tagSize: 128`, so there are no truncated-tag cases. Tag truncation is
//! covered by the bespoke negative tests in `src/lib.rs` instead.

use cryptoxide_git::aes_gcm::{AesGcm256, DecryptionResult, Tag};
use serde::Deserialize;

const VECTORS_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/vectors/wycheproof/aes_gcm_test.json"
);

/// Noise §12.4's three parameters, as Wycheproof spells them (in bits).
const KEY_SIZE: u32 = 256;
const IV_SIZE: u32 = 96;
const TAG_SIZE: u32 = 128;

/// The applicable subset, measured at the pinned commit. Asserted rather than
/// counted-and-printed: a refresh that changes the corpus must be noticed,
/// not silently absorbed into a smaller (or larger) run.
const EXPECTED: (u32, u32, u32) = (66, 39, 27);

#[derive(Deserialize)]
struct VectorFile {
    algorithm: String,
    #[serde(rename = "numberOfTests")]
    number_of_tests: u32,
    #[serde(rename = "testGroups")]
    test_groups: Vec<TestGroup>,
}

#[derive(Deserialize)]
struct TestGroup {
    #[serde(rename = "keySize")]
    key_size: u32,
    #[serde(rename = "ivSize")]
    iv_size: u32,
    #[serde(rename = "tagSize")]
    tag_size: u32,
    tests: Vec<TestCase>,
}

#[derive(Deserialize)]
struct TestCase {
    #[serde(rename = "tcId")]
    tc_id: u32,
    key: String,
    iv: String,
    aad: String,
    msg: String,
    ct: String,
    tag: String,
    result: String,
}

fn decode(hex_str: &str) -> Vec<u8> {
    hex::decode(hex_str).expect("hex")
}

fn load() -> VectorFile {
    let raw = std::fs::read_to_string(VECTORS_PATH)
        .unwrap_or_else(|e| panic!("missing {VECTORS_PATH} ({e})"));
    serde_json::from_str(&raw).expect("valid wycheproof json")
}

#[test]
fn wycheproof_aes_gcm_256_96_128() {
    let file = load();

    // The file is the file we think it is, before any crypto runs.
    assert_eq!(file.algorithm, "AES-GCM", "wrong Wycheproof corpus");
    assert_eq!(file.number_of_tests, 316, "corpus size moved — re-pin");

    let (mut ran, mut valid, mut invalid) = (0u32, 0u32, 0u32);

    for group in &file.test_groups {
        if group.key_size != KEY_SIZE || group.iv_size != IV_SIZE {
            continue;
        }
        // Not a filter — a claim. Every vector at this pin is 128-bit-tagged,
        // which is *why* truncation needs its own test elsewhere. If a refresh
        // ever introduces short tags this fails loudly rather than quietly
        // widening the run into cases the assertions below do not fit.
        assert_eq!(
            group.tag_size, TAG_SIZE,
            "unexpected truncated-tag group at this pin"
        );

        for case in &group.tests {
            ran += 1;
            let key: [u8; 32] = decode(&case.key).try_into().expect("256-bit key");
            let iv: [u8; 12] = decode(&case.iv).try_into().expect("96-bit iv");
            let (aad, msg, ct) = (decode(&case.aad), decode(&case.msg), decode(&case.ct));
            let tag: [u8; 16] = decode(&case.tag).try_into().expect("128-bit tag");
            let cipher = AesGcm256::new(&key);

            match case.result.as_str() {
                "valid" => {
                    valid += 1;

                    // Encryption must reproduce ciphertext AND tag exactly.
                    // Pinning the tag is the part that matters: a round-trip
                    // alone would pass under a wrong-but-self-consistent GHASH.
                    let mut got_ct = vec![0u8; msg.len()];
                    let mut got_tag = Tag([0u8; 16]);
                    cipher.encrypt(&iv, &aad, &msg, &mut got_ct, &mut got_tag);
                    assert_eq!(got_ct, ct, "tcId {} ciphertext", case.tc_id);
                    assert_eq!(got_tag.0, tag, "tcId {} tag", case.tc_id);

                    // …and decryption must verify and recover the plaintext.
                    let mut got_pt = vec![0u8; ct.len()];
                    assert_eq!(
                        cipher.decrypt(&iv, &aad, &ct, &mut got_pt, &Tag(tag)),
                        DecryptionResult::Match,
                        "tcId {} must verify",
                        case.tc_id
                    );
                    assert_eq!(got_pt, msg, "tcId {} plaintext", case.tc_id);
                }
                "invalid" => {
                    invalid += 1;
                    let mut got_pt = vec![0u8; ct.len()];
                    assert_eq!(
                        cipher.decrypt(&iv, &aad, &ct, &mut got_pt, &Tag(tag)),
                        DecryptionResult::MisMatch,
                        "tcId {} must be REJECTED",
                        case.tc_id
                    );
                }
                other => panic!("tcId {}: unexpected result class {other}", case.tc_id),
            }
        }
    }

    println!("wycheproof AES-GCM 256/96/128: ran={ran} valid={valid} invalid={invalid}");
    assert_eq!(
        (ran, valid, invalid),
        EXPECTED,
        "applicable subset moved — re-derive the census in PROVENANCE.md"
    );
}
