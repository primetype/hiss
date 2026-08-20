//! Google Project Wycheproof vectors for the AES-256-GCM primitive behind
//! [`AesGcm`](super::AesGcm).
//!
//! This is the **primitive-level** leg of the AESGCM validation: it drives
//! `cryptoxide::aes_gcm::AesGcm256` directly — no handshake, no [`Cipher`]
//! trait, no Noise framing. The question it answers is narrow and worth
//! keeping narrow — *is the primitive AES-256-GCM?* — against a corpus
//! written by Google, i.e. by none of cryptoxide, hiss or `snow`. The Noise
//! framing (big-endian nonce, appended tag) is pinned separately by the
//! third-party `cacophony` replays in `tests/noise_cacophony.rs`.
//!
//! Noise §12.4 AESGCM is AES-**256** with a **96**-bit nonce and a
//! **128**-bit tag, which selects **66** of the file's 316 tests — 39
//! `valid` and 27 `invalid` (measured at the pinned commit and asserted
//! below). The out-of-scope groups are dropped rather than run-and-ignored:
//! an unreplayed vector in a KAT directory is a claim with nothing behind
//! it.
//!
//! **What this corpus does not cover:** every vector at the pinned commit
//! has `tagSize: 128`, so there are no truncated-tag cases. Tag truncation
//! is covered by the bespoke negative tests in the parent module instead
//! (`truncated_tags_rejected`, `every_flipped_tag_bit_rejected`).
//!
//! Vectors are vendored under `tests/vectors/wycheproof/` (Apache-2.0; see
//! that directory's `PROVENANCE.md`).

use cryptoxide::aes_gcm::{AesGcm256, DecryptionResult, Tag};
use serde::Deserialize;

#[cfg(doc)]
use super::Cipher;

const VECTORS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/vectors/wycheproof/aes_gcm_test.json"
));

/// Noise §12.4's three parameters, as Wycheproof spells them (in bits).
const KEY_SIZE: u32 = 256;
const IV_SIZE: u32 = 96;
const TAG_SIZE: u32 = 128;

/// The applicable subset, measured at the pinned commit: (ran, valid,
/// invalid). Asserted rather than counted-and-printed: a refresh that
/// changes the corpus must be noticed, not silently absorbed into a smaller
/// (or larger) run.
const EXPECTED: (u32, u32, u32) = (66, 39, 27);

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct VectorFile {
    algorithm: String,
    number_of_tests: u32,
    test_groups: Vec<TestGroup>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TestGroup {
    key_size: u32,
    iv_size: u32,
    tag_size: u32,
    tests: Vec<TestCase>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TestCase {
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

#[test]
fn wycheproof_aes_gcm_256_96_128() {
    let file: VectorFile = serde_json::from_str(VECTORS).expect("valid wycheproof json");

    // The file is the file we think it is, before any crypto runs.
    assert_eq!(file.algorithm, "AES-GCM", "wrong Wycheproof corpus");
    assert_eq!(file.number_of_tests, 316, "corpus size moved — re-pin");

    let (mut ran, mut valid, mut invalid) = (0u32, 0u32, 0u32);

    for group in &file.test_groups {
        if group.key_size != KEY_SIZE || group.iv_size != IV_SIZE {
            continue;
        }
        // Not a filter — a claim. Every vector at this pin is 128-bit-tagged,
        // which is *why* truncation needs its own test elsewhere. If a
        // refresh ever introduces short tags this fails loudly rather than
        // quietly widening the run into cases the assertions below do not
        // fit.
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
                    // alone would pass under a wrong-but-self-consistent
                    // GHASH.
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

    assert_eq!(
        (ran, valid, invalid),
        EXPECTED,
        "applicable subset moved — re-derive the census in PROVENANCE.md"
    );
}
