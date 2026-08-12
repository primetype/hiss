//! Noise **AESGCM** implemented against an *unreleased* cryptoxide, so the
//! cipher can be validated before hiss commits to shipping it.
//!
//! This crate is a laboratory, not a product. It is `publish = false`,
//! out-of-workspace, excluded from hiss's packaged `.crate`, and it exists
//! only until cryptoxide publishes a release containing `aes_gcm` — at which
//! point it dissolves into hiss proper and is deleted. See `README.md` for
//! the exit criteria.
//!
//! # What this is validating
//!
//! [`AesGcm`] is a [`hiss::noise::Cipher`] implementation over
//! `cryptoxide_git::aes_gcm` — cryptoxide's AES-GCM as of the pinned master
//! commit. hiss's own `[dependencies]` are untouched: cryptoxide comes to
//! hiss from the **registry**, and only the code in this file sees master
//! (see `Cargo.toml` for why that split is both possible and desirable).
//!
//! # Noise §12.4
//!
//! > *"AES256 with GCM … with a 128-bit tag appended to the ciphertext. The
//! > 96-bit nonce is formed by encoding 32 bits of zeros followed by
//! > big-endian encoding of n."*
//!
//! Note the section number: AESGCM is **§12.4**. §12.3 is ChaChaPoly, whose
//! nonce is **little**-endian — see [`nonce_bytes`].

use cryptoxide_git::aes_gcm::{AesGcm256, DecryptionResult, Tag};
use hiss::noise::{Cipher, HandshakeError};

/// Noise **§12.4** `AESGCM`: AES-256-GCM with a 96-bit nonce and a 128-bit
/// tag appended to the ciphertext.
///
/// * Key = 32 bytes (AES-256)
/// * Nonce = 12 bytes: 4 zero bytes followed by the 64-bit counter,
///   **big-endian** ([`nonce_bytes`])
/// * Tag = 16 bytes, appended
///
/// On a [`DecryptionFailed`](HandshakeError::DecryptionFailed) error this
/// impl zeroes the plaintext region of `output` before returning. The reason
/// differs from `ChaChaPoly`'s and the difference is worth stating, because
/// hiss's trait documentation states the ChaChaPoly mechanism as though it
/// were universal: cryptoxide's AES-GCM verifies the tag **before** writing
/// any plaintext, so on mismatch `output` is *untouched* rather than full of
/// unverified plaintext. Untouched is not the same as safe — in a **reused**
/// buffer it means the *previous* message's plaintext survives, and a caller
/// that ignores the error would read the old message as the new one. Zeroing
/// closes that, and keeps the failure contract uniform across ciphers.
#[derive(Debug, Clone, Copy, Default)]
pub struct AesGcm;

/// Build the 12-byte Noise AESGCM nonce: 4 zero bytes followed by the 64-bit
/// counter in **big-endian** (Noise §12.4).
///
/// `ChaChaPoly` (§12.3) uses the same layout **little**-endian
/// (`src/noise/cipher.rs`), so copy-pasting that function reproduces the
/// classic silent Noise AEAD bug: counter 0 encodes identically in both
/// endiannesses, so an LE mutant still matches a corpus through the handshake
/// message *and* the first transport message, and only diverges at n = 1.
/// That is exactly why `nonce_is_big_endian` asserts n = 1 directly rather
/// than trusting a round-trip.
#[inline]
#[must_use]
pub fn nonce_bytes(n: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&n.to_be_bytes());
    nonce
}

impl Cipher for AesGcm {
    const NAME: &'static str = "AESGCM";
    const TAG_SIZE: usize = 16;

    fn encrypt(
        key: &[u8; 32],
        nonce: u64,
        ad: &[u8],
        plaintext: &[u8],
        output: &mut [u8],
    ) -> Result<usize, HandshakeError> {
        let ct_len = plaintext.len();
        let total = ct_len + Self::TAG_SIZE;
        if output.len() < total {
            return Err(HandshakeError::OutputBufferTooSmall {
                needed: total,
                actual: output.len(),
            });
        }

        let nonce = nonce_bytes(nonce);
        // hiss's trait wants ciphertext‖tag in one buffer; cryptoxide returns
        // the tag separately, so the split is ours to get right.
        let (ct, tag_out) = output[..total].split_at_mut(ct_len);
        let mut tag = Tag([0u8; Self::TAG_SIZE]);
        AesGcm256::new(key).encrypt(&nonce, ad, plaintext, ct, &mut tag);
        tag_out.copy_from_slice(&tag.0);
        Ok(total)
    }

    fn decrypt(
        key: &[u8; 32],
        nonce: u64,
        ad: &[u8],
        ciphertext: &[u8],
        output: &mut [u8],
    ) -> Result<usize, HandshakeError> {
        if ciphertext.len() < Self::TAG_SIZE {
            return Err(HandshakeError::DecryptionFailed);
        }
        let pt_len = ciphertext.len() - Self::TAG_SIZE;
        if output.len() < pt_len {
            return Err(HandshakeError::OutputBufferTooSmall {
                needed: pt_len,
                actual: output.len(),
            });
        }

        let nonce = nonce_bytes(nonce);
        let (ct, tag) = ciphertext.split_at(pt_len);
        let tag = Tag(tag.try_into().expect("split at len - TAG_SIZE"));
        match AesGcm256::new(key).decrypt(&nonce, ad, ct, &mut output[..pt_len], &tag) {
            DecryptionResult::Match => Ok(pt_len),
            DecryptionResult::MisMatch => {
                // cryptoxide verifies BEFORE writing, so `output` is untouched
                // here — unlike ChaChaPoly, which leaves the full unverified
                // plaintext behind. Untouched is still not safe: in a reused
                // buffer the PREVIOUS message's plaintext survives, and a
                // caller that ignores the `Err` would read it as this message.
                // Zero it, so the failure contract is uniform across ciphers.
                // (Fail-safe only — authentication is not bypassed.)
                hiss::zeroize::zeroize_bytes(&mut output[..pt_len]);
                Err(HandshakeError::DecryptionFailed)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// R1, caught directly. The LE/BE swap is silent at counter 0 — both
    /// encodings produce twelve zero bytes — so this asserts n = 1, where
    /// they first differ, and n = 0x0102… where the byte order is unambiguous.
    #[test]
    fn nonce_is_big_endian() {
        assert_eq!(
            nonce_bytes(0),
            [0u8; 12],
            "counter 0 is all zeros either way"
        );

        let mut want = [0u8; 12];
        want[11] = 1;
        assert_eq!(nonce_bytes(1), want, "Noise §12.4 nonce is BIG-endian");

        // The little-endian spelling, written out, must NOT be what we produce.
        let mut le = [0u8; 12];
        le[4..].copy_from_slice(&1u64.to_le_bytes());
        assert_ne!(nonce_bytes(1), le, "must not be ChaChaPoly's little-endian");

        assert_eq!(
            nonce_bytes(0x0102_0304_0506_0708)[4..],
            [1, 2, 3, 4, 5, 6, 7, 8],
            "most-significant byte first"
        );
    }

    /// The mechanism claim behind [`AesGcm`]'s doc comment and the explicit
    /// zeroing, asserted rather than assumed.
    ///
    /// If a future cryptoxide switched to write-then-verify, this test goes
    /// red and the comment stops being a lie quietly — which is the point of
    /// pinning the mechanism, not just the outcome.
    #[test]
    fn raw_cryptoxide_verifies_before_writing() {
        let key = [0x42u8; 32];
        let nonce = [7u8; 12];
        let cipher = AesGcm256::new(&key);

        let mut ct = [0u8; 14];
        let mut tag = Tag([0u8; 16]);
        cipher.encrypt(&nonce, b"ad", b"secret payload", &mut ct, &mut tag);

        let mut bad = Tag(tag.0);
        bad.0[0] ^= 0xFF;

        let mut out = [0xAAu8; 14];
        assert_eq!(
            cipher.decrypt(&nonce, b"ad", &ct, &mut out, &bad),
            DecryptionResult::MisMatch
        );
        assert!(
            out.iter().all(|&b| b == 0xAA),
            "cryptoxide AES-GCM verifies BEFORE writing: the buffer is untouched \
             on mismatch (this is *why* the impl zeroes explicitly)"
        );
    }

    /// R5, both halves. Ported from hiss's own
    /// `ChaChaPoly::decrypt_failure_zeroes_output` (`src/noise/cipher.rs`),
    /// plus the variant that matters here specifically.
    ///
    /// The fresh-buffer half is the direct port. The **reused**-buffer half is
    /// the one that catches this cipher's real hazard: because cryptoxide
    /// leaves `output` untouched on mismatch, a buffer that already holds the
    /// previous message's plaintext would silently keep it, and a caller
    /// ignoring the `Err` would read the old message as the new one.
    #[test]
    fn decrypt_failure_zeroes_output() {
        let key = [0x42u8; 32];
        let mut ct = [0u8; 64];
        let n = AesGcm::encrypt(&key, 0, &[], b"secret payload", &mut ct).unwrap();
        let pt_len = n - AesGcm::TAG_SIZE;

        let mut corrupted = ct;
        corrupted[n - 1] ^= 0xFF; // corrupt the tag

        // Fresh buffer, poisoned so a no-op would be visible.
        let mut pt = [0xAAu8; 64];
        let err = AesGcm::decrypt(&key, 0, &[], &corrupted[..n], &mut pt).unwrap_err();
        assert!(matches!(err, HandshakeError::DecryptionFailed));
        assert!(
            pt[..pt_len].iter().all(|&b| b == 0),
            "plaintext region must be zeroed on auth failure"
        );

        // Reused buffer: a prior *successful* decrypt left real plaintext here.
        let mut pt = [0u8; 64];
        AesGcm::decrypt(&key, 0, &[], &ct[..n], &mut pt).unwrap();
        assert_eq!(&pt[..pt_len], b"secret payload", "prior message decrypted");

        let err = AesGcm::decrypt(&key, 0, &[], &corrupted[..n], &mut pt).unwrap_err();
        assert!(matches!(err, HandshakeError::DecryptionFailed));
        assert!(
            pt[..pt_len].iter().all(|&b| b == 0),
            "stale plaintext from the PREVIOUS message must not survive a failed decrypt"
        );
    }

    /// R4 — tag truncation, which Wycheproof does **not** cover.
    ///
    /// Every vector in `aes_gcm_test.json` at the pinned commit has
    /// `tagSize: 128` (measured — see `vectors/wycheproof/PROVENANCE.md`), so
    /// nothing in that corpus exercises a short tag. This is the bespoke
    /// replacement: shorter-than-a-tag input, a one-byte truncation, and a
    /// tag that is present but one bit wrong.
    #[test]
    fn truncated_tags_rejected() {
        let key = [0x42u8; 32];
        let mut ct = [0u8; 64];
        let n = AesGcm::encrypt(&key, 3, b"ad", b"secret payload", &mut ct).unwrap();
        let mut out = [0u8; 64];

        // Nothing can be a valid ciphertext‖tag if it is shorter than the tag.
        for short in 0..AesGcm::TAG_SIZE {
            assert!(
                matches!(
                    AesGcm::decrypt(&key, 3, b"ad", &ct[..short], &mut out),
                    Err(HandshakeError::DecryptionFailed)
                ),
                "{short}-byte input is shorter than the tag and must be rejected"
            );
        }

        // Truncated by one byte: the split still succeeds, so this reaches the
        // AEAD with a misaligned tag — a prefix comparison would accept it.
        assert!(
            AesGcm::decrypt(&key, 3, b"ad", &ct[..n - 1], &mut out).is_err(),
            "a one-byte truncation must not authenticate"
        );
    }

    /// R4's other half: every single-bit change to the 128-bit tag is
    /// rejected. 128 flips, not 16 — a comparison that ignored the low bits
    /// of each byte would survive a byte-granular test.
    #[test]
    fn every_flipped_tag_bit_rejected() {
        let key = [0x42u8; 32];
        let mut ct = [0u8; 64];
        let n = AesGcm::encrypt(&key, 3, b"ad", b"secret payload", &mut ct).unwrap();
        let pt_len = n - AesGcm::TAG_SIZE;
        let mut out = [0u8; 64];

        for bit in 0..(AesGcm::TAG_SIZE * 8) {
            let mut bad = ct;
            bad[pt_len + bit / 8] ^= 1 << (bit % 8);
            assert!(
                AesGcm::decrypt(&key, 3, b"ad", &bad[..n], &mut out).is_err(),
                "tag bit {bit} flipped must be rejected"
            );
        }

        // …and the untampered tag still verifies, so the loop above is not
        // passing because everything is rejected.
        assert_eq!(
            AesGcm::decrypt(&key, 3, b"ad", &ct[..n], &mut out).unwrap(),
            pt_len
        );
    }

    /// A ciphertext bit flip is rejected too — the tag covers the ciphertext,
    /// not just itself.
    #[test]
    fn flipped_ciphertext_rejected() {
        let key = [0x42u8; 32];
        let mut ct = [0u8; 64];
        let n = AesGcm::encrypt(&key, 3, b"ad", b"secret payload", &mut ct).unwrap();
        let pt_len = n - AesGcm::TAG_SIZE;
        let mut out = [0u8; 64];

        for byte in 0..pt_len {
            let mut bad = ct;
            bad[byte] ^= 0x01;
            assert!(
                AesGcm::decrypt(&key, 3, b"ad", &bad[..n], &mut out).is_err(),
                "ciphertext byte {byte} flipped must be rejected"
            );
        }
    }

    /// R2 at the unit level: the AD is authenticated, so decrypting under a
    /// different AD must fail. The corpus and live-interop legs cover this
    /// against foreign implementations; this catches a dropped `ad` argument
    /// without leaving the crate.
    #[test]
    fn wrong_associated_data_rejected() {
        let key = [0x42u8; 32];
        let mut ct = [0u8; 64];
        let n = AesGcm::encrypt(&key, 1, b"ad", b"secret payload", &mut ct).unwrap();
        let mut out = [0u8; 64];

        assert!(AesGcm::decrypt(&key, 1, b"AD", &ct[..n], &mut out).is_err());
        assert!(AesGcm::decrypt(&key, 1, &[], &ct[..n], &mut out).is_err());
        // Right AD, wrong nonce — the counter is authenticated through the IV.
        assert!(AesGcm::decrypt(&key, 2, b"ad", &ct[..n], &mut out).is_err());
        // Right everything.
        assert!(AesGcm::decrypt(&key, 1, b"ad", &ct[..n], &mut out).is_ok());
    }

    /// The buffer-size contract, both directions — a short `output` is a
    /// distinct error from a failed decrypt, and must not be silently
    /// truncated into one.
    #[test]
    fn short_output_buffer_is_its_own_error() {
        let key = [0x42u8; 32];
        let mut ct = [0u8; 64];

        // encrypt: needs plaintext.len() + TAG_SIZE
        let mut tiny = [0u8; 8];
        assert!(matches!(
            AesGcm::encrypt(&key, 0, &[], b"secret payload", &mut tiny),
            Err(HandshakeError::OutputBufferTooSmall {
                needed: 30,
                actual: 8
            })
        ));

        let n = AesGcm::encrypt(&key, 0, &[], b"secret payload", &mut ct).unwrap();
        assert_eq!(n, 14 + AesGcm::TAG_SIZE, "ciphertext‖tag, tag appended");

        // decrypt: needs ciphertext.len() - TAG_SIZE
        let mut tiny = [0u8; 8];
        assert!(matches!(
            AesGcm::decrypt(&key, 0, &[], &ct[..n], &mut tiny),
            Err(HandshakeError::OutputBufferTooSmall {
                needed: 14,
                actual: 8
            })
        ));
    }

    /// The empty-plaintext edge: a zero-length payload is still a 16-byte
    /// authenticated message, and it still round-trips.
    #[test]
    fn empty_plaintext_round_trips() {
        let key = [0x42u8; 32];
        let mut ct = [0u8; 32];
        let n = AesGcm::encrypt(&key, 0, b"ad", &[], &mut ct).unwrap();
        assert_eq!(n, AesGcm::TAG_SIZE, "tag only");

        let mut out = [0u8; 32];
        assert_eq!(
            AesGcm::decrypt(&key, 0, b"ad", &ct[..n], &mut out).unwrap(),
            0
        );

        let mut bad = ct;
        bad[0] ^= 0x01;
        assert!(AesGcm::decrypt(&key, 0, b"ad", &bad[..n], &mut out).is_err());
    }

    /// The Noise name and tag size are wire-visible constants: `NAME` is mixed
    /// into the protocol name that seeds the handshake hash, and `TAG_SIZE`
    /// sets every generated message's compile-time width.
    #[test]
    fn noise_constants() {
        assert_eq!(AesGcm::NAME, "AESGCM");
        assert_eq!(AesGcm::TAG_SIZE, 16, "Noise §12.4: 128-bit tag");
    }
}
