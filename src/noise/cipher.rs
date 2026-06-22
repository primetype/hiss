//! AEAD cipher trait for Noise transport encryption.

use super::error::HandshakeError;

/// An AEAD cipher usable in Noise handshakes.
pub trait Cipher {
    /// Noise name component (e.g. `"ChaChaPoly"`).
    const NAME: &'static str;

    /// Authentication tag size in bytes.
    const TAG_SIZE: usize;

    /// Encrypt `plaintext` with the given key, nonce, and associated
    /// data. Writes ciphertext + authentication tag into `output`.
    ///
    /// `output` must be at least `plaintext.len() + TAG_SIZE` bytes.
    /// Returns the number of bytes written.
    fn encrypt(
        key: &[u8; 32],
        nonce: u64,
        ad: &[u8],
        plaintext: &[u8],
        output: &mut [u8],
    ) -> Result<usize, HandshakeError>;

    /// Decrypt `ciphertext` (with appended tag) using the given key,
    /// nonce, and associated data. Writes the plaintext into `output`.
    ///
    /// `output` must be at least `ciphertext.len() - TAG_SIZE` bytes.
    /// Returns the number of bytes written.
    ///
    /// **Output contract on failure.** The AEAD writes the decrypted
    /// plaintext into `output` *before* the authentication tag is
    /// verified. On a [`DecryptionFailed`](HandshakeError::DecryptionFailed)
    /// error `output` therefore holds **unauthenticated** bytes that must
    /// **not** be read or acted on. (This is purely an output-buffer
    /// caveat — authentication is not bypassed: a tag mismatch still
    /// returns the error.)
    fn decrypt(
        key: &[u8; 32],
        nonce: u64,
        ad: &[u8],
        ciphertext: &[u8],
        output: &mut [u8],
    ) -> Result<usize, HandshakeError>;
}

// ── ChaCha20-Poly1305 ──────────────────────────────────────────

/// ChaCha20-Poly1305 AEAD as specified by the Noise protocol.
///
/// * Key = 32 bytes
/// * Nonce = 12 bytes (8-byte counter zero-padded to 12)
/// * Tag = 16 bytes
#[derive(Debug, Clone, Copy, Default)]
pub struct ChaChaPoly;

/// Build the 12-byte Noise nonce: 4 zero bytes followed by the
/// 64-bit counter in little-endian.
fn nonce_bytes(n: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&n.to_le_bytes());
    nonce
}

impl Cipher for ChaChaPoly {
    const NAME: &'static str = "ChaChaPoly";
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
        let (ct, tag_out) = output[..total].split_at_mut(ct_len);
        let mut cipher = cryptoxide::chacha20poly1305::ChaCha20Poly1305::new(key, &nonce, ad);
        cipher.encrypt(plaintext, ct, tag_out);
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
        let mut cipher = cryptoxide::chacha20poly1305::ChaCha20Poly1305::new(key, &nonce, ad);
        if !cipher.decrypt(ct, &mut output[..pt_len], tag) {
            return Err(HandshakeError::DecryptionFailed);
        }
        Ok(pt_len)
    }
}
