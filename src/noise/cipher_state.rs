//! Noise CipherState — symmetric key + monotonic nonce.
//!
//! Two [`CipherState`]s are produced at handshake completion (one per
//! direction). Each encrypts or decrypts transport messages using the
//! negotiated AEAD cipher.

use super::cipher::Cipher;
use super::error::HandshakeError;
use crate::zeroize::zeroize_array;
use std::marker::PhantomData;

/// A Noise CipherState holding a symmetric key and nonce counter.
///
/// An "empty" CipherState (no key) passes data through in plaintext,
/// as required by the Noise specification for pre-keyed messages.
pub struct CipherState<Ci: Cipher> {
    /// `k` in the Noise spec. `None` means plaintext mode.
    k: Option<[u8; 32]>,
    /// `n` in the Noise spec — 64-bit message counter.
    n: u64,
    _cipher: PhantomData<Ci>,
}

impl<Ci: Cipher> CipherState<Ci> {
    /// Create an empty CipherState (plaintext mode).
    pub fn empty() -> Self {
        Self {
            k: None,
            n: 0,
            _cipher: PhantomData,
        }
    }

    /// Create a CipherState with the given key.
    pub(crate) fn from_key(key: [u8; 32]) -> Self {
        Self {
            k: Some(key),
            n: 0,
            _cipher: PhantomData,
        }
    }

    /// Returns `true` if a key has been established.
    pub fn has_key(&self) -> bool {
        self.k.is_some()
    }

    /// Encrypt `plaintext` with associated data `ad`, writing
    /// ciphertext (+ tag if keyed) into `output`.
    ///
    /// When keyed, `output` must be at least
    /// `plaintext.len() + TAG_SIZE` bytes.
    /// When unkeyed, `output` must be at least `plaintext.len()` bytes.
    ///
    /// Returns the number of bytes written. Increments the nonce on
    /// success.
    pub fn encrypt_with_ad(
        &mut self,
        ad: &[u8],
        plaintext: &[u8],
        output: &mut [u8],
    ) -> Result<usize, HandshakeError> {
        match self.k {
            None => {
                let len = plaintext.len();
                output[..len].copy_from_slice(plaintext);
                Ok(len)
            }
            Some(key) => {
                if self.n == u64::MAX {
                    return Err(HandshakeError::NonceOverflow);
                }
                let len = Ci::encrypt(&key, self.n, ad, plaintext, output)?;
                self.n += 1;
                Ok(len)
            }
        }
    }

    /// Re-key this CipherState in place.
    ///
    /// Noise spec §5.1: `Rekey(): k = ENCRYPT(k, maxnonce, zerolen, zeros)`
    /// where `maxnonce = 2^64 − 1` and `zeros` is a 32-byte zero
    /// plaintext. The first 32 bytes of the AEAD output become the new
    /// key; the nonce counter is **not** incremented.
    ///
    /// Returns `Err` if this CipherState has no key.
    pub fn rekey(&mut self) -> Result<(), HandshakeError> {
        let key = self.k.as_ref().ok_or(HandshakeError::RekeyWithoutKey)?;

        let zeros = [0u8; 32];
        // ENCRYPT(k, 2^64−1, "", zeros) → 32 bytes ciphertext + 16 tag = 48 bytes.
        let mut output = [0u8; 48];
        Ci::encrypt(key, u64::MAX, &[], &zeros, &mut output)?;

        let mut new_key = [0u8; 32];
        new_key.copy_from_slice(&output[..32]);

        // Zero the old key and install the new one.
        if let Some(ref mut old) = self.k {
            zeroize_array(old);
        }
        self.k = Some(new_key);
        zeroize_array(&mut new_key);
        Ok(())
    }

    /// Decrypt `ciphertext` with associated data `ad`, writing
    /// plaintext into `output`.
    ///
    /// When keyed, `output` must be at least
    /// `ciphertext.len() - TAG_SIZE` bytes.
    /// When unkeyed, `output` must be at least `ciphertext.len()` bytes.
    ///
    /// Returns the number of bytes written. Increments the nonce on
    /// success.
    pub fn decrypt_with_ad(
        &mut self,
        ad: &[u8],
        ciphertext: &[u8],
        output: &mut [u8],
    ) -> Result<usize, HandshakeError> {
        match self.k {
            None => {
                let len = ciphertext.len();
                output[..len].copy_from_slice(ciphertext);
                Ok(len)
            }
            Some(key) => {
                if self.n == u64::MAX {
                    return Err(HandshakeError::NonceOverflow);
                }
                let len = Ci::decrypt(&key, self.n, ad, ciphertext, output)?;
                self.n += 1;
                Ok(len)
            }
        }
    }
}

impl<Ci: Cipher> Drop for CipherState<Ci> {
    fn drop(&mut self) {
        if let Some(ref mut key) = self.k {
            zeroize_array(key);
        }
        self.n = 0;
    }
}
