//! Noise CipherState — symmetric key + monotonic nonce.
//!
//! Two [`CipherState`]s are produced at handshake completion (one per
//! direction). Each encrypts or decrypts transport messages using the
//! negotiated AEAD cipher.

use super::cipher::Cipher;
use super::error::HandshakeError;
use crate::zeroize::zeroize_array;
use std::marker::PhantomData;

/// Maximum length of a Noise message on the wire, in bytes (spec §3).
///
/// Every transport or handshake message — ciphertext including any AEAD
/// tag — must be `<= MAX_MESSAGE_LEN`. The value is the largest 16-bit
/// integer, matching the conventional 2-byte length framing and every
/// conformant Noise implementation (e.g. snow's `MAXMSGLEN`). Payloads
/// larger than this must be split across multiple messages by the caller.
pub(crate) const MAX_MESSAGE_LEN: usize = 65535;

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
                if len > MAX_MESSAGE_LEN {
                    return Err(HandshakeError::MessageTooLong { len });
                }
                output[..len].copy_from_slice(plaintext);
                Ok(len)
            }
            Some(key) => {
                if self.n == u64::MAX {
                    return Err(HandshakeError::NonceOverflow);
                }
                // The on-wire message is the ciphertext plus the AEAD tag;
                // it must fit the Noise length cap (spec §3).
                let msg_len = plaintext.len() + Ci::TAG_SIZE;
                if msg_len > MAX_MESSAGE_LEN {
                    return Err(HandshakeError::MessageTooLong { len: msg_len });
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
    /// Returns the number of bytes written. The nonce counter advances
    /// **only on success** and is **never reset**, so messages must be
    /// decrypted in the exact order they were encrypted, with none lost,
    /// reordered, or replayed — one such record permanently desynchronises
    /// this state. A failure is **terminal**; tear the session down rather
    /// than retrying.
    ///
    /// On a [`DecryptionFailed`](HandshakeError::DecryptionFailed) error
    /// the underlying AEAD has already written its (unverified) plaintext
    /// into `output` before the tag check ran, so `output` holds
    /// **unauthenticated** bytes that must not be read. (Authentication is
    /// not bypassed: the nonce does not advance and the error is returned.)
    pub fn decrypt_with_ad(
        &mut self,
        ad: &[u8],
        ciphertext: &[u8],
        output: &mut [u8],
    ) -> Result<usize, HandshakeError> {
        // Reject an over-cap incoming message (spec §3) before doing any
        // work, so a peer cannot dictate unbounded buffers.
        if ciphertext.len() > MAX_MESSAGE_LEN {
            return Err(HandshakeError::MessageTooLong {
                len: ciphertext.len(),
            });
        }
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
