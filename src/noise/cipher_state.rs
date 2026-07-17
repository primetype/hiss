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

    /// Force the nonce counter to `n` (tests only).
    ///
    /// Used to drive the nonce up to its `u64::MAX` boundary so the
    /// overflow guard in `encrypt_with_ad`/`decrypt_with_ad` can be
    /// exercised without performing 2^64 operations.
    #[cfg(test)]
    pub(crate) fn set_nonce_for_test(&mut self, n: u64) {
        self.n = n;
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
                if output.len() < len {
                    return Err(HandshakeError::OutputBufferTooSmall {
                        needed: len,
                        actual: output.len(),
                    });
                }
                output[..len].copy_from_slice(plaintext);
                Ok(len)
            }
            Some(ref key) => {
                if self.n == u64::MAX {
                    return Err(HandshakeError::NonceOverflow);
                }
                // The on-wire message is the ciphertext plus the AEAD tag;
                // it must fit the Noise length cap (spec §3).
                let msg_len = plaintext.len() + Ci::TAG_SIZE;
                if msg_len > MAX_MESSAGE_LEN {
                    return Err(HandshakeError::MessageTooLong { len: msg_len });
                }
                let len = Ci::encrypt(key, self.n, ad, plaintext, output)?;
                self.n += 1;
                Ok(len)
            }
        }
    }

    /// Encrypt `plaintext` with associated data `ad` using the next send
    /// counter, reporting that counter alongside the byte count.
    ///
    /// Behaves exactly like [`encrypt_with_ad`](Self::encrypt_with_ad) —
    /// the same [`MAX_MESSAGE_LEN`] cap, the same `u64::MAX`
    /// nonce-exhaustion guard, the same strictly monotonic increment on
    /// success — but additionally hands back the nonce the message was
    /// sealed under. That counter is what an out-of-order transport (see
    /// [`DatagramSend`](super::datagram::DatagramSend)) transmits in its
    /// packet header so the peer can open the message with the matching
    /// explicit nonce. Because the counter is owned here and never
    /// supplied by the caller, two messages can never share a nonce. On
    /// any error the nonce does **not** advance and nothing is written.
    pub(crate) fn encrypt_next_with_ad(
        &mut self,
        ad: &[u8],
        plaintext: &[u8],
        output: &mut [u8],
    ) -> Result<(u64, usize), HandshakeError> {
        let counter = self.n;
        let len = self.encrypt_with_ad(ad, plaintext, output)?;
        Ok((counter, len))
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
        let mut new_key = rekey_key::<Ci>(key)?;

        // Zero the old key and install the new one.
        if let Some(ref mut old) = self.k {
            zeroize_array(old);
        }
        self.k = Some(new_key);
        zeroize_array(&mut new_key);
        Ok(())
    }

    /// The current nonce counter (`n` in the Noise spec).
    ///
    /// Crate-internal: the datagram send half (see
    /// [`DatagramSend`](super::datagram::DatagramSend)) reads it before a
    /// seal to learn whether the counter about to be used has crossed into
    /// a new key epoch, so it can ratchet the key forward to match.
    pub(crate) fn nonce(&self) -> u64 {
        self.n
    }

    /// A copy of this state's key, or `None` in plaintext mode.
    ///
    /// Crate-internal: the datagram receive half (see
    /// [`DatagramRecv`](super::datagram::DatagramRecv)) reads it exactly
    /// once, at construction, to seed the epoch-0 key of its ratchet. The
    /// source [`CipherState`] is dropped straight afterwards, scrubbing its
    /// own copy, so no residue outlives the hand-off.
    pub(crate) fn key(&self) -> Option<[u8; 32]> {
        self.k
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
    /// `output` is zeroed before returning; the nonce does not advance and
    /// the error is returned.
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
                if output.len() < len {
                    return Err(HandshakeError::OutputBufferTooSmall {
                        needed: len,
                        actual: output.len(),
                    });
                }
                output[..len].copy_from_slice(ciphertext);
                Ok(len)
            }
            Some(ref key) => {
                if self.n == u64::MAX {
                    return Err(HandshakeError::NonceOverflow);
                }
                let len = Ci::decrypt(key, self.n, ad, ciphertext, output)?;
                self.n += 1;
                Ok(len)
            }
        }
    }

    /// Decrypt a datagram sealed under an explicit `counter`, writing
    /// plaintext into `output`.
    ///
    /// Unlike [`decrypt_with_ad`](Self::decrypt_with_ad) this is
    /// **stateless**: it decrypts under the supplied `counter` rather than
    /// the internal nonce, advances no counter, and takes `&self` — so one
    /// state can open datagrams that arrive out of order, more than once,
    /// or not at all. Replay protection is therefore **not** provided here;
    /// it is the caller's duty (see
    /// [`DatagramRecv::decrypt_at`](super::datagram::DatagramRecv::decrypt_at)).
    /// The [`MAX_MESSAGE_LEN`] cap and the `u64::MAX` nonce guard are
    /// enforced exactly as in [`decrypt_with_ad`](Self::decrypt_with_ad):
    /// no legitimately sealed message ever carries `u64::MAX`, since
    /// [`encrypt_next_with_ad`](Self::encrypt_next_with_ad) refuses that
    /// counter. On any error nothing is learnt and no state changes.
    ///
    /// On a [`DecryptionFailed`](HandshakeError::DecryptionFailed) error
    /// `output` holds **unauthenticated** bytes that must not be read, per
    /// the AEAD output contract.
    pub(crate) fn decrypt_at(
        &self,
        counter: u64,
        ad: &[u8],
        ciphertext: &[u8],
        output: &mut [u8],
    ) -> Result<usize, HandshakeError> {
        // Reject an over-cap incoming message (spec §3) before any work, so
        // a peer cannot dictate unbounded buffers.
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
            Some(ref key) => {
                if counter == u64::MAX {
                    return Err(HandshakeError::NonceOverflow);
                }
                Ci::decrypt(key, counter, ad, ciphertext, output)
            }
        }
    }
}

/// Derive the next key from `key` per the Noise §5.1 / §11.3 `Rekey()`
/// transform: `ENCRYPT(k, 2^64−1, "", zeros[32])`, taking the first 32
/// ciphertext bytes (the trailing 16-byte AEAD tag is discarded).
///
/// The transform is deterministic and one-way — the previous key cannot be
/// recovered from the result — so chaining it derives a forward-only
/// sequence of epoch keys. It advances no counter and touches no
/// [`CipherState`]; the caller owns the returned key.
///
/// The 48-byte AEAD scratch (32 key bytes + 16 tag) is zeroised before
/// return, so no derived-key residue is left on the stack frame. The
/// returned key is the live value and is the caller's to scrub.
pub(crate) fn rekey_key<Ci: Cipher>(key: &[u8; 32]) -> Result<[u8; 32], HandshakeError> {
    const {
        assert!(
            Ci::TAG_SIZE <= 16,
            "rekey scratch [0u8; 48] assumes TAG_SIZE <= 16"
        )
    };

    let zeros = [0u8; 32];
    // ENCRYPT(k, 2^64−1, "", zeros) → 32 bytes ciphertext + 16 tag = 48 bytes.
    let mut output = [0u8; 48];
    Ci::encrypt(key, u64::MAX, &[], &zeros, &mut output)?;

    let mut new_key = [0u8; 32];
    new_key.copy_from_slice(&output[..32]);

    // Scrub the scratch, which holds a copy of the new key alongside the tag.
    zeroize_array(&mut output);
    Ok(new_key)
}

impl<Ci: Cipher> Drop for CipherState<Ci> {
    fn drop(&mut self) {
        if let Some(ref mut key) = self.k {
            zeroize_array(key);
        }
        self.n = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::noise::cipher::ChaChaPoly;

    type Cs = CipherState<ChaChaPoly>;

    #[test]
    fn encrypt_overflows_at_max_nonce() {
        let mut cs = Cs::from_key([0u8; 32]);
        // One short of the cap: this call must succeed and bump n to u64::MAX.
        cs.set_nonce_for_test(u64::MAX - 1);
        let plaintext = b"x";
        let mut out = [0u8; 1 + <ChaChaPoly as Cipher>::TAG_SIZE];
        cs.encrypt_with_ad(&[], plaintext, &mut out)
            .expect("encrypt at u64::MAX - 1 should succeed");
        // n is now u64::MAX: the next encrypt must refuse to reuse the nonce.
        let err = cs
            .encrypt_with_ad(&[], plaintext, &mut out)
            .expect_err("encrypt at u64::MAX must overflow");
        assert!(matches!(err, HandshakeError::NonceOverflow));
    }

    #[test]
    fn decrypt_guard_fires_at_max_nonce() {
        let mut cs = Cs::from_key([0u8; 32]);
        cs.set_nonce_for_test(u64::MAX);
        // The guard fires before any AEAD work, so the ciphertext need not
        // be valid.
        let ciphertext = [0u8; <ChaChaPoly as Cipher>::TAG_SIZE];
        let mut out = [0u8; 1];
        let err = cs
            .decrypt_with_ad(&[], &ciphertext, &mut out)
            .expect_err("decrypt at u64::MAX must overflow");
        assert!(matches!(err, HandshakeError::NonceOverflow));
    }

    #[test]
    fn unkeyed_encrypt_rejects_short_output() {
        let mut cs = Cs::empty();
        let mut out = [0u8; 2];
        let err = cs.encrypt_with_ad(&[], b"four", &mut out).unwrap_err();
        assert!(matches!(
            err,
            HandshakeError::OutputBufferTooSmall {
                needed: 4,
                actual: 2
            }
        ));
    }

    #[test]
    fn unkeyed_decrypt_rejects_short_output() {
        let mut cs = Cs::empty();
        let mut out = [0u8; 2];
        let err = cs.decrypt_with_ad(&[], b"four", &mut out).unwrap_err();
        assert!(matches!(
            err,
            HandshakeError::OutputBufferTooSmall {
                needed: 4,
                actual: 2
            }
        ));
    }

    #[test]
    fn unkeyed_passthrough_with_exact_output_succeeds() {
        let mut cs = Cs::empty();
        let mut out = [0u8; 4];
        assert_eq!(cs.encrypt_with_ad(&[], b"four", &mut out).unwrap(), 4);
        assert_eq!(&out, b"four");
    }
}
