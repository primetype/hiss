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
    /// `k` in the Noise spec — the cipher's **expanded** key, built once by
    /// [`Cipher::key`] and reused for every message under it. `None` means
    /// plaintext mode. Dropping it is what scrubs it (see [`Cipher::Key`]).
    k: Option<Ci::Key>,
    /// `n` in the Noise spec — 64-bit message counter.
    n: u64,
    /// `fn() -> Ci`, not `Ci`: the marker must not be able to strip an auto
    /// trait (`Send`, `Sync`, `UnwindSafe`) from a session that a
    /// [`Cipher::Key`] — which is `Send + Sync + 'static` by the trait —
    /// would otherwise keep.
    _cipher: PhantomData<fn() -> Ci>,
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
    ///
    /// Runs the cipher's key schedule ([`Cipher::key`]) once, here, and
    /// zeroises the caller's 32 raw bytes before returning — so the scrub is
    /// this constructor's, not something each call site has to remember.
    pub(crate) fn from_key(mut key: [u8; 32]) -> Self {
        let state = Self {
            k: Some(Ci::key(&key)),
            n: 0,
            _cipher: PhantomData,
        };
        zeroize_array(&mut key);
        state
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
        let new_key = rekey_key::<Ci>(key)?;
        // Installing the new key drops the old one, and a `Cipher::Key`
        // scrubs itself on drop — there is no raw copy left to wipe by hand.
        self.k = Some(new_key);
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

    /// Take this state's expanded key, leaving it unkeyed, or `None` if it
    /// already was.
    ///
    /// Crate-internal: the datagram receive half (see
    /// [`DatagramRecv`](super::datagram::DatagramRecv)) calls it exactly
    /// once, at construction, to seed the epoch-0 key of its ratchet. The
    /// key travels to the ratchet and this state is left in plaintext mode,
    /// so only one *live* key exists afterwards.
    ///
    /// **The moved-from slot is not scrubbed**, and that is move semantics
    /// rather than anything the optimiser did: moving a value copies its
    /// bytes and does not erase the source. So after the `take` the payload
    /// of `k` still holds the 32 key bytes, and this state's `Drop` will not
    /// wipe them — the field drop glue that does the wiping sees `None`.
    /// There is no clean fix at this level: zeroing the source would mean
    /// writing over a live `None`, whose encoding is all-zero only for a
    /// niche-free `Ci::Key`, so it is not something a generic `take` may
    /// assume. In practice the residue is dead stack of the one caller,
    /// [`into_datagram_with_epoch`](super::transport::Transport::into_datagram_with_epoch),
    /// the same class as every other move of a key-bearing value;
    /// SECURITY.md's "Honest limits" records it.
    pub(crate) fn take_key(&mut self) -> Option<Ci::Key> {
        self.k.take()
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
/// The 48-byte AEAD scratch (32 key bytes + 16 tag) and the raw 32-byte
/// intermediate are zeroised before return, so no derived-key residue is
/// left on the stack frame. The returned [`Cipher::Key`] is the live value
/// and scrubs itself when the caller drops it.
pub(crate) fn rekey_key<Ci: Cipher>(key: &Ci::Key) -> Result<Ci::Key, HandshakeError> {
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
    let expanded = Ci::key(&new_key);

    // Scrub the scratch, which holds a copy of the new key alongside the tag,
    // and the raw copy the schedule was run over. The returned `Ci::Key` is
    // the live value and scrubs itself when the caller drops it.
    zeroize_array(&mut new_key);
    zeroize_array(&mut output);
    Ok(expanded)
}

impl<Ci: Cipher> Drop for CipherState<Ci> {
    fn drop(&mut self) {
        // The key is wiped by the field drop glue that runs after this body —
        // the `Cipher::Key` contract — and deliberately **not** by an
        // `self.k = None` here. That assignment looks equivalent and is
        // worse: it drops the old key (wiping it) and then copies a whole
        // `Option<Ci::Key>` temporary over the field, and in a debug build
        // that temporary's payload bytes are uninitialised stack. Observed
        // in a probe: eight bytes of the just-wiped key came back, because
        // the temporary landed on the key's own dead stack image. Leaving
        // the wipe to the glue is deterministic in every profile;
        // `cipher_state_scrubs_key_on_drop` pins it.
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

    /// `ChaChaPoly` pays nothing in space for the expanded-key trait shape.
    ///
    /// 48 bytes is what this state was when `k` was a raw `[u8; 32]`, and
    /// `Option<ChaChaPolyKey>` is the same 33 bytes padded to 40, plus the
    /// `u64` counter. The pin is here because the *other* cipher does pay:
    /// `CipherState<AesGcm>` is 528 bytes on `aarch64` and 992 on the
    /// portable path, so "which ciphers cost what" should not be something a
    /// refactor can move quietly.
    #[test]
    fn chachapoly_state_size_unchanged() {
        assert_eq!(
            size_of::<CipherState<ChaChaPoly>>(),
            48,
            "the ChaChaPoly cipher state must stay 48 bytes"
        );
    }

    /// A keyed [`CipherState`] leaves no copy of its key behind when it
    /// drops. The state does not scrub key bytes itself — it owns a
    /// [`Cipher::Key`] and lets dropping that do the work — so this pins the
    /// outcome end to end.
    ///
    /// The probe builds the state inside a `MaybeUninit`, drops it in place,
    /// and reads the bytes back. It looks at **only** the `k` field —
    /// `size_of::<Option<ChaChaPolyKey>>()` bytes, every one of which
    /// `from_key` initialises (the `Some` discriminant plus the 32 key
    /// bytes) — and not the whole 48-byte state, whose seven padding bytes
    /// between `k` and `n` are uninitialised and must not be read as `u8`.
    ///
    /// It is also what caught the `self.k = None` that used to open
    /// [`Drop`](CipherState::drop): see that impl for why the assignment
    /// un-scrubbed the key in a debug build.
    ///
    /// Like the two `Cipher::Key` probes in `cipher::tests`, this pins the
    /// **contract**, not the volatile pass: reading the storage back is
    /// itself a use of those bytes, so it keeps even ordinary, elidable
    /// zeroing stores alive — in every profile, not just debug. The evidence
    /// that hiss's wipe survives optimisation is the disassembly; what this
    /// test catches is a key that stops scrubbing at all.
    #[test]
    fn cipher_state_scrubs_key_on_drop() {
        use crate::noise::cipher::ChaChaPolyKey;
        use core::mem::MaybeUninit;

        const PATTERN: [u8; 32] = [0xA5; 32];

        /// The bytes of the `k` field, read back volatile.
        ///
        /// # Safety
        ///
        /// `slot`'s storage must have been initialised by `from_key` and
        /// only written to since, so that every byte of `k` is initialised.
        unsafe fn key_bytes(slot: &mut MaybeUninit<CipherState<ChaChaPoly>>) -> Vec<u8> {
            // SAFETY: the storage holds a `CipherState<ChaChaPoly>` place, so
            // projecting to its `k` field is in bounds; `&raw mut` takes the
            // address without forming a reference or reading anything.
            let k = unsafe { (&raw mut (*slot.as_mut_ptr()).k).cast::<u8>() };
            (0..size_of::<Option<ChaChaPolyKey>>())
                // SAFETY: `from_key` writes every byte of `k` — the `Some`
                // discriminant and all 32 key bytes — and nothing since has
                // deinitialised them, so each byte is initialised and within
                // the field. Volatile, so the reads cannot be folded against
                // the stores the destructor made.
                .map(|i| unsafe { k.add(i).read_volatile() })
                .collect()
        }

        let mut slot = MaybeUninit::new(CipherState::<ChaChaPoly>::from_key(PATTERN));

        // SAFETY: `slot` was initialised by `from_key` on the line above.
        let before = unsafe { key_bytes(&mut slot) };
        assert!(
            before.windows(PATTERN.len()).any(|w| w == PATTERN),
            "the probe must see the live key first"
        );

        // SAFETY: initialised above and dropped exactly once, here; nothing
        // reads it as a `CipherState` afterwards.
        unsafe { slot.assume_init_drop() };

        // SAFETY: the storage is still ours and still allocated, and the drop
        // wrote every payload byte of `k` in place (`ChaChaPolyKey::drop`),
        // so the field is still initialised throughout.
        let after = unsafe { key_bytes(&mut slot) };
        assert!(
            !after.contains(&PATTERN[0]),
            "no byte of the key may survive the drop, got {after:02x?}"
        );
        // The `Option` discriminant is the one byte drop glue does not
        // rewrite, which is why this is "no key byte survives" rather than
        // "all 33 bytes are zero" — and why it is `<= 1`, not `== 1`: a
        // niche-optimised `Option` for some other `Cipher::Key` would have no
        // discriminant byte at all.
        assert!(
            after.iter().filter(|&&b| b != 0).count() <= 1,
            "only the Option discriminant may remain, got {after:02x?}"
        );
    }

    /// `take_key` moves the key out and leaves plaintext mode behind — the
    /// hand-off the datagram ratchet is built on. A second call finds
    /// nothing, and the emptied state really does pass bytes through.
    #[test]
    fn take_key_leaves_state_unkeyed() {
        let mut cs = Cs::from_key([0x11u8; 32]);
        assert!(cs.has_key());

        assert!(cs.take_key().is_some(), "a keyed state hands its key over");
        assert!(!cs.has_key(), "and is left unkeyed");
        assert!(cs.take_key().is_none(), "a second take finds nothing");

        let mut out = [0u8; 4];
        assert_eq!(cs.encrypt_with_ad(&[], b"four", &mut out).unwrap(), 4);
        assert_eq!(&out, b"four", "the emptied state is in plaintext mode");
    }
}
