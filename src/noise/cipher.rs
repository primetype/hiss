//! AEAD cipher trait for Noise transport encryption, and the two ciphers the
//! Noise specification names: [`ChaChaPoly`] (§12.3) and [`AesGcm`] (§12.4).

use super::error::HandshakeError;

use core::mem::ManuallyDrop;
use cryptoxide::aes_gcm::{AesGcm256, DecryptionResult, Tag};

#[cfg(test)]
mod wycheproof;

/// An AEAD cipher usable in Noise handshakes.
///
/// # The key schedule runs once per key, never per message
///
/// [`encrypt`](Self::encrypt) and [`decrypt`](Self::decrypt) take an
/// already-expanded [`Key`](Self::Key), not the 32 raw Noise key bytes.
/// Whatever an AEAD derives from those bytes and then reuses — an AES
/// round-key schedule, a GHASH subkey — is therefore computed by
/// [`key`](Self::key) at the points where a Noise key comes into existence:
/// each `MixKey` and `MixKeyAndHash` token, the `Split` at the end of the
/// handshake, and every `Rekey()`. Never inside a seal or an open.
/// [`ChaChaPoly`] has nothing to hoist and pays nothing for the shape;
/// [`AesGcm`] has most of the cost of a small record.
///
/// # What a `Key` owes
///
/// **A `Key` scrubs its own secret material on drop.** hiss keeps one alive
/// for as long as the key is current — the whole session, for a transport
/// [`CipherState`](super::CipherState) — and cannot reach inside it, so the
/// wipe has to belong to the type. Both in-tree implementations do it with
/// the volatile writes of [`crate::zeroize`]: [`ChaChaPolyKey`] over its 32
/// bytes, [`AesGcmKey`] over the whole expanded schedule.
///
/// `Key` is `Send + Sync + 'static`, so which cipher a protocol names can
/// never be the reason a session type refuses to cross a thread boundary.
/// The one shape that buys out: an implementor whose expanded key is a
/// non-`Send` handle — a thread-bound HSM session, say — cannot be a
/// `Cipher` here, which is an acceptable trade when the AEAD always runs
/// in-process.
pub trait Cipher {
    /// Noise name component (e.g. `"ChaChaPoly"`).
    const NAME: &'static str;

    /// Authentication tag size in bytes.
    const TAG_SIZE: usize;

    /// This cipher's expanded key: what it derives from the 32 Noise key
    /// bytes once and reuses for every message under that key.
    ///
    /// Built by [`key`](Self::key); see the [trait docs](Cipher) for when
    /// that happens and for the scrub-on-drop contract a `Key` owes.
    type Key: Send + Sync + 'static;

    /// Run this cipher's key schedule over the 32 Noise key bytes.
    ///
    /// Called once per key — at `MixKey`, `MixKeyAndHash`, `Split` and
    /// `Rekey()` — and never per message. `k` remains the caller's to
    /// scrub; the returned [`Key`](Self::Key) scrubs itself on drop.
    fn key(k: &[u8; 32]) -> Self::Key;

    /// Encrypt `plaintext` with the given key, nonce, and associated
    /// data. Writes ciphertext + authentication tag into `output`.
    ///
    /// `output` must be at least `plaintext.len() + TAG_SIZE` bytes.
    /// Returns the number of bytes written.
    fn encrypt(
        key: &Self::Key,
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
    /// **Output contract on failure.** Implementations must zero
    /// `output[..pt_len]` before returning
    /// [`DecryptionFailed`](HandshakeError::DecryptionFailed), whatever the
    /// underlying AEAD left there. The hazard differs by cipher and the
    /// contract covers both: an AEAD that decrypts before it verifies
    /// ([`ChaChaPoly`]) leaves unverified, attacker-influenced plaintext in
    /// `output`; one that verifies before it writes ([`AesGcm`]) leaves
    /// `output` untouched — which, in a reused buffer, is the *previous*
    /// message's plaintext. Either way a caller that ignores the error must
    /// find zeros, not bytes it could mistake for this message.
    /// (Authentication is not bypassed: a tag mismatch still returns the
    /// error.)
    fn decrypt(
        key: &Self::Key,
        nonce: u64,
        ad: &[u8],
        ciphertext: &[u8],
        output: &mut [u8],
    ) -> Result<usize, HandshakeError>;
}

// ── Nonces ──────────────────────────────────────────────────────
//
// Both Noise ciphers take a 96-bit nonce of 32 zero bits followed by the
// 64-bit counter `n` — but §12.3 (ChaChaPoly) encodes `n` **little**-endian
// and §12.4 (AESGCM) **big**-endian. Counter 0 is twelve zero bytes under
// either encoding, so a cipher built on the wrong one agrees with every peer
// through the handshake and the first transport message in each direction,
// and diverges only once a counter reaches 1. That is why these are two
// functions with the byte order in the name, and why the unit tests below
// assert n = 1 directly rather than trusting a round trip.

/// The Noise §12.3 `ChaChaPoly` nonce: 4 zero bytes, then `n` little-endian.
fn nonce_le(n: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&n.to_le_bytes());
    nonce
}

/// The Noise §12.4 `AESGCM` nonce: 4 zero bytes, then `n` big-endian.
fn nonce_be(n: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&n.to_be_bytes());
    nonce
}

// ── ChaCha20-Poly1305 ──────────────────────────────────────────

/// ChaCha20-Poly1305 AEAD as specified by the Noise protocol (§12.3
/// `ChaChaPoly`).
///
/// * Key = 32 bytes
/// * Nonce = 12 bytes (8-byte counter, little-endian, zero-padded to 12)
/// * Tag = 16 bytes
///
/// On a [`DecryptionFailed`](HandshakeError::DecryptionFailed) error `hiss`
/// zeroes `output` before returning, so a caller that ignores the error
/// cannot read the unverified plaintext. (Auth is not bypassed: a tag
/// mismatch still errors.)
#[derive(Debug, Clone, Copy, Default)]
pub struct ChaChaPoly;

/// [`ChaChaPoly`]'s expanded key — the 32 Noise key bytes themselves.
///
/// ChaCha20-Poly1305 derives its state from the key *and* the nonce, so
/// there is nothing to compute once per key and hold: cryptoxide's
/// `ChaCha20Poly1305::new` runs per message either way, and this newtype
/// costs a `ChaChaPoly` session exactly nothing (a
/// [`CipherState<ChaChaPoly>`](super::CipherState) is still 48 bytes, pinned
/// by a test). Its whole job is the [`Cipher::Key`] scrub-on-drop contract.
///
/// Deliberately opaque: no `Clone`, `Copy`, `Debug` or `PartialEq`. Nothing
/// in hiss needs to duplicate a key, and a `Debug` that printed one would be
/// a foot-gun with no user.
pub struct ChaChaPolyKey([u8; 32]);

impl Drop for ChaChaPolyKey {
    fn drop(&mut self) {
        crate::zeroize::zeroize_array(&mut self.0);
    }
}

impl Cipher for ChaChaPoly {
    const NAME: &'static str = "ChaChaPoly";
    const TAG_SIZE: usize = 16;

    type Key = ChaChaPolyKey;

    fn key(k: &[u8; 32]) -> ChaChaPolyKey {
        ChaChaPolyKey(*k)
    }

    fn encrypt(
        key: &ChaChaPolyKey,
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

        let nonce = nonce_le(nonce);
        let (ct, tag_out) = output[..total].split_at_mut(ct_len);
        let mut cipher = cryptoxide::chacha20poly1305::ChaCha20Poly1305::new(&key.0, &nonce, ad);
        cipher.encrypt(plaintext, ct, tag_out);
        Ok(total)
    }

    fn decrypt(
        key: &ChaChaPolyKey,
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

        let nonce = nonce_le(nonce);
        let (ct, tag) = ciphertext.split_at(pt_len);
        let mut cipher = cryptoxide::chacha20poly1305::ChaCha20Poly1305::new(&key.0, &nonce, ad);
        if !cipher.decrypt(ct, &mut output[..pt_len], tag) {
            // Auth failed: the AEAD already wrote unverified plaintext into
            // `output`. Zero it so a caller that ignores the `Err` cannot read
            // attacker-influenced bytes. (Fail-safe only — auth is not bypassed.)
            crate::zeroize::zeroize_bytes(&mut output[..pt_len]);
            return Err(HandshakeError::DecryptionFailed);
        }
        Ok(pt_len)
    }
}

// ── AES-256-GCM ─────────────────────────────────────────────────

/// AES-256-GCM AEAD as specified by the Noise protocol (§12.4 `AESGCM`).
///
/// * Key = 32 bytes (AES-256)
/// * Nonce = 12 bytes: 4 zero bytes followed by the 64-bit counter,
///   **big**-endian — the opposite byte order from [`ChaChaPoly`]
/// * Tag = 16 bytes, appended to the ciphertext
///
/// Backed by `cryptoxide::aes_gcm::AesGcm256`. cryptoxide picks its AES and
/// GHASH implementations at compile time: on `aarch64` with the `aes` target
/// feature — on by default for `aarch64-apple-darwin`, not for the Linux
/// aarch64 targets — it uses the ARMv8 AES and `pmull` intrinsics; everywhere
/// else, x86-64 included, a constant-time fixsliced AES and a portable GHASH.
/// On Apple Silicon that makes `AesGcm` over five times as fast as
/// [`ChaChaPoly`] in `hiss-interop`'s transport comparison; on the portable
/// path it is not, and [`ChaChaPoly`] remains the performance default.
///
/// # Failure contract
///
/// On a [`DecryptionFailed`](HandshakeError::DecryptionFailed) error this
/// implementation zeroes the plaintext region of `output` before returning,
/// as [`ChaChaPoly`] does — but for a different reason, and the difference
/// is worth stating because it is easy to assume ChaChaPoly's mechanism is
/// universal. cryptoxide's AES-GCM **verifies the tag before writing any
/// plaintext**, so on a mismatch `output` is untouched rather than full of
/// unverified bytes. Untouched is not the same as safe: in a reused buffer
/// it means the *previous* message's plaintext survives, and a caller that
/// ignores the error would read the old message as the new one. Zeroing
/// closes that, and keeps the [`Cipher::decrypt`] contract uniform across
/// ciphers. (`raw_cryptoxide_verifies_before_writing` in this module's tests
/// pins the mechanism, so a cryptoxide that switched to write-then-verify
/// would turn this paragraph red rather than silently false.)
///
/// # The expanded key: hoisted, large, and scrubbed
///
/// The AES-256 key expansion and the GHASH subkey `H = AES_K(0)` are what
/// [`Cipher::key`] computes, once per Noise key, into an [`AesGcmKey`] that
/// lives as long as that key is current — not per message. It is what the
/// trait's shape buys: on Apple Silicon, where everything around it is
/// hardware-accelerated, the schedule is about 117 ns against roughly 160 ns
/// for the rest of a 1 KiB seal, and hoisting it took `benches/noise.rs`'s
/// `transport_1KiB` round trip from 594 ns to 365 ns and, in
/// `hiss-interop`'s one-suite bench, a 64-byte round trip from 314 ns to
/// 84 ns. (On the portable path the same fixed cost is a smaller share of a
/// larger total.)
///
/// It is not free in space. An [`AesGcmKey`] is 496 bytes on `aarch64` and
/// 976 on the portable fixsliced path, so a
/// [`CipherState`](super::CipherState) holding one is 528 / 992 bytes
/// against [`ChaChaPoly`]'s 48. Measured over a `P256`/`AESGCM`/`SHA256`
/// `IK`: a [`Transport`](super::Transport) is 1280 / 2200 bytes against 312
/// for the same suite over [`ChaChaPoly`], and a ratcheting
/// [`DatagramRecv`](super::DatagramRecv), which retains two epoch keys,
/// 1040 / 1992 against 104. Budget for that on a small target before naming
/// this cipher.
///
/// [`AesGcmKey`] wipes the schedule on drop, with **volatile** writes.
/// cryptoxide zeroes `h` and the round keys in its own `Drop` impls, but
/// with ordinary stores that LLVM is free to delete once the storage is
/// about to be released — and under fat LTO it does delete every one of
/// them. hiss does not rely on them: it runs cryptoxide's destructor and
/// then wipes the bytes itself. That mattered less when the schedule was a
/// per-call stack value; now it is the only live copy of the session key
/// (the first two AES-256 round keys are that key verbatim) for the whole
/// session.
#[derive(Debug, Clone, Copy, Default)]
pub struct AesGcm;

/// [`AesGcm`]'s expanded key — the AES-256 round-key schedule and the GHASH
/// subkey `H`, built once per Noise key by [`Cipher::key`].
///
/// 496 bytes on `aarch64` with the `aes` target feature (fifteen encryption
/// and fifteen decryption round keys as `uint8x16_t`, plus the 16-byte `H`;
/// GCM's CTR mode never decrypts a block, but cryptoxide expands the
/// decryption half anyway), 976 bytes on the portable fixsliced path
/// (`[u64; 120]` plus `H`).
///
/// Deliberately opaque — no `Clone`, `Copy`, `Debug` or `PartialEq` — and
/// scrubbed on drop with volatile writes; see [`AesGcm`]'s docs for why hiss
/// does that itself rather than leaving it to cryptoxide.
pub struct AesGcmKey(ManuallyDrop<AesGcm256>);

impl Drop for AesGcmKey {
    fn drop(&mut self) {
        // Runs cryptoxide's own `Drop` first, then volatile-zeroes every byte
        // the value occupied. This is the one call site, it is the owning
        // type's `Drop`, and nothing reads the field afterwards — which is
        // exactly `zeroize_storage`'s caller contract; see its docs for the
        // safety argument, and `AesGcm`'s for why the second step is not
        // belt-and-braces: cryptoxide's zeroing stores are plain, and LTO
        // deletes them.
        crate::zeroize::zeroize_storage(&mut self.0);
    }
}

impl Cipher for AesGcm {
    const NAME: &'static str = "AESGCM";
    const TAG_SIZE: usize = 16;

    type Key = AesGcmKey;

    fn key(k: &[u8; 32]) -> AesGcmKey {
        AesGcmKey(ManuallyDrop::new(AesGcm256::new(k)))
    }

    fn encrypt(
        key: &AesGcmKey,
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

        let nonce = nonce_be(nonce);
        // The trait wants ciphertext‖tag in one buffer; cryptoxide returns
        // the tag separately, so the split is ours to get right.
        let (ct, tag_out) = output[..total].split_at_mut(ct_len);
        let mut tag = Tag([0u8; Self::TAG_SIZE]);
        key.0.encrypt(&nonce, ad, plaintext, ct, &mut tag);
        tag_out.copy_from_slice(&tag.0);
        Ok(total)
    }

    fn decrypt(
        key: &AesGcmKey,
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

        let nonce = nonce_be(nonce);
        let (ct, tag) = ciphertext.split_at(pt_len);
        let tag = Tag(tag.try_into().expect("split at len - TAG_SIZE"));
        match key.0.decrypt(&nonce, ad, ct, &mut output[..pt_len], &tag) {
            DecryptionResult::Match => Ok(pt_len),
            DecryptionResult::MisMatch => {
                // cryptoxide verifies BEFORE writing, so `output` is untouched
                // here — unlike ChaChaPoly, which leaves the full unverified
                // plaintext behind. Untouched is still not safe: in a reused
                // buffer the PREVIOUS message's plaintext survives, and a
                // caller that ignores the `Err` would read it as this message.
                // Zero it, so the failure contract is uniform across ciphers.
                // (Fail-safe only — authentication is not bypassed.)
                crate::zeroize::zeroize_bytes(&mut output[..pt_len]);
                Err(HandshakeError::DecryptionFailed)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::MaybeUninit;

    /// Count the non-zero bytes of `len` bytes at `p`.
    ///
    /// # Safety
    ///
    /// `p` must be valid for reads of `len` initialised bytes.
    unsafe fn count_nonzero(p: *mut u8, len: usize) -> usize {
        // Volatile so the reads cannot be folded away against the stores the
        // destructor made.
        (0..len)
            // SAFETY: the caller guarantees `len` readable initialised bytes
            // from `p`, and `i < len`.
            .filter(|&i| unsafe { p.add(i).read_volatile() } != 0)
            .count()
    }

    /// Build a `K`, count its non-zero bytes, drop it in place, count again.
    ///
    /// # Safety
    ///
    /// Sound only for a `K` **without padding** whose constructor
    /// initialises every byte — otherwise the counts read uninitialised
    /// padding as `u8`. Both [`Cipher::Key`] types qualify (`[u8; 32]`;
    /// `30 × 16 + 16` on `aarch64`, `120 × 8 + 16` portable).
    unsafe fn scrub_probe<K>(build: impl FnOnce() -> K) -> (usize, usize) {
        let mut slot = MaybeUninit::new(build());
        let size = size_of::<K>();
        // SAFETY: `slot` holds an initialised, padding-free `K` (the
        // function's own precondition), so all `size` bytes are initialised.
        let before = unsafe { count_nonzero(slot.as_mut_ptr().cast::<u8>(), size) };
        // SAFETY: `slot` was initialised by `MaybeUninit::new` just above and
        // is dropped exactly once, here; nothing reads it as a `K` after.
        unsafe { slot.assume_init_drop() };
        // SAFETY: the storage is still ours and still allocated, and holds
        // exactly the bytes the destructor left behind — `MaybeUninit`
        // permits any contents.
        let after = unsafe { count_nonzero(slot.as_mut_ptr().cast::<u8>(), size) };
        (before, after)
    }

    /// [`ChaChaPolyKey`] leaves zeros behind — the [`Cipher::Key`]
    /// scrub-on-drop contract hiss relies on for the life of a session.
    ///
    /// Two things to know about this probe, about
    /// `aes_gcm::key_scrubs_on_drop` which shares it, and about
    /// `cipher_state::tests::cipher_state_scrubs_key_on_drop`, which does
    /// the same thing one level up.
    ///
    /// It pins the **contract**, not the volatile pass. Reading the storage
    /// back is itself a use of those bytes, so it keeps even ordinary,
    /// elidable zeroing stores alive — in every profile, not just debug: a
    /// raw `AesGcm256`, scrubbed only by cryptoxide's own plain stores,
    /// passes exactly this probe in release. What makes hiss's wipe survive
    /// optimisation is that `zeroize_storage` is a volatile loop and a
    /// fence, and the evidence for that is the disassembly, not this test.
    /// What this test catches is a `Key` that stops scrubbing at all.
    ///
    /// And it is sound *for these two types* because neither carries
    /// padding and `Cipher::key` initialises every byte, so nothing here
    /// reads an uninitialised byte. On a padded type it would.
    #[test]
    fn chachapoly_key_scrubs_on_drop() {
        // SAFETY: `ChaChaPolyKey` is a `[u8; 32]` newtype — no padding, every
        // byte written by `ChaChaPoly::key`.
        let (before, after) = unsafe { scrub_probe(|| ChaChaPoly::key(&[0xA5u8; 32])) };
        assert_eq!(before, 32, "the probe must see the live key first");
        assert_eq!(after, 0, "ChaChaPolyKey must leave zeros behind on drop");
    }

    /// The LE/BE swap is silent at counter 0 — both encodings produce twelve
    /// zero bytes — so this asserts n = 1, where they first differ, and an
    /// n whose byte order is unambiguous.
    #[test]
    fn nonces_differ_in_byte_order_from_counter_one() {
        assert_eq!(nonce_le(0), [0u8; 12], "counter 0 is all zeros either way");
        assert_eq!(nonce_be(0), [0u8; 12], "counter 0 is all zeros either way");

        let mut le = [0u8; 12];
        le[4] = 1;
        assert_eq!(
            nonce_le(1),
            le,
            "Noise §12.3 ChaChaPoly nonce is LITTLE-endian"
        );

        let mut be = [0u8; 12];
        be[11] = 1;
        assert_eq!(nonce_be(1), be, "Noise §12.4 AESGCM nonce is BIG-endian");
        assert_ne!(
            nonce_be(1),
            nonce_le(1),
            "the two encodings diverge at n = 1"
        );

        assert_eq!(
            nonce_be(0x0102_0304_0506_0708)[4..],
            [1, 2, 3, 4, 5, 6, 7, 8],
            "most-significant byte first"
        );
        assert_eq!(
            nonce_le(0x0102_0304_0506_0708)[4..],
            [8, 7, 6, 5, 4, 3, 2, 1],
            "least-significant byte first"
        );
    }

    #[test]
    fn chachapoly_decrypt_failure_zeroes_output() {
        let key = [0x42u8; 32];
        let mut ct = [0u8; 64];
        let n = ChaChaPoly::encrypt(&ChaChaPoly::key(&key), 0, &[], b"secret payload", &mut ct)
            .unwrap();
        ct[n - 1] ^= 0xFF; // corrupt the tag
        let mut pt = [0xAAu8; 64];
        let err =
            ChaChaPoly::decrypt(&ChaChaPoly::key(&key), 0, &[], &ct[..n], &mut pt).unwrap_err();
        assert!(matches!(err, HandshakeError::DecryptionFailed));
        let pt_len = n - ChaChaPoly::TAG_SIZE;
        assert!(
            pt[..pt_len].iter().all(|&b| b == 0),
            "plaintext region must be zeroed on auth failure"
        );
    }

    /// The AESGCM-specific tests. The corpus and live-interop legs prove the
    /// cipher against foreign implementations; these pin the properties of
    /// *this* adapter that no vector reaches — the failure path, the buffer
    /// contract, the tag geometry, and the mechanism the docs describe.
    mod aes_gcm {
        use super::*;

        /// The mechanism claim behind [`AesGcm`]'s doc comment and its
        /// explicit zeroing, asserted rather than assumed.
        ///
        /// If a future cryptoxide switched to write-then-verify, this test
        /// goes red and the docs stop being a lie quietly — which is the
        /// point of pinning the mechanism, not just the outcome.
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

        /// Both halves of the failure contract. The fresh-buffer half is the
        /// direct port of the ChaChaPoly test; the **reused**-buffer half is
        /// the one that catches this cipher's real hazard — because
        /// cryptoxide leaves `output` untouched on mismatch, a buffer that
        /// already holds the previous message's plaintext would silently
        /// keep it.
        #[test]
        fn decrypt_failure_zeroes_output() {
            let key = [0x42u8; 32];
            let mut ct = [0u8; 64];
            let n =
                AesGcm::encrypt(&AesGcm::key(&key), 0, &[], b"secret payload", &mut ct).unwrap();
            let pt_len = n - AesGcm::TAG_SIZE;

            let mut corrupted = ct;
            corrupted[n - 1] ^= 0xFF; // corrupt the tag

            // Fresh buffer, poisoned so a no-op would be visible.
            let mut pt = [0xAAu8; 64];
            let err =
                AesGcm::decrypt(&AesGcm::key(&key), 0, &[], &corrupted[..n], &mut pt).unwrap_err();
            assert!(matches!(err, HandshakeError::DecryptionFailed));
            assert!(
                pt[..pt_len].iter().all(|&b| b == 0),
                "plaintext region must be zeroed on auth failure"
            );

            // Reused buffer: a prior *successful* decrypt left real plaintext
            // here.
            let mut pt = [0u8; 64];
            AesGcm::decrypt(&AesGcm::key(&key), 0, &[], &ct[..n], &mut pt).unwrap();
            assert_eq!(&pt[..pt_len], b"secret payload", "prior message decrypted");

            let err =
                AesGcm::decrypt(&AesGcm::key(&key), 0, &[], &corrupted[..n], &mut pt).unwrap_err();
            assert!(matches!(err, HandshakeError::DecryptionFailed));
            assert!(
                pt[..pt_len].iter().all(|&b| b == 0),
                "stale plaintext from the PREVIOUS message must not survive a failed decrypt"
            );
        }

        /// Tag truncation, which Wycheproof does **not** cover: every vector
        /// in `aes_gcm_test.json` at the pinned commit has `tagSize: 128`
        /// (see `tests/vectors/wycheproof/PROVENANCE.md`), so nothing in
        /// that corpus exercises a short tag. This is the bespoke
        /// replacement: shorter-than-a-tag input, a one-byte truncation.
        #[test]
        fn truncated_tags_rejected() {
            let key = [0x42u8; 32];
            let mut ct = [0u8; 64];
            let n =
                AesGcm::encrypt(&AesGcm::key(&key), 3, b"ad", b"secret payload", &mut ct).unwrap();
            let mut out = [0u8; 64];

            // Nothing can be a valid ciphertext‖tag if it is shorter than the
            // tag.
            for short in 0..AesGcm::TAG_SIZE {
                assert!(
                    matches!(
                        AesGcm::decrypt(&AesGcm::key(&key), 3, b"ad", &ct[..short], &mut out),
                        Err(HandshakeError::DecryptionFailed)
                    ),
                    "{short}-byte input is shorter than the tag and must be rejected"
                );
            }

            // Truncated by one byte: the split still succeeds, so this reaches
            // the AEAD with a misaligned tag — a prefix comparison would
            // accept it.
            assert!(
                AesGcm::decrypt(&AesGcm::key(&key), 3, b"ad", &ct[..n - 1], &mut out).is_err(),
                "a one-byte truncation must not authenticate"
            );
        }

        /// Every single-bit change to the 128-bit tag is rejected. 128
        /// flips, not 16 — a comparison that ignored the low bits of each
        /// byte would survive a byte-granular test.
        #[test]
        fn every_flipped_tag_bit_rejected() {
            let key = [0x42u8; 32];
            let mut ct = [0u8; 64];
            let n =
                AesGcm::encrypt(&AesGcm::key(&key), 3, b"ad", b"secret payload", &mut ct).unwrap();
            let pt_len = n - AesGcm::TAG_SIZE;
            let mut out = [0u8; 64];

            for bit in 0..(AesGcm::TAG_SIZE * 8) {
                let mut bad = ct;
                bad[pt_len + bit / 8] ^= 1 << (bit % 8);
                assert!(
                    AesGcm::decrypt(&AesGcm::key(&key), 3, b"ad", &bad[..n], &mut out).is_err(),
                    "tag bit {bit} flipped must be rejected"
                );
            }

            // …and the untampered tag still verifies, so the loop above is
            // not passing because everything is rejected.
            assert_eq!(
                AesGcm::decrypt(&AesGcm::key(&key), 3, b"ad", &ct[..n], &mut out).unwrap(),
                pt_len
            );
        }

        /// A ciphertext bit flip is rejected too — the tag covers the
        /// ciphertext, not just itself.
        #[test]
        fn flipped_ciphertext_rejected() {
            let key = [0x42u8; 32];
            let mut ct = [0u8; 64];
            let n =
                AesGcm::encrypt(&AesGcm::key(&key), 3, b"ad", b"secret payload", &mut ct).unwrap();
            let pt_len = n - AesGcm::TAG_SIZE;
            let mut out = [0u8; 64];

            for byte in 0..pt_len {
                let mut bad = ct;
                bad[byte] ^= 0x01;
                assert!(
                    AesGcm::decrypt(&AesGcm::key(&key), 3, b"ad", &bad[..n], &mut out).is_err(),
                    "ciphertext byte {byte} flipped must be rejected"
                );
            }
        }

        /// The AD is authenticated, so decrypting under a different AD must
        /// fail; so must the right AD under a different counter, which is
        /// authenticated through the nonce.
        #[test]
        fn wrong_associated_data_rejected() {
            let key = [0x42u8; 32];
            let mut ct = [0u8; 64];
            let n =
                AesGcm::encrypt(&AesGcm::key(&key), 1, b"ad", b"secret payload", &mut ct).unwrap();
            let mut out = [0u8; 64];

            assert!(AesGcm::decrypt(&AesGcm::key(&key), 1, b"AD", &ct[..n], &mut out).is_err());
            assert!(AesGcm::decrypt(&AesGcm::key(&key), 1, &[], &ct[..n], &mut out).is_err());
            // Right AD, wrong nonce.
            assert!(AesGcm::decrypt(&AesGcm::key(&key), 2, b"ad", &ct[..n], &mut out).is_err());
            // Right everything.
            assert!(AesGcm::decrypt(&AesGcm::key(&key), 1, b"ad", &ct[..n], &mut out).is_ok());
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
                AesGcm::encrypt(&AesGcm::key(&key), 0, &[], b"secret payload", &mut tiny),
                Err(HandshakeError::OutputBufferTooSmall {
                    needed: 30,
                    actual: 8
                })
            ));

            let n =
                AesGcm::encrypt(&AesGcm::key(&key), 0, &[], b"secret payload", &mut ct).unwrap();
            assert_eq!(n, 14 + AesGcm::TAG_SIZE, "ciphertext‖tag, tag appended");

            // decrypt: needs ciphertext.len() - TAG_SIZE
            let mut tiny = [0u8; 8];
            assert!(matches!(
                AesGcm::decrypt(&AesGcm::key(&key), 0, &[], &ct[..n], &mut tiny),
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
            let n = AesGcm::encrypt(&AesGcm::key(&key), 0, b"ad", &[], &mut ct).unwrap();
            assert_eq!(n, AesGcm::TAG_SIZE, "tag only");

            let mut out = [0u8; 32];
            assert_eq!(
                AesGcm::decrypt(&AesGcm::key(&key), 0, b"ad", &ct[..n], &mut out).unwrap(),
                0
            );

            let mut bad = ct;
            bad[0] ^= 0x01;
            assert!(AesGcm::decrypt(&AesGcm::key(&key), 0, b"ad", &bad[..n], &mut out).is_err());
        }

        /// [`AesGcmKey`] leaves zeros behind — the expanded AES-256
        /// schedule and the GHASH subkey both. See
        /// [`chachapoly_key_scrubs_on_drop`](super::chachapoly_key_scrubs_on_drop)
        /// for what this probe does and does not prove.
        #[test]
        fn key_scrubs_on_drop() {
            // SAFETY: `AesGcm256` is round keys plus a 16-byte `H` — arrays
            // of vector words or `u64`, no padding — and `AesGcm::key`
            // initialises all of it.
            let (before, after) = unsafe { super::scrub_probe(|| AesGcm::key(&[0xA5u8; 32])) };
            assert!(
                before > 32,
                "the probe must see a live, expanded schedule first (saw {before} non-zero bytes)"
            );
            assert_eq!(after, 0, "AesGcmKey must leave zeros behind on drop");
        }

        /// The Noise name and tag size are wire-visible constants: `NAME` is
        /// mixed into the protocol name that seeds the handshake hash, and
        /// `TAG_SIZE` sets every generated message's compile-time width.
        #[test]
        fn noise_constants() {
            assert_eq!(AesGcm::NAME, "AESGCM");
            assert_eq!(AesGcm::TAG_SIZE, 16, "Noise §12.4: 128-bit tag");
        }
    }
}
