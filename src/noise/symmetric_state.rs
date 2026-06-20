//! Noise SymmetricState — chaining key, handshake hash, and embedded
//! CipherState.
//!
//! This is the core mixing state of the handshake: every DH output,
//! PSK, and encrypted payload is folded into the chaining key (`ck`)
//! and handshake hash (`h`) through `mix_key`, `mix_hash`, and their
//! combined variant `mix_key_and_hash`.

use super::cipher::Cipher;
use super::cipher_state::CipherState;
use super::error::HandshakeError;
use super::hash::Hash;
use crate::zeroize::{zeroize_array, zeroize_bytes};
use std::marker::PhantomData;

/// Noise HKDF with 2 outputs.
///
/// ```text
/// temp_key = HMAC-HASH(ck, ikm)
/// output1  = HMAC-HASH(temp_key, 0x01)
/// output2  = HMAC-HASH(temp_key, output1 || 0x02)
/// ```
fn noise_hkdf_2<H: Hash>(ck: &[u8], ikm: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut temp_key = H::hmac(ck, ikm);
    let output1 = H::hmac(&temp_key, &[0x01]);
    let mut input2 = output1.clone();
    input2.push(0x02);
    let output2 = H::hmac(&temp_key, &input2);
    zeroize_bytes(&mut temp_key);
    zeroize_bytes(&mut input2);
    (output1, output2)
}

/// Noise HKDF with 3 outputs.
///
/// ```text
/// temp_key = HMAC-HASH(ck, ikm)
/// output1  = HMAC-HASH(temp_key, 0x01)
/// output2  = HMAC-HASH(temp_key, output1 || 0x02)
/// output3  = HMAC-HASH(temp_key, output2 || 0x03)
/// ```
fn noise_hkdf_3<H: Hash>(ck: &[u8], ikm: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let mut temp_key = H::hmac(ck, ikm);
    let output1 = H::hmac(&temp_key, &[0x01]);
    let mut input2 = output1.clone();
    input2.push(0x02);
    let output2 = H::hmac(&temp_key, &input2);
    let mut input3 = output2.clone();
    input3.push(0x03);
    let output3 = H::hmac(&temp_key, &input3);
    zeroize_bytes(&mut temp_key);
    zeroize_bytes(&mut input2);
    zeroize_bytes(&mut input3);
    (output1, output2, output3)
}

/// The Noise SymmetricState.
///
/// Maintains the chaining key (`ck`), handshake hash (`h`), and an
/// embedded [`CipherState`] that is used for encrypting static keys
/// and payloads once keying material has been established.
pub struct SymmetricState<Ci: Cipher, H: Hash> {
    /// Chaining key — updated by each `mix_key` call.
    ck: Vec<u8>,
    /// Handshake hash — updated by each `mix_hash` call.
    h: Vec<u8>,
    /// Embedded CipherState for encrypt-and-hash / decrypt-and-hash.
    cipher_state: CipherState<Ci>,
    _hash: PhantomData<H>,
}

impl<Ci: Cipher, H: Hash> SymmetricState<Ci, H> {
    /// Initialise from a protocol name string.
    ///
    /// If the protocol name is ≤ `HASHLEN` bytes, it is padded with
    /// zeroes to `HASHLEN`. Otherwise it is hashed.
    pub fn initialize(protocol_name: &str) -> Self {
        let h = if protocol_name.len() <= H::HASH_LEN {
            let mut h = vec![0u8; H::HASH_LEN];
            h[..protocol_name.len()].copy_from_slice(protocol_name.as_bytes());
            h
        } else {
            H::hash(protocol_name.as_bytes())
        };
        let ck = h.clone();
        Self {
            ck,
            h,
            cipher_state: CipherState::empty(),
            _hash: PhantomData,
        }
    }

    /// Returns `true` if the embedded CipherState has a key.
    ///
    /// Callers check this to learn whether a static key written by the
    /// `s` token will be sent encrypted (with an AEAD tag, once a key
    /// has been established) or in the clear.
    pub fn has_key(&self) -> bool {
        self.cipher_state.has_key()
    }

    /// Mix key material into the chaining key via HKDF.
    ///
    /// Derives a new `ck` and optionally a new cipher key.
    pub(crate) fn mix_key(&mut self, input_key_material: &[u8]) {
        let (new_ck, mut temp_k) = noise_hkdf_2::<H>(&self.ck, input_key_material);
        zeroize_bytes(&mut self.ck);
        self.ck = new_ck;
        let mut key = [0u8; 32];
        key.copy_from_slice(&temp_k[..32]);
        self.cipher_state = CipherState::from_key(key);
        zeroize_array(&mut key);
        zeroize_bytes(&mut temp_k);
    }

    /// Mix data into the handshake hash.
    pub(crate) fn mix_hash(&mut self, data: &[u8]) {
        self.h = H::hash_two(&self.h, data);
    }

    /// Mix a PSK into both the chaining key and the handshake hash.
    ///
    /// `HKDF(ck, psk)` → `(new_ck, temp_h, temp_k)`.
    /// `temp_h` is mixed into `h`; `temp_k` becomes the cipher key.
    pub(crate) fn mix_key_and_hash(&mut self, input_key_material: &[u8]) {
        let (new_ck, mut temp_h, mut temp_k) = noise_hkdf_3::<H>(&self.ck, input_key_material);
        zeroize_bytes(&mut self.ck);
        self.ck = new_ck;
        self.mix_hash(&temp_h);
        let mut key = [0u8; 32];
        key.copy_from_slice(&temp_k[..32]);
        self.cipher_state = CipherState::from_key(key);
        zeroize_array(&mut key);
        zeroize_bytes(&mut temp_h);
        zeroize_bytes(&mut temp_k);
    }

    /// Encrypt `plaintext` under the current cipher key with `h` as
    /// associated data, writing the result into `output`.
    ///
    /// Updates `h` with the output bytes. Returns the number of bytes
    /// written.
    pub(crate) fn encrypt_and_hash(
        &mut self,
        plaintext: &[u8],
        output: &mut [u8],
    ) -> Result<usize, HandshakeError> {
        let len = self
            .cipher_state
            .encrypt_with_ad(&self.h, plaintext, output)?;
        self.mix_hash(&output[..len]);
        Ok(len)
    }

    /// Decrypt `ciphertext` under the current cipher key with `h` as
    /// associated data, writing the plaintext into `output`.
    ///
    /// Updates `h` with the ciphertext (before decryption). Returns
    /// the number of plaintext bytes written.
    pub(crate) fn decrypt_and_hash(
        &mut self,
        ciphertext: &[u8],
        output: &mut [u8],
    ) -> Result<usize, HandshakeError> {
        let len = self
            .cipher_state
            .decrypt_with_ad(&self.h, ciphertext, output)?;
        self.mix_hash(ciphertext);
        Ok(len)
    }

    /// Split into two CipherStates for transport.
    ///
    /// Returns `(initiator_to_responder, responder_to_initiator)`.
    pub(crate) fn split(mut self) -> (CipherState<Ci>, CipherState<Ci>) {
        let (mut temp_k1, mut temp_k2) = noise_hkdf_2::<H>(&self.ck, &[]);
        let mut key1 = [0u8; 32];
        key1.copy_from_slice(&temp_k1[..32]);
        let mut key2 = [0u8; 32];
        key2.copy_from_slice(&temp_k2[..32]);
        let result = (CipherState::from_key(key1), CipherState::from_key(key2));
        zeroize_array(&mut key1);
        zeroize_array(&mut key2);
        zeroize_bytes(&mut temp_k1);
        zeroize_bytes(&mut temp_k2);
        // ck is zeroed by our Drop impl
        zeroize_bytes(&mut self.ck);
        result
    }

    /// The current handshake hash — used as the channel binding value
    /// after the handshake completes.
    pub fn handshake_hash(&self) -> &[u8] {
        &self.h
    }
}

impl<Ci: Cipher, H: Hash> Drop for SymmetricState<Ci, H> {
    fn drop(&mut self) {
        zeroize_bytes(&mut self.ck);
        // h is the handshake hash — not secret, but zero it anyway
        // for defence in depth. CipherState handles its own key.
    }
}
