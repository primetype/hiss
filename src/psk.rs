//! Pre-shared key type for the `Noise_*psk*` patterns.
//!
//! A [`Psk`] is a 32-byte symmetric secret established out of band
//! (e.g. a physical pairing / QR trust ceremony) and used in every
//! subsequent `Noise_IKpsk1` session between a pair of devices. It is
//! zeroed on drop to prevent lingering in memory.

use rand_core::{CryptoRng, RngCore};
use std::fmt;

/// A 32-byte pre-shared key.
///
/// Zeroed on drop. Cannot be displayed (use [`Debug`] for
/// diagnostics, which shows the hex encoding).
#[derive(Clone)]
pub struct Psk([u8; Self::SIZE]);

impl Psk {
    /// PSK length in bytes.
    pub const SIZE: usize = 32;

    /// Wrap existing bytes into a `Psk`.
    #[inline]
    pub fn from_bytes(bytes: [u8; Self::SIZE]) -> Self {
        Self(bytes)
    }

    /// Generate a random PSK using the operating system's CSPRNG.
    #[inline]
    pub fn generate() -> Self {
        let mut bytes = [0u8; Self::SIZE];
        getrandom::fill(&mut bytes).expect("OS CSPRNG fill must not fail");
        Self(bytes)
    }

    /// Generate a random PSK from a caller-supplied CSPRNG.
    ///
    /// Useful for deterministic tests or for plugging in a specific
    /// entropy source.
    pub fn generate_with<R: RngCore + CryptoRng>(mut rng: R) -> Self {
        let mut bytes = [0u8; Self::SIZE];
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Borrow the raw bytes.
    #[inline]
    pub fn as_bytes(&self) -> &[u8; Self::SIZE] {
        &self.0
    }
}

impl AsRef<[u8]> for Psk {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes().as_slice()
    }
}

impl Drop for Psk {
    fn drop(&mut self) {
        crate::zeroize::zeroize_array(&mut self.0);
    }
}

#[cfg(not(test))]
impl fmt::Debug for Psk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Psk").finish_non_exhaustive()
    }
}

#[cfg(test)]
impl fmt::Debug for Psk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Psk").field(&hex::encode(self.0)).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_bytes_round_trip() {
        let bytes = [0x42u8; 32];
        let psk = Psk::from_bytes(bytes);
        assert_eq!(*psk.as_bytes(), bytes);
    }

    #[test]
    fn generate_produces_non_zero() {
        let psk = Psk::generate();
        // Vanishingly unlikely to be all zeros from a CSPRNG.
        assert_ne!(*psk.as_bytes(), [0u8; 32]);
    }

    #[test]
    fn debug_shows_hex() {
        let psk = Psk::from_bytes([0xAB; 32]);
        let dbg = format!("{psk:?}");
        assert!(dbg.starts_with("Psk(\""));
        assert!(dbg.contains(&hex::encode([0xAB; 32])));
    }

    #[test]
    fn clone_preserves_bytes() {
        let psk = Psk::generate();
        let cloned = psk.clone();
        assert_eq!(psk.as_bytes(), cloned.as_bytes());
    }
}
