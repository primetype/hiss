//! Volatile zeroing of secret material.
//!
//! Uses `ptr::write_volatile` followed by a compiler fence to
//! prevent the compiler from eliding the zero-fill as a dead store.
//! This is the same technique used by the `zeroize` crate.

use std::sync::atomic::{AtomicBool, Ordering};

/// A volatile read that the compiler cannot optimise away.
///
/// This forces the compiler to treat the preceding volatile writes
/// as observable, preventing dead-store elimination.
#[inline(never)]
fn volatile_fence() {
    static FENCE: AtomicBool = AtomicBool::new(false);
    FENCE.load(Ordering::SeqCst);
}

/// Zero the contents of a byte slice using volatile writes.
///
/// The compiler cannot elide this — each byte is written via
/// `ptr::write_volatile`, and a compiler fence ensures the writes
/// are treated as observable side effects.
pub fn zeroize_bytes(bytes: &mut [u8]) {
    for byte in bytes.iter_mut() {
        // SAFETY: `byte` is a valid, aligned, dereferenceable pointer
        // to a single `u8` within the slice.
        unsafe {
            std::ptr::write_volatile(byte, 0);
        }
    }
    volatile_fence();
}

/// Zero a fixed-size array using volatile writes.
pub fn zeroize_array<const N: usize>(arr: &mut [u8; N]) {
    zeroize_bytes(arr.as_mut_slice());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zeroize_clears_bytes() {
        let mut buf = [0xFFu8; 64];
        zeroize_bytes(&mut buf);
        assert!(buf.iter().all(|&b| b == 0));
    }

    #[test]
    fn zeroize_clears_array() {
        let mut arr = [0xABu8; 32];
        zeroize_array(&mut arr);
        assert!(arr.iter().all(|&b| b == 0));
    }

    #[test]
    fn zeroize_empty_slice() {
        let mut buf = [];
        zeroize_bytes(&mut buf); // must not panic
    }
}
