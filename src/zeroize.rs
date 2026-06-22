//! Volatile zeroing of secret material.
//!
//! Each byte is written with `ptr::write_volatile` followed by a
//! `core::sync::atomic::compiler_fence(SeqCst)` to prevent the compiler
//! from eliding the zero-fill as a dead store. This is the same
//! technique used by the `zeroize` crate.

use core::sync::atomic::{Ordering, compiler_fence};

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
    compiler_fence(Ordering::SeqCst);
}

/// Zero a fixed-size array using volatile writes.
///
/// A convenience wrapper that forwards to [`zeroize_bytes`] over the
/// array as a slice; the same volatile-write plus compiler-fence
/// guarantee therefore applies, so the zero-fill cannot be elided as
/// a dead store.
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
