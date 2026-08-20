//! Volatile zeroing of secret material.
//!
//! Each byte is written with `ptr::write_volatile` followed by a
//! `core::sync::atomic::compiler_fence(SeqCst)` to prevent the compiler
//! from eliding the zero-fill as a dead store. This is the same
//! technique used by the `zeroize` crate.

use core::mem::ManuallyDrop;
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

/// Drop the value held in `slot`, then volatile-zero the storage it
/// occupied.
///
/// This is the escape hatch for a secret whose type belongs to another
/// crate: `hiss` cannot reach inside such a value to wipe its fields, and a
/// `Drop` impl that assigns zeros with ordinary stores is precisely the
/// pattern LLVM is entitled to delete once the storage is about to be
/// released — which, under LTO, it does. Hold the value in a
/// [`ManuallyDrop`] field, call this from the owning type's `Drop`, and the
/// foreign destructor still runs (step 1) but every byte the value occupied
/// is afterwards wiped with the same volatile write plus compiler fence
/// [`zeroize_bytes`] uses (step 2), whatever that destructor did or did not
/// do.
///
/// This is how [`AesGcmKey`](crate::noise::AesGcmKey) meets the
/// [`Cipher::Key`](crate::noise::Cipher::Key) scrub-on-drop contract over
/// `cryptoxide`'s `AesGcm256`.
///
/// # Caller obligations
///
/// This function is **safe to call only under a contract it cannot check**,
/// which is why it is crate-private rather than part of `hiss`'s public API:
///
/// * Call it **exactly once** per value, from the owning type's `Drop`. A
///   second call re-runs `T`'s destructor over all-zero bytes — freeing a
///   null pointer, for anything that owns an allocation.
/// * **Never touch `slot` again** afterwards. The value has been dropped and
///   its bytes overwritten; `ManuallyDrop`'s safe `Deref` would hand out a
///   dangling `T`. Calling this from the owner's `Drop` on a
///   `ManuallyDrop` field satisfies this by construction, because the
///   owner's drop glue skips that field and nothing else can reach it.
///
/// `T`'s layout, padding included, is irrelevant: step 2 only ever *writes*
/// bytes — through a raw pointer, forming no reference — to storage the slot
/// owns and whose value has already been dropped, so no byte is ever read
/// and nothing here depends on `T` having initialised all of them.
pub(crate) fn zeroize_storage<T>(slot: &mut ManuallyDrop<T>) {
    // SAFETY: per this function's caller obligations, it is called exactly
    // once, from the owning type's `Drop`, on a field that the owner's drop
    // glue will not touch again — so nothing else drops the value, and
    // nothing reads it after this point.
    unsafe { ManuallyDrop::drop(slot) };

    // `&raw mut` rather than `&mut *slot as *mut _`: no `&mut T` to the
    // just-dropped value is ever materialised.
    let start = (&raw mut *slot).cast::<u8>();
    for i in 0..size_of::<T>() {
        // SAFETY: `start` is derived from a unique borrow of the field, and
        // `ManuallyDrop<T>` is `repr(transparent)`, so `start .. start +
        // size_of::<T>()` is exactly the field's extent: one allocation this
        // call exclusively owns, non-null and trivially aligned for `u8`.
        // The byte is written, never read, so its initialisation state does
        // not matter; and by the obligations above no typed access to the
        // field follows.
        unsafe { start.add(i).write_volatile(0) };
    }
    // Same fence as `zeroize_bytes`: the volatile stores are observable side
    // effects, so the zero-fill cannot be elided as a dead store.
    compiler_fence(Ordering::SeqCst);
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

    /// `zeroize_storage` does **both** halves: it runs the inner
    /// destructor and it wipes the storage. Either one alone would look
    /// like success from the other's point of view, so both are asserted.
    #[test]
    fn zeroize_storage_drops_then_wipes() {
        use core::sync::atomic::AtomicUsize;

        static DROPS: AtomicUsize = AtomicUsize::new(0);

        struct Noisy([u8; 16]);
        impl Noisy {
            /// Reading the payload back keeps the field live for the lint
            /// and, more to the point, proves the probe is looking at it.
            fn first(&self) -> u8 {
                self.0[0]
            }
        }
        impl Drop for Noisy {
            fn drop(&mut self) {
                DROPS.fetch_add(1, Ordering::SeqCst);
            }
        }

        let mut slot = ManuallyDrop::new(Noisy([0xCD; 16]));
        assert_eq!(slot.first(), 0xCD, "the payload starts non-zero");
        zeroize_storage(&mut slot);

        assert_eq!(
            DROPS.load(Ordering::SeqCst),
            1,
            "the inner destructor must still run"
        );
        // SAFETY: our own storage, still allocated; `Noisy` is a `[u8; 16]`
        // newtype with no padding, and these are the bytes `zeroize_storage`
        // just wrote.
        let bytes = unsafe {
            core::slice::from_raw_parts((&raw const slot).cast::<u8>(), size_of::<Noisy>())
        };
        assert!(bytes.iter().all(|&b| b == 0), "the storage must be wiped");
    }
}
