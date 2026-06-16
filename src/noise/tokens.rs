//! Type-level tokens for Noise handshake patterns.
//!
//! Each token is a zero-sized type representing a single operation
//! in a Noise handshake message. Tokens are composed into messages
//! using [`Cons`]/[`Nil`] type-level lists.
//!
//! # Wire size computation
//!
//! The [`WireSize`] trait computes the exact byte size of a token
//! list at compile time. Only two tokens contribute bytes to the
//! wire:
//!
//! - **`E`** — always `PUBLIC_KEY_SIZE` (plaintext ephemeral).
//! - **`S`** — `PUBLIC_KEY_SIZE` if unkeyed, or
//!   `PUBLIC_KEY_SIZE + TAG_SIZE` if a cipher key has been
//!   established by a preceding DH or PSK token.
//!
//! DH tokens (`Ee`, `Es`, `Se`, `Ss`) and `Psk` contribute zero
//! bytes but transition the symmetric state to *keyed*. This
//! transition is monotonic — once keyed, it stays keyed.
//!
//! The trait tracks both keyed and unkeyed branches simultaneously,
//! using const-`if` to propagate the keyed state through the
//! Cons-list. This avoids unstable `generic_const_exprs`.

use std::marker::PhantomData;

use super::cipher::Cipher;
use crate::curve::Curve;

// ── Handshake tokens ────────────────────────────────────────────

/// Generate and transmit a local ephemeral public key.
pub struct E;

/// Transmit the local static public key (encrypted after key material is established).
pub struct S;

/// DH between both parties' ephemeral keys.
pub struct Ee;

/// DH between initiator's ephemeral and responder's static key.
pub struct Es;

/// DH between initiator's static and responder's ephemeral key.
pub struct Se;

/// DH between both parties' static keys.
pub struct Ss;

/// Inject a pre-shared key into the handshake state.
pub struct Psk;

// ── Type-level list ─────────────────────────────────────────────

/// Terminator for a type-level list.
pub struct Nil;

/// Cons cell: head `H` followed by tail `T`.
pub struct Cons<H, T>(PhantomData<fn() -> (H, T)>);

// ── Message direction ───────────────────────────────────────────

/// Message sent by the initiator (→).
pub struct ToResponder;

/// Message sent by the responder (←).
pub struct ToInitiator;

/// A directed message: a direction paired with a list of tokens.
pub struct Message<Dir, Tokens>(PhantomData<fn() -> (Dir, Tokens)>);

// ── Wire size computation ─────────────────────────────────────────

/// Compile-time wire size computation for Noise handshake tokens.
///
/// Computes the total bytes a token or token list contributes to the
/// wire, and tracks whether the symmetric state becomes keyed. Both
/// keyed and unkeyed starting states are computed simultaneously,
/// avoiding unstable const generic chaining.
///
/// The `HAS_PSK` parameter reflects the pattern's PSK modifier — it
/// affects whether the [`E`] token calls `mix_key`, which transitions
/// the symmetric state to keyed.
pub trait WireSize<Cu: Curve, Ci: Cipher, const HAS_PSK: bool> {
    /// Wire bytes when the symmetric state starts unkeyed.
    const SIZE_UNKEYED: usize;
    /// Wire bytes when the symmetric state starts keyed.
    const SIZE_KEYED: usize;
    /// Whether the state is keyed after processing, given an unkeyed start.
    const KEYED_AFTER_UNKEYED: bool;
    /// Whether the state is keyed after processing, given a keyed start.
    const KEYED_AFTER_KEYED: bool;
}

// ── E ──────────────────────────────────────────────────────────────
// Always writes PUBLIC_KEY_SIZE bytes (ephemeral is never encrypted).
// In a PSK pattern, E also calls mix_key(e_pub), transitioning to keyed.

impl<Cu: Curve, Ci: Cipher> WireSize<Cu, Ci, false> for E {
    const SIZE_UNKEYED: usize = Cu::PUBLIC_KEY_SIZE;
    const SIZE_KEYED: usize = Cu::PUBLIC_KEY_SIZE;
    const KEYED_AFTER_UNKEYED: bool = false;
    const KEYED_AFTER_KEYED: bool = true;
}

impl<Cu: Curve, Ci: Cipher> WireSize<Cu, Ci, true> for E {
    const SIZE_UNKEYED: usize = Cu::PUBLIC_KEY_SIZE;
    const SIZE_KEYED: usize = Cu::PUBLIC_KEY_SIZE;
    const KEYED_AFTER_UNKEYED: bool = true; // PSK pattern: E calls mix_key
    const KEYED_AFTER_KEYED: bool = true;
}

// ── S ──────────────────────────────────────────────────────────────
// Plaintext when unkeyed (PUBLIC_KEY_SIZE), encrypted when keyed
// (PUBLIC_KEY_SIZE + TAG_SIZE). S itself does not call mix_key.

impl<Cu: Curve, Ci: Cipher, const HAS_PSK: bool> WireSize<Cu, Ci, HAS_PSK> for S {
    const SIZE_UNKEYED: usize = Cu::PUBLIC_KEY_SIZE;
    const SIZE_KEYED: usize = Cu::PUBLIC_KEY_SIZE + Ci::TAG_SIZE;
    const KEYED_AFTER_UNKEYED: bool = false;
    const KEYED_AFTER_KEYED: bool = true;
}

// ── DH tokens (Ee, Es, Se, Ss) ────────────────────────────────────
// Zero wire bytes. All call mix_key, transitioning to keyed.

impl<Cu: Curve, Ci: Cipher, const HAS_PSK: bool> WireSize<Cu, Ci, HAS_PSK> for Ee {
    const SIZE_UNKEYED: usize = 0;
    const SIZE_KEYED: usize = 0;
    const KEYED_AFTER_UNKEYED: bool = true;
    const KEYED_AFTER_KEYED: bool = true;
}

impl<Cu: Curve, Ci: Cipher, const HAS_PSK: bool> WireSize<Cu, Ci, HAS_PSK> for Es {
    const SIZE_UNKEYED: usize = 0;
    const SIZE_KEYED: usize = 0;
    const KEYED_AFTER_UNKEYED: bool = true;
    const KEYED_AFTER_KEYED: bool = true;
}

impl<Cu: Curve, Ci: Cipher, const HAS_PSK: bool> WireSize<Cu, Ci, HAS_PSK> for Se {
    const SIZE_UNKEYED: usize = 0;
    const SIZE_KEYED: usize = 0;
    const KEYED_AFTER_UNKEYED: bool = true;
    const KEYED_AFTER_KEYED: bool = true;
}

impl<Cu: Curve, Ci: Cipher, const HAS_PSK: bool> WireSize<Cu, Ci, HAS_PSK> for Ss {
    const SIZE_UNKEYED: usize = 0;
    const SIZE_KEYED: usize = 0;
    const KEYED_AFTER_UNKEYED: bool = true;
    const KEYED_AFTER_KEYED: bool = true;
}

// ── Psk ────────────────────────────────────────────────────────────
// Zero wire bytes. Calls mix_key_and_hash, transitioning to keyed.

impl<Cu: Curve, Ci: Cipher, const HAS_PSK: bool> WireSize<Cu, Ci, HAS_PSK> for Psk {
    const SIZE_UNKEYED: usize = 0;
    const SIZE_KEYED: usize = 0;
    const KEYED_AFTER_UNKEYED: bool = true;
    const KEYED_AFTER_KEYED: bool = true;
}

// ── Nil ────────────────────────────────────────────────────────────
// Empty list: zero bytes, keyed state preserved.

impl<Cu: Curve, Ci: Cipher, const HAS_PSK: bool> WireSize<Cu, Ci, HAS_PSK> for Nil {
    const SIZE_UNKEYED: usize = 0;
    const SIZE_KEYED: usize = 0;
    const KEYED_AFTER_UNKEYED: bool = false;
    const KEYED_AFTER_KEYED: bool = true;
}

// ── Cons ───────────────────────────────────────────────────────────
// Recursive: head's KEYED_AFTER selects the tail's branch via const-if.

impl<H, T, Cu: Curve, Ci: Cipher, const HAS_PSK: bool> WireSize<Cu, Ci, HAS_PSK> for Cons<H, T>
where
    H: WireSize<Cu, Ci, HAS_PSK>,
    T: WireSize<Cu, Ci, HAS_PSK>,
{
    const SIZE_UNKEYED: usize = H::SIZE_UNKEYED
        + if H::KEYED_AFTER_UNKEYED {
            T::SIZE_KEYED
        } else {
            T::SIZE_UNKEYED
        };

    const SIZE_KEYED: usize = H::SIZE_KEYED + T::SIZE_KEYED;

    const KEYED_AFTER_UNKEYED: bool = if H::KEYED_AFTER_UNKEYED {
        T::KEYED_AFTER_KEYED
    } else {
        T::KEYED_AFTER_UNKEYED
    };

    const KEYED_AFTER_KEYED: bool = T::KEYED_AFTER_KEYED;
}

// ── Compile-time message size macro ────────────────────────────────
//
// Computes the total wire size of a Noise handshake message as a true
// `const`, usable in array sizes. The macro walks the token list,
// threading the keyed state through each token, and adds the trailing
// empty-payload tag if the cipher is keyed after all tokens.
//
// Usage:
//
// ```
// const MSG1: usize = noise_message_size!(
//     curve: P256,
//     cipher: ChaChaPoly,
//     has_psk: true,
//     keyed: false,
//     tokens: [E, Es, S, Ss, Psk],
// );
// ```

/// Compute the total wire size of a Noise handshake message at compile
/// time.
///
/// Walks the token list recursively, accumulating sizes and threading
/// the keyed state. Appends `TAG_SIZE` if the cipher is keyed after
/// all tokens (the empty-payload `EncryptAndHash("")` tag).
///
/// The result is a `const`-evaluable `usize` expression.
///
/// # Example
///
/// ```
/// use hiss::noise::curve::P256;
/// use hiss::noise::cipher::ChaChaPoly;
/// use hiss::noise_message_size;
///
/// // IKpsk1 msg1: -> e, es, s, ss, psk
/// const MSG1: usize = noise_message_size!(
///     curve: P256,
///     cipher: ChaChaPoly,
///     has_psk: true,
///     keyed: false,
///     tokens: [E, Es, S, Ss, Psk],
/// );
/// assert_eq!(MSG1, 162);
/// ```
#[macro_export]
macro_rules! noise_message_size {
    // Entry point — delegates to the recursive accumulator.
    (
        curve: $Cu:ty,
        cipher: $Ci:ty,
        has_psk: $has_psk:tt,
        keyed: $keyed:tt,
        tokens: [$($tokens:tt),* $(,)?],
    ) => {
        $crate::noise_message_size!(@accum
            curve: $Cu,
            cipher: $Ci,
            has_psk: $has_psk,
            keyed: $keyed,
            remaining: [$($tokens),*],
            size: 0,
        )
    };

    // Base case — no tokens left. Add the payload tag if keyed.
    (@accum
        curve: $Cu:ty,
        cipher: $Ci:ty,
        has_psk: $_psk:tt,
        keyed: true,
        remaining: [],
        size: $size:expr,
    ) => {
        $size + <$Ci as $crate::noise::cipher::Cipher>::TAG_SIZE
    };
    (@accum
        curve: $Cu:ty,
        cipher: $Ci:ty,
        has_psk: $_psk:tt,
        keyed: false,
        remaining: [],
        size: $size:expr,
    ) => {
        $size
    };

    // ── Recursive cases ──────────────────────────────────────────
    //
    // Each token needs explicit arms because macro_rules! cannot
    // use a macro invocation result as a tt for the next recursion.
    // The keyed-after logic is inlined per token.

    // E — size: PUBLIC_KEY_SIZE. Keyed-after: true if has_psk, else unchanged.
    (@accum curve: $Cu:ty, cipher: $Ci:ty, has_psk: true, keyed: $keyed:tt,
        remaining: [E $(, $rest:tt)*], size: $size:expr,
    ) => {
        $crate::noise_message_size!(@accum curve: $Cu, cipher: $Ci,
            has_psk: true, keyed: true, remaining: [$($rest),*],
            size: $size + <$Cu as $crate::curve::Curve>::PUBLIC_KEY_SIZE,
        )
    };
    (@accum curve: $Cu:ty, cipher: $Ci:ty, has_psk: false, keyed: $keyed:tt,
        remaining: [E $(, $rest:tt)*], size: $size:expr,
    ) => {
        $crate::noise_message_size!(@accum curve: $Cu, cipher: $Ci,
            has_psk: false, keyed: $keyed, remaining: [$($rest),*],
            size: $size + <$Cu as $crate::curve::Curve>::PUBLIC_KEY_SIZE,
        )
    };

    // S — size: PUBLIC_KEY_SIZE + TAG_SIZE if keyed, else PUBLIC_KEY_SIZE.
    //     Keyed-after: unchanged.
    (@accum curve: $Cu:ty, cipher: $Ci:ty, has_psk: $psk:tt, keyed: true,
        remaining: [S $(, $rest:tt)*], size: $size:expr,
    ) => {
        $crate::noise_message_size!(@accum curve: $Cu, cipher: $Ci,
            has_psk: $psk, keyed: true, remaining: [$($rest),*],
            size: $size + <$Cu as $crate::curve::Curve>::PUBLIC_KEY_SIZE
                        + <$Ci as $crate::noise::cipher::Cipher>::TAG_SIZE,
        )
    };
    (@accum curve: $Cu:ty, cipher: $Ci:ty, has_psk: $psk:tt, keyed: false,
        remaining: [S $(, $rest:tt)*], size: $size:expr,
    ) => {
        $crate::noise_message_size!(@accum curve: $Cu, cipher: $Ci,
            has_psk: $psk, keyed: false, remaining: [$($rest),*],
            size: $size + <$Cu as $crate::curve::Curve>::PUBLIC_KEY_SIZE,
        )
    };

    // DH tokens (Es, Ee, Se, Ss) — zero bytes, always keys the state.
    (@accum curve: $Cu:ty, cipher: $Ci:ty, has_psk: $psk:tt, keyed: $keyed:tt,
        remaining: [Es $(, $rest:tt)*], size: $size:expr,
    ) => {
        $crate::noise_message_size!(@accum curve: $Cu, cipher: $Ci,
            has_psk: $psk, keyed: true, remaining: [$($rest),*], size: $size,
        )
    };
    (@accum curve: $Cu:ty, cipher: $Ci:ty, has_psk: $psk:tt, keyed: $keyed:tt,
        remaining: [Ee $(, $rest:tt)*], size: $size:expr,
    ) => {
        $crate::noise_message_size!(@accum curve: $Cu, cipher: $Ci,
            has_psk: $psk, keyed: true, remaining: [$($rest),*], size: $size,
        )
    };
    (@accum curve: $Cu:ty, cipher: $Ci:ty, has_psk: $psk:tt, keyed: $keyed:tt,
        remaining: [Se $(, $rest:tt)*], size: $size:expr,
    ) => {
        $crate::noise_message_size!(@accum curve: $Cu, cipher: $Ci,
            has_psk: $psk, keyed: true, remaining: [$($rest),*], size: $size,
        )
    };
    (@accum curve: $Cu:ty, cipher: $Ci:ty, has_psk: $psk:tt, keyed: $keyed:tt,
        remaining: [Ss $(, $rest:tt)*], size: $size:expr,
    ) => {
        $crate::noise_message_size!(@accum curve: $Cu, cipher: $Ci,
            has_psk: $psk, keyed: true, remaining: [$($rest),*], size: $size,
        )
    };

    // Psk — zero bytes, always keys the state.
    (@accum curve: $Cu:ty, cipher: $Ci:ty, has_psk: $psk:tt, keyed: $keyed:tt,
        remaining: [Psk $(, $rest:tt)*], size: $size:expr,
    ) => {
        $crate::noise_message_size!(@accum curve: $Cu, cipher: $Ci,
            has_psk: $psk, keyed: true, remaining: [$($rest),*], size: $size,
        )
    };
}

#[cfg(test)]
#[allow(clippy::bool_assert_comparison)]
mod tests {
    use super::*;
    use crate::noise::cipher::ChaChaPoly;
    use crate::noise::curve::P256;

    // IKpsk1 token lists (HAS_PSK = true)
    type Msg1Tokens = Cons<E, Cons<Es, Cons<S, Cons<Ss, Cons<Psk, Nil>>>>>; // -> e, es, s, ss, psk
    type Msg2Tokens = Cons<E, Cons<Ee, Cons<Se, Nil>>>; // <- e, ee, se

    #[test]
    fn ikpsk1_msg1_size() {
        // msg1 starts unkeyed. E writes 65 bytes, Es keys the state,
        // S is encrypted (65 + 16 = 81), Ss and Psk write 0 bytes.
        assert_eq!(
            <Msg1Tokens as WireSize<P256, ChaChaPoly, true>>::SIZE_UNKEYED,
            65 + 81 // e_pub + encrypted(s_pub) + tag
        );
        // After msg1, state is keyed.
        assert_eq!(
            <Msg1Tokens as WireSize<P256, ChaChaPoly, true>>::KEYED_AFTER_UNKEYED,
            true
        );
    }

    #[test]
    fn ikpsk1_msg2_size() {
        // msg2 starts keyed (from msg1). E writes 65 bytes.
        assert_eq!(
            <Msg2Tokens as WireSize<P256, ChaChaPoly, true>>::SIZE_KEYED,
            65
        );
        // Still keyed after msg2.
        assert_eq!(
            <Msg2Tokens as WireSize<P256, ChaChaPoly, true>>::KEYED_AFTER_KEYED,
            true
        );
    }

    #[test]
    fn non_psk_e_does_not_key() {
        // Without PSK modifier, E does not transition to keyed.
        assert_eq!(
            <E as WireSize<P256, ChaChaPoly, false>>::KEYED_AFTER_UNKEYED,
            false
        );

        // Hypothetical non-PSK pattern: e, s (both unkeyed).
        type EsThenS = Cons<E, Cons<S, Nil>>;
        assert_eq!(
            <EsThenS as WireSize<P256, ChaChaPoly, false>>::SIZE_UNKEYED,
            65 + 65 // both plaintext
        );
    }

    #[test]
    fn dh_before_s_encrypts_s() {
        // e, es, s — Es keys the state, so S is encrypted.
        type EEsS = Cons<E, Cons<Es, Cons<S, Nil>>>;
        assert_eq!(
            <EEsS as WireSize<P256, ChaChaPoly, false>>::SIZE_UNKEYED,
            65 + (65 + 16) // E plaintext (65), Es (0), S encrypted (65 + 16)
        );
    }

    // ── noise_message_size! macro tests ────────────────────────────

    #[test]
    fn macro_ikpsk1_msg1() {
        // -> e, es, s, ss, psk (starts unkeyed, HAS_PSK = true)
        // e(65) + es(0,keys) + s(65+16) + ss(0) + psk(0) + payload_tag(16) = 162
        const SIZE: usize = noise_message_size!(
            curve: P256,
            cipher: ChaChaPoly,
            has_psk: true,
            keyed: false,
            tokens: [E, Es, S, Ss, Psk],
        );
        assert_eq!(SIZE, 162);
    }

    #[test]
    fn macro_ikpsk1_msg2() {
        // <- e, ee, se (starts keyed, HAS_PSK = true)
        // e(65) + ee(0) + se(0) + payload_tag(16) = 81
        const SIZE: usize = noise_message_size!(
            curve: P256,
            cipher: ChaChaPoly,
            has_psk: true,
            keyed: true,
            tokens: [E, Ee, Se],
        );
        assert_eq!(SIZE, 81);
    }

    #[test]
    fn macro_n_msg1() {
        // -> e, es (starts unkeyed, no PSK)
        // e(65) + es(0,keys) + payload_tag(16) = 81
        const SIZE: usize = noise_message_size!(
            curve: P256,
            cipher: ChaChaPoly,
            has_psk: false,
            keyed: false,
            tokens: [E, Es],
        );
        assert_eq!(SIZE, 81);
    }

    #[test]
    fn macro_k_msg1() {
        // -> e, es, ss (starts unkeyed, no PSK)
        // e(65) + es(0,keys) + ss(0) + payload_tag(16) = 81
        const SIZE: usize = noise_message_size!(
            curve: P256,
            cipher: ChaChaPoly,
            has_psk: false,
            keyed: false,
            tokens: [E, Es, Ss],
        );
        assert_eq!(SIZE, 81);
    }

    #[test]
    fn macro_kpsk0_msg1() {
        // -> psk, e, es, ss (starts unkeyed, HAS_PSK = true)
        // psk(0,keys) + e(65) + es(0) + ss(0) + payload_tag(16) = 81
        const SIZE: usize = noise_message_size!(
            curve: P256,
            cipher: ChaChaPoly,
            has_psk: true,
            keyed: false,
            tokens: [Psk, E, Es, Ss],
        );
        assert_eq!(SIZE, 81);
    }

    #[test]
    fn macro_non_psk_e_s_unkeyed() {
        // Hypothetical: -> e, s (no PSK, no DH before S)
        // e(65) + s(65, plaintext because unkeyed) = 130
        // No payload tag — state is never keyed.
        const SIZE: usize = noise_message_size!(
            curve: P256,
            cipher: ChaChaPoly,
            has_psk: false,
            keyed: false,
            tokens: [E, S],
        );
        assert_eq!(SIZE, 130);
    }

    #[test]
    fn macro_dh_before_s_encrypts_s() {
        // -> e, es, s (no PSK, Es keys the state before S)
        // e(65) + es(0,keys) + s(65+16) + payload_tag(16) = 162
        const SIZE: usize = noise_message_size!(
            curve: P256,
            cipher: ChaChaPoly,
            has_psk: false,
            keyed: false,
            tokens: [E, Es, S],
        );
        assert_eq!(SIZE, 162);
    }

    #[test]
    fn macro_sizes_are_const() {
        // Prove that the macro output is usable as an array size.
        const MSG1: usize = noise_message_size!(
            curve: P256,
            cipher: ChaChaPoly,
            has_psk: true,
            keyed: false,
            tokens: [E, Es, S, Ss, Psk],
        );
        const MSG2: usize = noise_message_size!(
            curve: P256,
            cipher: ChaChaPoly,
            has_psk: true,
            keyed: true,
            tokens: [E, Ee, Se],
        );
        let _buf1: [u8; MSG1] = [0u8; 162];
        let _buf2: [u8; MSG2] = [0u8; 81];
    }

    #[test]
    fn macro_matches_wire_size_trait() {
        // Cross-check: macro output must match the WireSize trait computation
        // for every pattern we support.

        // IKpsk1 msg1 (WireSize: SIZE_UNKEYED + payload_tag)
        let trait_msg1 =
            <Msg1Tokens as WireSize<P256, ChaChaPoly, true>>::SIZE_UNKEYED + ChaChaPoly::TAG_SIZE; // payload tag (keyed after all tokens)
        const MACRO_MSG1: usize = noise_message_size!(
            curve: P256, cipher: ChaChaPoly, has_psk: true, keyed: false,
            tokens: [E, Es, S, Ss, Psk],
        );
        assert_eq!(MACRO_MSG1, trait_msg1);

        // IKpsk1 msg2 (WireSize: SIZE_KEYED + payload_tag)
        let trait_msg2 =
            <Msg2Tokens as WireSize<P256, ChaChaPoly, true>>::SIZE_KEYED + ChaChaPoly::TAG_SIZE;
        const MACRO_MSG2: usize = noise_message_size!(
            curve: P256, cipher: ChaChaPoly, has_psk: true, keyed: true,
            tokens: [E, Ee, Se],
        );
        assert_eq!(MACRO_MSG2, trait_msg2);
    }
}
