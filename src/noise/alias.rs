//! Ready-made protocol aliases for the default suite.
//!
//! Each alias fixes the curve, cipher, and hash to the crate's default
//! suite — **P-256 / ChaCha20-Poly1305 / BLAKE2b** — and is named after
//! its handshake pattern. Reached through the [`noise`](crate::noise)
//! namespace they read cleanly, with no `Noise` stutter:
//! `noise::IKpsk1::sync_initiator(…)`.
//!
//! The building-block **pattern markers** live one level down, in
//! [`noise::pattern`](super::pattern) — so `noise::IKpsk1` is the
//! ready-to-use protocol and `noise::pattern::IKpsk1` is the marker.
//! A non-default suite names the full [`Noise<P, Cu, Ci, H>`](super::Noise)
//! with a `pattern::` marker.
//!
//! ```
//! use hiss::noise;
//!
//! type _Channel = noise::IKpsk1;          // ready-made default-suite protocol
//! type _Marker = noise::pattern::IKpsk1;  // the building-block pattern marker
//! ```
//!
//! [`Noise::sync_initiator`]: super::Noise::sync_initiator
//! [`Noise::sync_responder`]: super::Noise::sync_responder

use super::pattern;
use super::{Blake2b, ChaChaPoly, Noise, P256};

/// `Noise_N_P256_ChaChaPoly_BLAKE2b` — one-way seal to a known recipient.
pub type N = Noise<pattern::N, P256, ChaChaPoly, Blake2b>;

/// `Noise_K_P256_ChaChaPoly_BLAKE2b` — one-way, sender-authenticated.
pub type K = Noise<pattern::K, P256, ChaChaPoly, Blake2b>;

/// `Noise_Kpsk0_P256_ChaChaPoly_BLAKE2b` — `K` with a pre-shared key.
pub type Kpsk0 = Noise<pattern::Kpsk0, P256, ChaChaPoly, Blake2b>;

/// `Noise_IKpsk1_P256_ChaChaPoly_BLAKE2b` — interactive mutual
/// authentication with a pre-shared key.
pub type IKpsk1 = Noise<pattern::IKpsk1, P256, ChaChaPoly, Blake2b>;

/// `Noise_IK_P256_ChaChaPoly_BLAKE2b` — interactive mutual
/// authentication (no pre-shared key).
pub type IK = Noise<pattern::IK, P256, ChaChaPoly, Blake2b>;

/// `Noise_NK_P256_ChaChaPoly_BLAKE2b` — interactive,
/// responder-authenticated handshake with an anonymous initiator.
pub type NK = Noise<pattern::NK, P256, ChaChaPoly, Blake2b>;

/// `Noise_IX_P256_ChaChaPoly_BLAKE2b` — interactive mutual
/// authentication with no pre-messages; both statics are exchanged
/// during the handshake (the initiator's in the clear).
pub type IX = Noise<pattern::IX, P256, ChaChaPoly, Blake2b>;

/// `Noise_XK_P256_ChaChaPoly_BLAKE2b` — interactive, three-message
/// mutual authentication with strong initiator-identity privacy; the
/// responder's static is pre-known and the initiator's static is sent
/// encrypted in msg3.
pub type XK = Noise<pattern::XK, P256, ChaChaPoly, Blake2b>;

/// `Noise_NN_P256_ChaChaPoly_BLAKE2b` — interactive, **unauthenticated**
/// handshake: both parties are anonymous (no static keys). Confidentiality
/// holds only against a passive eavesdropper; full forward secrecy after `ee`.
pub type NN = Noise<pattern::NN, P256, ChaChaPoly, Blake2b>;

/// `Noise_XX_P256_ChaChaPoly_BLAKE2b` — the canonical interactive,
/// three-message mutual authentication with no pre-messages; both
/// statics are exchanged during the handshake, **encrypted**, so both
/// identities are hidden from a passive eavesdropper. Full forward
/// secrecy after `ee`.
pub type XX = Noise<pattern::XX, P256, ChaChaPoly, Blake2b>;
