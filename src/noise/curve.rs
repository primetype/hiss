//! Re-exports the [`Curve`]/[`DhCurve`] traits and curve markers from
//! [`crate::curve`] for use in Noise protocol parameterisation.

pub use crate::curve::p256::P256;
pub use crate::curve::x25519::X25519;
pub use crate::curve::{Curve, DhCurve};
