//! Session identity — unique identifier for a Noise session.
//!
//! Every completed Noise handshake yields a [`SessionId`] derived from
//! the handshake hash. Both peers in the same session produce the same
//! identifier, so it can be compared out-of-band to confirm that no
//! man-in-the-middle is present.
//!
//! This type carries the raw identifier bytes only. Any human-facing
//! representation (verbal phrase, visual glyph, short authentication
//! string) is the responsibility of the consuming application.

use std::fmt;

/// Unique identifier for a Noise session, derived from the handshake hash.
///
/// Both peers in a completed handshake produce the same `SessionId`.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct SessionId(Box<[u8]>);

impl SessionId {
    /// The raw bytes of this session identifier.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for SessionId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for SessionId {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes.into_boxed_slice())
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(&self.0))
    }
}

impl fmt::Debug for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_through_bytes() {
        let bytes = vec![0xab, 0xcd, 0xef];
        let id = SessionId::from(bytes.clone());
        assert_eq!(id.as_bytes(), bytes.as_slice());
        assert_eq!(id.as_ref(), bytes.as_slice());
    }

    #[test]
    fn equal_ids_compare_equal() {
        let a = SessionId::from(vec![1, 2, 3, 4]);
        let b = SessionId::from(vec![1, 2, 3, 4]);
        let c = SessionId::from(vec![1, 2, 3, 5]);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn display_is_hex() {
        let id = SessionId::from(vec![0xab, 0xcd, 0xef]);
        assert_eq!(id.to_string(), "abcdef");
    }
}
