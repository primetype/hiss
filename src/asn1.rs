//! Minimal ASN.1 DER codec.
//!
//! Only the subset needed to decode (and, in tests, encode) ECDSA
//! signatures in the X9.62 / DER format returned by Apple's
//! Security framework:
//!
//! ```text
//! SEQUENCE {
//!   INTEGER r,
//!   INTEGER s
//! }
//! ```
//!
//! [`ASN1Reader`] walks a byte slice non-destructively.
//! [`ASN1Writer`] (test-only) builds a DER blob from scratch.

#[derive(Debug, thiserror::Error)]
pub enum Asn1Error {
    #[error("unexpected end of data")]
    UnexpectedEnd,
    #[error("expected tag 0x{expected:02x}, found 0x{found:02x}")]
    UnexpectedTag { expected: u8, found: u8 },
    #[error("data truncated")]
    Truncated,
    #[error("trailing data after structure")]
    #[allow(dead_code)]
    TrailingData,
    #[error("value too large: {0} bytes")]
    #[allow(dead_code)]
    TooLarge(usize),
}

#[cfg(test)]
#[derive(Debug, Clone, Default)]
pub struct ASN1Writer(Vec<u8>);

#[derive(Debug, Clone, Copy)]
pub struct ASN1Reader<'a>(&'a [u8]);

#[cfg(test)]
impl ASN1Writer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn sequence(&mut self, len: u8) {
        self.0.push(0x30u8);
        self.0.push(len);
    }

    pub fn integer(&mut self, integer: &[u8]) {
        assert!(
            integer.len() < (u8::MAX as usize),
            "integer too large: {} bytes",
            integer.len()
        );
        self.0.push(0x02u8);
        self.0.push(integer.len() as u8);
        self.0.extend_from_slice(integer);
    }

    pub fn finalize(self) -> Vec<u8> {
        self.0
    }
}

impl<'a> ASN1Reader<'a> {
    #[inline]
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self(bytes)
    }

    fn not_empty(self) -> Result<Self, Asn1Error> {
        if self.0.is_empty() {
            return Err(Asn1Error::UnexpectedEnd);
        }
        Ok(self)
    }

    #[inline(always)]
    pub fn is_empty(self) -> bool {
        self.0.is_empty()
    }

    pub fn sequence(self) -> Result<Self, Asn1Error> {
        let this = self.not_empty()?;
        if this.0[0] != 0x30 {
            return Err(Asn1Error::UnexpectedTag {
                expected: 0x30,
                found: this.0[0],
            });
        }
        if this.0.len() < 2 {
            return Err(Asn1Error::Truncated);
        }
        let remaining_length = this.0[1] as usize;
        let remaining = &this.0[2..];
        if remaining.len() < remaining_length {
            return Err(Asn1Error::Truncated);
        }
        Ok(Self(remaining))
    }

    pub fn integer(self) -> Result<(Self, &'a [u8]), Asn1Error> {
        let this = self.not_empty()?;
        if this.0[0] != 0x02 {
            return Err(Asn1Error::UnexpectedTag {
                expected: 0x02,
                found: this.0[0],
            });
        }
        if this.0.len() < 2 {
            return Err(Asn1Error::Truncated);
        }
        let integer_length = this.0[1] as usize;
        if this.0.len() < 2 + integer_length {
            return Err(Asn1Error::Truncated);
        }
        let integer = &this.0[2..(2 + integer_length)];
        let remaining = &this.0[(2 + integer_length)..];
        Ok((Self(remaining), integer))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENCODED: &[u8] = &[
        48, 69, 2, 32, 17, 228, 99, 34, 120, 37, 69, 116, 229, 142, 174, 166, 66, 182, 115, 165,
        236, 153, 178, 59, 233, 223, 255, 125, 25, 93, 206, 45, 220, 10, 53, 97, 2, 33, 0, 241, 1,
        246, 203, 223, 101, 49, 70, 12, 167, 176, 90, 118, 217, 115, 61, 23, 200, 214, 81, 204, 74,
        219, 44, 58, 232, 125, 187, 1, 202, 203, 185,
    ];

    const R: &[u8] = &[
        17, 228, 99, 34, 120, 37, 69, 116, 229, 142, 174, 166, 66, 182, 115, 165, 236, 153, 178,
        59, 233, 223, 255, 125, 25, 93, 206, 45, 220, 10, 53, 97,
    ];

    const S: &[u8] = &[
        0, 241, 1, 246, 203, 223, 101, 49, 70, 12, 167, 176, 90, 118, 217, 115, 61, 23, 200, 214,
        81, 204, 74, 219, 44, 58, 232, 125, 187, 1, 202, 203, 185,
    ];

    #[test]
    fn encode_signature() {
        let mut writer = ASN1Writer::new();
        writer.sequence(69);
        writer.integer(R);
        writer.integer(S);

        assert_eq!(ENCODED, writer.0.as_slice());
    }

    #[test]
    fn decode_signature() {
        let reader = ASN1Reader(ENCODED);
        let reader = reader.sequence().unwrap();
        let (reader, r) = reader.integer().unwrap();
        let (reader, s) = reader.integer().unwrap();

        assert!(reader.is_empty());
        assert_eq!(r, R);
        assert_eq!(s, S);
    }
}
