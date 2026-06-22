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
//! `ASN1Writer` (test-only) builds a DER blob from scratch.

/// An error raised while decoding (or, in tests, encoding) DER.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Asn1Error {
    /// The reader was empty where a tag–length–value triple was expected.
    #[error("unexpected end of data")]
    UnexpectedEnd,
    /// The tag octet at the cursor did not match the expected universal tag
    /// (`0x30` for SEQUENCE, `0x02` for INTEGER).
    #[error("expected tag 0x{expected:02x}, found 0x{found:02x}")]
    UnexpectedTag {
        /// The tag octet the reader required.
        expected: u8,
        /// The tag octet actually found at the cursor.
        found: u8,
    },
    /// The declared length runs past the end of the buffer, or a length
    /// octet was absent — i.e. the encoding is shorter than it claims. Also
    /// raised for an INTEGER with a zero-length content field.
    #[error("data truncated")]
    Truncated,
    /// Bytes remain after the SEQUENCE that was expected to span the whole
    /// input; a standalone signature must consume the buffer exactly.
    #[error("trailing data after structure")]
    TrailingData,
    /// The length used the long form (`0x81…`) or indefinite form (`0x80`)
    /// where the short form is mandatory — always non-minimal for the
    /// sub-128-byte structures this codec decodes.
    #[error("non-minimal length encoding (long-form or indefinite length)")]
    NonMinimalLength,
    /// An INTEGER carried a superfluous leading `0x00` or `0xff` octet not
    /// required to encode the sign bit (X.690 §8.3.2).
    #[error("non-minimal integer encoding (superfluous leading 0x00/0xff)")]
    NonMinimalInteger,
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

    /// Enter a SEQUENCE that spans the **entire** remaining input.
    ///
    /// Strict DER for the one structure this codec decodes — a standalone
    /// ECDSA signature — so:
    ///
    /// * the length must use the definite **short form** (a P-256
    ///   signature's SEQUENCE body is far below the 128-byte short-form
    ///   ceiling, so a long-form `0x81…` or indefinite `0x80` length is
    ///   always a non-minimal/illegal encoding here → [`Asn1Error::NonMinimalLength`]);
    /// * the body must be exactly the rest of the input — a length that
    ///   overruns the buffer is [`Asn1Error::Truncated`], one that leaves
    ///   bytes after the SEQUENCE is [`Asn1Error::TrailingData`].
    ///
    /// The returned reader is therefore bounded to the SEQUENCE body.
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
        if this.0[1] >= 0x80 {
            return Err(Asn1Error::NonMinimalLength);
        }
        let length = this.0[1] as usize;
        let body = &this.0[2..];
        if body.len() < length {
            return Err(Asn1Error::Truncated);
        }
        if body.len() > length {
            return Err(Asn1Error::TrailingData);
        }
        Ok(Self(body))
    }

    /// Read one DER INTEGER from the front, returning the remaining reader
    /// and the integer's **content** octets.
    ///
    /// Strict DER: the length must use the definite **short form**
    /// (P-256 `r`/`s` are at most 33 content octets → [`Asn1Error::NonMinimalLength`]
    /// otherwise), there must be at least one content octet, and the
    /// encoding must be **minimal** — a leading `0x00` (or `0xff`) that is
    /// not required to carry the sign bit is rejected with
    /// [`Asn1Error::NonMinimalInteger`] (X.690 §8.3.2). The sign and range
    /// of the value itself are the caller's concern.
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
        if this.0[1] >= 0x80 {
            return Err(Asn1Error::NonMinimalLength);
        }
        let length = this.0[1] as usize;
        if length == 0 {
            return Err(Asn1Error::Truncated);
        }
        if this.0.len() < 2 + length {
            return Err(Asn1Error::Truncated);
        }
        let integer = &this.0[2..(2 + length)];
        // X.690 §8.3.2: with more than one content octet, the first octet
        // and bit 8 of the second must not be all-zero (superfluous
        // leading 0x00) nor all-one (superfluous leading 0xff).
        if length >= 2 {
            let superfluous_zero = integer[0] == 0x00 && (integer[1] & 0x80) == 0;
            let superfluous_ones = integer[0] == 0xff && (integer[1] & 0x80) != 0;
            if superfluous_zero || superfluous_ones {
                return Err(Asn1Error::NonMinimalInteger);
            }
        }
        let remaining = &this.0[(2 + length)..];
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

    #[test]
    fn sequence_rejects_long_form_length() {
        // 0x81 == long-form length; never minimal for a sub-128-byte body.
        let der = &[0x30, 0x81, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02];
        assert!(matches!(
            ASN1Reader::new(der).sequence(),
            Err(Asn1Error::NonMinimalLength)
        ));
    }

    #[test]
    fn sequence_rejects_trailing_data() {
        // Body is one byte longer than the declared length.
        let der = &[0x30, 0x03, 0x02, 0x01, 0x01, 0xff];
        assert!(matches!(
            ASN1Reader::new(der).sequence(),
            Err(Asn1Error::TrailingData)
        ));
    }

    #[test]
    fn sequence_rejects_truncated_body() {
        let der = &[0x30, 0x05, 0x02, 0x01, 0x01];
        assert!(matches!(
            ASN1Reader::new(der).sequence(),
            Err(Asn1Error::Truncated)
        ));
    }

    #[test]
    fn integer_rejects_long_form_length() {
        assert!(matches!(
            ASN1Reader::new(&[0x02, 0x81, 0x01, 0x01]).integer(),
            Err(Asn1Error::NonMinimalLength)
        ));
    }

    #[test]
    fn integer_rejects_empty_content() {
        assert!(matches!(
            ASN1Reader::new(&[0x02, 0x00]).integer(),
            Err(Asn1Error::Truncated)
        ));
    }

    #[test]
    fn integer_rejects_superfluous_leading_zero() {
        // 0x00 0x01: the 0x00 is not needed for the sign bit.
        assert!(matches!(
            ASN1Reader::new(&[0x02, 0x02, 0x00, 0x01]).integer(),
            Err(Asn1Error::NonMinimalInteger)
        ));
    }

    #[test]
    fn integer_rejects_superfluous_leading_ones() {
        // 0xff 0x80: non-minimal negative encoding.
        assert!(matches!(
            ASN1Reader::new(&[0x02, 0x02, 0xff, 0x80]).integer(),
            Err(Asn1Error::NonMinimalInteger)
        ));
    }

    #[test]
    fn integer_accepts_required_sign_byte() {
        // 0x00 0x80: the leading 0x00 IS required (0x80 has its top bit
        // set), so this is the minimal encoding of a positive value.
        let (reader, content) = ASN1Reader::new(&[0x02, 0x02, 0x00, 0x80])
            .integer()
            .unwrap();
        assert!(reader.is_empty());
        assert_eq!(content, &[0x00, 0x80]);
    }
}
