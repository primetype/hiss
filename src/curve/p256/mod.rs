//! P-256 (secp256r1) ECDSA signatures and ECDH key exchange.
//!
//! # Key types
//!
//! * [`P256r1PublicKey`] — 65-byte uncompressed SEC1 public key.
//!   Deserialises both uncompressed (`0x04`) and compressed
//!   (`0x02`/`0x03`) encodings; always stores uncompressed
//!   internally for consistency.
//!
//! * [`P256r1PrivateKey`] — 32-byte scalar (software backend,
//!   re-exported from [`software`]). See also
//!   [`apple::P256r1PrivateKey`] on macOS / iOS.
//!
//! * [`P256Signature`] — 64-byte raw `(r, s)` ECDSA signature.
//!   Can be converted to/from the ASN.1 DER encoding used by
//!   Apple's Security framework via [`P256Signature::try_from_asn1`].
//!
//! # ECDH
//!
//! Both software and Apple backends provide a `dh()` method that
//! returns a [`SharedSecret`](super::SharedSecret) — the raw
//! 32-byte x-coordinate of the shared ECDH point, as required by
//! the Noise protocol specification (`DHLEN = 32` for P-256).

#[cfg(any(target_os = "macos", target_os = "ios"))]
pub mod apple;
mod software;

use super::{Curve, SharedSecret};
#[cfg(any(target_os = "macos", target_os = "ios", test))]
use crate::asn1::ASN1Reader;
use cryptoxide::{digest::Digest as _, sha2::Sha256};
use eccoxide::curve::{
    Sign,
    sec2::p256r1::{FieldElement, Point, PointAffine, Scalar},
};
use packtool::Packed;
use std::fmt;

#[cfg(any(target_os = "macos", target_os = "ios"))]
pub use self::apple::SecureEnclaveCryptoProvider;
pub use self::software::{P256r1PrivateKey, SoftwareCryptoProvider};

// ── Curve marker ────────────────────────────────────────────────

/// NIST P-256 (secp256r1) curve marker.
///
/// Zero-sized type implementing [`Curve`] that ties together the
/// concrete [`P256r1PublicKey`], [`P256Signature`], and
/// [`SharedSecret`] types. Used as a type parameter for
/// [`Noise`](crate::noise::Noise) and
/// [`CryptoProvider`](super::CryptoProvider).
pub struct P256;

impl Curve for P256 {
    const NAME: &'static str = "P256";
    const DHLEN: usize = 32;
    const PUBLIC_KEY_SIZE: usize = 65;
    const PRIVATE_KEY_SIZE: usize = 32;

    type Error = Error;
    type PublicKey = P256r1PublicKey;
    type Signature = P256Signature;
    type SharedSecret = SharedSecret;

    fn public_key_from_bytes(bytes: &[u8]) -> Result<Self::PublicKey, Self::Error> {
        P256r1PublicKey::from_bytes(bytes)
    }
}

// ── Errors ──────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid field element")]
    InvalidFieldElement,
    #[error("invalid curve point")]
    InvalidPoint,
    #[error("invalid private key: must be a non-zero scalar less than the P-256 curve order")]
    InvalidPrivateKey,
    #[error("unknown point encoding prefix 0x{0:02x}")]
    UnknownPrefix(u8),
    #[error("invalid signature length")]
    InvalidSignatureLength,
    #[error("invalid ASN.1 encoded signature: {0}")]
    InvalidSignatureAsn1(String),
    #[error("RNG failure: {0}")]
    Rng(String),
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    #[error("{0}")]
    Platform(String),
}

// ── Public key ──────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct P256r1PublicKey([u8; 65]);

impl P256r1PublicKey {
    pub(self) fn from_point(point: Point) -> Self {
        Self(point_to_bytes(point))
    }

    pub fn to_point(&self) -> Result<Point, Error> {
        let prefix = self.0[0];
        let x = FieldElement::from_slice(&self.0[1..33]).ok_or(Error::InvalidFieldElement)?;

        let pa = match prefix {
            0x04 => {
                let y =
                    FieldElement::from_slice(&self.0[33..65]).ok_or(Error::InvalidFieldElement)?;
                PointAffine::from_coordinate(&x, &y).ok_or(Error::InvalidPoint)?
            }
            0x02 => PointAffine::decompress(&x, Sign::Positive).ok_or(Error::InvalidPoint)?,
            0x03 => PointAffine::decompress(&x, Sign::Negative).ok_or(Error::InvalidPoint)?,
            other => return Err(Error::UnknownPrefix(other)),
        };

        Ok(Point::from(pa))
    }

    pub fn to_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Return the 33-byte SEC1 compressed encoding of this public key.
    ///
    /// The prefix byte is `0x02` if the y-coordinate is even, `0x03`
    /// if odd.
    pub fn to_compressed(&self) -> [u8; 33] {
        let mut out = [0u8; 33];
        out[0] = if (self.0[64] & 1) == 0 { 0x02 } else { 0x03 };
        out[1..33].copy_from_slice(&self.0[1..33]);
        out
    }

    pub fn from_bytes(public_key: &[u8]) -> Result<Self, Error> {
        let prefix = public_key[0];
        let x = FieldElement::from_slice(&public_key[1..33]).ok_or(Error::InvalidFieldElement)?;

        let pa = match prefix {
            0x04 => {
                let y = FieldElement::from_slice(&public_key[33..65])
                    .ok_or(Error::InvalidFieldElement)?;
                PointAffine::from_coordinate(&x, &y).ok_or(Error::InvalidPoint)?
            }
            0x02 => PointAffine::decompress(&x, Sign::Positive).ok_or(Error::InvalidPoint)?,
            0x03 => PointAffine::decompress(&x, Sign::Negative).ok_or(Error::InvalidPoint)?,
            other => return Err(Error::UnknownPrefix(other)),
        };

        let point = Point::from(pa);
        Ok(Self(point_to_bytes(point)))
    }

    pub fn verify(&self, signature: P256Signature, message: impl AsRef<[u8]>) -> bool {
        let point = self
            .to_point()
            .expect("the P256 key should have been verified already");
        let e = input_to_scalar(message);

        let r = Scalar::from_slice(&signature.0[0..32]);
        let s = Scalar::from_slice(&signature.0[32..64]);
        let (Some(r), Some(s)) = (r, s) else {
            return false;
        };
        if r == Scalar::zero() || s == Scalar::zero() {
            return false;
        }

        let sinv = s.inverse();
        let u1 = &e * &sinv;
        let u2 = &r * sinv;
        let rp = &u1 * &Point::generator() + &u2 * &point;

        match rp.to_affine() {
            None => false,
            Some(rpa) => {
                let (xr, _) = rpa.to_coordinate();
                xr.to_bytes() == r.to_bytes()
            }
        }
    }
}

impl Packed for P256r1PublicKey {
    /// Packed as the 33-byte SEC1 compressed encoding.
    const SIZE: usize = 33;

    fn unchecked_read_from_slice(slice: &[u8]) -> Self {
        // from_bytes handles compressed (0x02/0x03) input and
        // decompresses to the internal 65-byte uncompressed form.
        Self::from_bytes(&slice[..33]).expect("Packed::check should have validated the key")
    }

    fn unchecked_write_to_slice(&self, slice: &mut [u8]) {
        slice[..33].copy_from_slice(&self.to_compressed());
    }

    fn check(slice: &[u8]) -> Result<(), packtool::Error> {
        let prefix = slice[0];
        if prefix != 0x02 && prefix != 0x03 {
            return Err(packtool::Error::invalid_field::<Self>("compressed_prefix"));
        }
        Self::from_bytes(&slice[..33])
            .map_err(|_| packtool::Error::invalid_field::<Self>("point"))?;
        Ok(())
    }
}

impl AsRef<[u8]> for P256r1PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for P256r1PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl fmt::Debug for P256r1PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

// ── Signature ───────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Packed)]
pub struct P256Signature(#[packed(accessor = false)] [u8; 64]);

impl P256Signature {
    pub fn try_from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self, Error> {
        let arr: [u8; 64] = bytes
            .as_ref()
            .try_into()
            .map_err(|_| Error::InvalidSignatureLength)?;
        Ok(Self(arr))
    }

    #[cfg(test)]
    pub(crate) fn to_asn1(self) -> Vec<u8> {
        let r = &self.0[0..32];
        let s = &self.0[32..64];

        let mut len = 68u8;

        let r = if (r[0] & 0x80) == 0x80 {
            len += 1;
            let mut r_ = vec![0];
            r_.extend_from_slice(r);
            r_
        } else {
            r.to_vec()
        };

        let s = if (s[0] & 0x80) == 0x80 {
            len += 1;
            let mut s_ = vec![0];
            s_.extend_from_slice(s);
            s_
        } else {
            s.to_vec()
        };

        let mut writer = crate::asn1::ASN1Writer::new();
        writer.sequence(len);
        writer.integer(r.as_slice());
        writer.integer(s.as_slice());
        writer.finalize()
    }

    #[cfg(any(target_os = "macos", target_os = "ios", test))]
    pub(crate) fn try_from_asn1(bytes: impl AsRef<[u8]>) -> Result<Self, Error> {
        let reader = ASN1Reader::new(bytes.as_ref());
        let reader = reader.sequence().map_err(asn1_err)?;
        let (reader, r) = reader.integer().map_err(asn1_err)?;
        let (reader, s) = reader.integer().map_err(asn1_err)?;

        if !(r.len() <= 32 || (r.len() == 33 && r[0] == 0)) {
            return Err(Error::InvalidSignatureAsn1(format!(
                "r: expected length of 32 or 33 (got {}), first byte 0x{:02x}",
                r.len(),
                r[0]
            )));
        }
        if !(s.len() <= 32 || (s.len() == 33 && s[0] == 0)) {
            return Err(Error::InvalidSignatureAsn1(format!(
                "s: expected length of 32 or 33 (got {}), first byte 0x{:02x}",
                s.len(),
                s[0]
            )));
        }
        if !reader.is_empty() {
            return Err(Error::InvalidSignatureAsn1("trailing data".to_string()));
        }

        let r = if r.len() == 33 { &r[1..] } else { r };
        let s = if s.len() == 33 { &s[1..] } else { s };
        let r_i = if r.len() < 32 { 32 - r.len() } else { 0 };
        let s_i = if s.len() < 32 { 32 - s.len() } else { 0 };
        let mut signature = [0; 64];
        signature[r_i..32].copy_from_slice(r);
        signature[32 + s_i..].copy_from_slice(s);

        Ok(P256Signature(signature))
    }
}

impl AsRef<[u8]> for P256Signature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for P256Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

// ── Helpers ─────────────────────────────────────────────────────

fn point_to_bytes(point: Point) -> [u8; 65] {
    let point = point.to_affine().unwrap();
    let (x, y) = point.to_coordinate();

    let mut pk = [0; 65];
    pk[0] = 0x04;
    pk[1..33].copy_from_slice(&x.to_bytes());
    pk[33..].copy_from_slice(&y.to_bytes());
    pk
}

pub(crate) fn input_to_scalar(message: impl AsRef<[u8]>) -> Scalar {
    let mut hash = [0u8; 32];
    let mut context = Sha256::new();
    context.input(message.as_ref());
    context.result(&mut hash);
    reduce_be_mod_order(&hash)
}

/// Reduce a 32-byte big-endian integer modulo the curve order `n`,
/// producing a scalar. Never fails.
///
/// `Scalar::from_slice` returns `None` for values `>= n` (it requires a
/// canonical encoding), so calling it on an arbitrary digest panics for
/// the ~2^-32 of values that land in `[n, 2^256)`. Standard ECDSA
/// reduces the digest modulo `n` instead. We do that by splitting the
/// input into two 128-bit halves — each is `< 2^128 < n`, so each parses
/// without rejection — and recombining with scalar arithmetic, which is
/// itself performed modulo `n`:  `value = hi * 2^128 + lo  (mod n)`.
fn reduce_be_mod_order(bytes: &[u8; 32]) -> Scalar {
    let mut hi_buf = [0u8; 32];
    let mut lo_buf = [0u8; 32];
    hi_buf[16..].copy_from_slice(&bytes[..16]);
    lo_buf[16..].copy_from_slice(&bytes[16..]);
    let hi = Scalar::from_slice(&hi_buf).expect("128-bit value is < n");
    let lo = Scalar::from_slice(&lo_buf).expect("128-bit value is < n");

    // 2^128 reduced into the scalar field (2^128 < n, so this is exact).
    let mut two_pow_128 = [0u8; 32];
    two_pow_128[15] = 0x01;
    let two_pow_128 = Scalar::from_slice(&two_pow_128).expect("2^128 is < n");

    (&hi * &two_pow_128) + &lo
}

#[cfg(any(target_os = "macos", target_os = "ios", test))]
fn asn1_err(e: crate::asn1::Asn1Error) -> Error {
    Error::InvalidSignatureAsn1(e.to_string())
}

// ── Tests ───────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

    /// Public key and signature generated on iPhone 12 Pro, iOS 16,
    /// Secure Enclave using `.ecdsaSignatureMessageX962SHA256`.
    const PKSTR: &str =
        "BNe8CwkfEsB2m5peB0PQINtep4xMuJvH6zFbkkBgBlwpJ8pQSGFe00s6Of3m7lOCbGEJuo7W8cYEK_kgQx8dPUs";
    const SIGSTR: &str = "MEUCIQCdH-6x6xmFGJ-Py9Qn4a_JGGMMCri6QosXDVYygka_LQIgUTbBhT_kuuzJmBZa9uXofcwIc7WVWDcJBnx9cP07G0o";

    #[test]
    fn pk_from_to_bytes() {
        let pkbytes = URL_SAFE_NO_PAD.decode(PKSTR).unwrap();
        let pk = P256r1PublicKey::from_bytes(&pkbytes).unwrap();
        assert_eq!(pk.to_bytes(), pkbytes);
    }

    #[test]
    fn signature_decode_31() {
        let bytes = hex::decode(
            "3044022100e84c694ba8e5864f152db261091dac062a20358100234ad1c98643b4fee02ff0\
             021f7fdb70746a4c610a78831472493cfc4643597741929c43703dabaa78c3ad26",
        )
        .unwrap();
        let _sig = P256Signature::try_from_asn1(bytes).unwrap();
    }

    #[test]
    fn signature_asn1_encode_decode() {
        let sigbytes = URL_SAFE_NO_PAD.decode(SIGSTR).unwrap();

        let sig = P256Signature::try_from_asn1(&sigbytes).unwrap();
        let encoded = sig.to_asn1();

        assert_eq!(sigbytes, encoded);
    }

    #[test]
    fn check_sig_verification() {
        const MSG: &str = "Hello World!";
        let pkbytes = URL_SAFE_NO_PAD.decode(PKSTR).unwrap();
        let sigbytes = URL_SAFE_NO_PAD.decode(SIGSTR).unwrap();
        let pk = P256r1PublicKey::from_bytes(&pkbytes).unwrap();
        let signature = P256Signature::try_from_asn1(sigbytes).unwrap();

        assert!(pk.verify(signature, MSG.as_bytes()));
    }

    // ── Public key negative tests ─────────────────────────────────

    #[test]
    fn pk_from_bytes_wrong_prefix() {
        let mut bytes = [0u8; 65];
        bytes[0] = 0x05; // invalid prefix (not 0x02, 0x03, or 0x04)
        let err = P256r1PublicKey::from_bytes(&bytes).unwrap_err();
        assert!(matches!(err, Error::UnknownPrefix(0x05)));
    }

    #[test]
    fn pk_from_bytes_all_zeros_rejected() {
        // 0x04 prefix with zero coordinates — not a valid curve point.
        let mut key = [0u8; 65];
        key[0] = 0x04;
        let err = P256r1PublicKey::from_bytes(&key).unwrap_err();
        assert!(matches!(err, Error::InvalidPoint));
    }

    #[test]
    fn pk_from_bytes_compressed_02() {
        // Generate a valid key pair and re-encode as compressed 0x02.
        let sk = software::P256r1PrivateKey::generate().unwrap();
        let pk = sk.public();
        let uncompressed = pk.to_bytes();

        // Extract x-coordinate and determine y parity.
        let x = &uncompressed[1..33];
        let y = &uncompressed[33..65];
        let y_is_even = (y[31] & 1) == 0;

        let mut compressed = [0u8; 33];
        compressed[0] = if y_is_even { 0x02 } else { 0x03 };
        compressed[1..33].copy_from_slice(x);

        // Decompression should succeed and produce the same public key.
        let pk2 = P256r1PublicKey::from_bytes(&compressed).unwrap();
        assert_eq!(pk, pk2);
    }

    #[test]
    fn to_compressed_round_trips() {
        let sk = software::P256r1PrivateKey::generate().unwrap();
        let pk = sk.public();
        let compressed = pk.to_compressed();

        // Compressed encoding should decompresses back to the same key.
        let pk2 = P256r1PublicKey::from_bytes(&compressed).unwrap();
        assert_eq!(pk, pk2);

        // Prefix must be 0x02 or 0x03.
        assert!(compressed[0] == 0x02 || compressed[0] == 0x03);

        // X-coordinate must match.
        assert_eq!(&compressed[1..33], &pk.to_bytes()[1..33]);
    }

    // ── Signature negative tests ──────────────────────────────────

    #[test]
    fn signature_wrong_length_rejected() {
        let err = P256Signature::try_from_bytes([0u8; 63].as_ref()).unwrap_err();
        assert!(matches!(err, Error::InvalidSignatureLength));

        let err = P256Signature::try_from_bytes([0u8; 65].as_ref()).unwrap_err();
        assert!(matches!(err, Error::InvalidSignatureLength));
    }

    #[test]
    fn verify_wrong_message_fails() {
        let sk = software::P256r1PrivateKey::generate().unwrap();
        let pk = sk.public();
        let sig = sk.sign(b"correct message").unwrap();

        assert!(!pk.verify(sig, b"wrong message"));
    }

    #[test]
    fn verify_wrong_key_fails() {
        let sk1 = software::P256r1PrivateKey::generate().unwrap();
        let sk2 = software::P256r1PrivateKey::generate().unwrap();
        let pk2 = sk2.public();

        let sig = sk1.sign(b"signed by sk1").unwrap();
        assert!(!pk2.verify(sig, b"signed by sk1"));
    }

    #[test]
    fn verify_corrupted_signature_fails() {
        let sk = software::P256r1PrivateKey::generate().unwrap();
        let pk = sk.public();
        let sig = sk.sign(b"test").unwrap();

        // Corrupt one byte of the signature.
        let mut raw = [0u8; 64];
        raw.copy_from_slice(sig.as_ref());
        raw[16] ^= 0xFF;
        let corrupted = P256Signature::try_from_bytes(raw).unwrap();

        assert!(!pk.verify(corrupted, b"test"));
    }

    #[test]
    fn verify_zero_signature_fails() {
        let sk = software::P256r1PrivateKey::generate().unwrap();
        let pk = sk.public();

        let zero_sig = P256Signature::try_from_bytes([0u8; 64]).unwrap();
        assert!(!pk.verify(zero_sig, b"anything"));
    }

    // ── ECDH negative tests ───────────────────────────────────────

    #[test]
    fn dh_different_peers_produce_different_secrets() {
        let sk = software::P256r1PrivateKey::generate().unwrap();
        let peer1 = software::P256r1PrivateKey::generate().unwrap().public();
        let peer2 = software::P256r1PrivateKey::generate().unwrap().public();

        let ss1 = sk.dh(&peer1);
        let ss2 = sk.dh(&peer2);
        assert_ne!(ss1, ss2);
    }

    #[test]
    fn dh_is_not_commutative_with_different_keys() {
        // dh(sk1, pk2) == dh(sk2, pk1) — ECDH symmetry.
        let sk1 = software::P256r1PrivateKey::generate().unwrap();
        let pk1 = sk1.public();
        let sk2 = software::P256r1PrivateKey::generate().unwrap();
        let pk2 = sk2.public();

        let ss1 = sk1.dh(&pk2);
        let ss2 = sk2.dh(&pk1);
        assert_eq!(ss1, ss2);

        // But dh(sk1, pk1) != dh(sk1, pk2) — different peers.
        let ss_self = sk1.dh(&pk1);
        assert_ne!(ss_self, ss1);
    }

    // ── Modular reduction (H2) ────────────────────────────────────

    /// The P-256 curve order `n`, big-endian.
    const N_BYTES: [u8; 32] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63,
        0x25, 0x51,
    ];

    fn scalar_bytes(bytes: [u8; 32]) -> [u8; 32] {
        Scalar::from_slice(&bytes).expect("canonical scalar").to_bytes()
    }

    #[test]
    fn reduce_is_identity_below_order() {
        // A value < n is returned unchanged.
        let mut v = [0u8; 32];
        v[31] = 5;
        assert_eq!(reduce_be_mod_order(&v).to_bytes(), scalar_bytes(v));
    }

    #[test]
    fn reduce_order_maps_to_zero() {
        // n mod n == 0. n is >= n, so the old `from_slice(..).unwrap()`
        // would have panicked on this input.
        assert_eq!(reduce_be_mod_order(&N_BYTES).to_bytes(), Scalar::zero().to_bytes());
    }

    #[test]
    fn reduce_order_plus_one_maps_to_one() {
        // (n + 1) mod n == 1 — another value that previously panicked.
        let mut n_plus_1 = N_BYTES;
        n_plus_1[31] = 0x52; // 0x51 + 1, no carry
        let mut one = [0u8; 32];
        one[31] = 1;
        assert_eq!(reduce_be_mod_order(&n_plus_1).to_bytes(), scalar_bytes(one));
    }

    #[test]
    fn reduce_max_value_does_not_panic() {
        // 0xFF..FF (= 2^256 - 1) is >= n; it must reduce, not panic.
        let reduced = reduce_be_mod_order(&[0xFF; 32]).to_bytes();
        // 2^256 - 1 is in [n, 2n), so the result is non-zero and < n.
        assert_ne!(reduced, Scalar::zero().to_bytes());
    }
}
