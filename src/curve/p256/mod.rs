//! P-256 (secp256r1) ECDSA signatures and ECDH key exchange.
//!
//! # Key types
//!
//! * [`P256r1PublicKey`] — 65-byte uncompressed SEC1 public key.
//!   Deserialises both uncompressed (`0x04`) and compressed
//!   (`0x02`/`0x03`) encodings; always stores uncompressed
//!   internally for consistency.
//!
//! * [`P256r1PrivateKey`] — 32-byte scalar (software backend). The
//!   hardware-backed Secure Enclave key lives in
//!   [`crate::provider::apple`] on macOS / iOS.
//!
//! * [`P256Signature`] — 64-byte raw `(r, s)` ECDSA signature.
//!   Converts to/from the ASN.1 DER encoding used by Apple's Security
//!   framework.
//!
//! # ECDH
//!
//! Both software and Apple backends provide a `dh()` method that
//! returns a [`SharedSecret`] — the raw
//! 32-byte x-coordinate of the shared ECDH point, as required by
//! the Noise protocol specification (`DHLEN = 32` for P-256).

mod software;

#[cfg(test)]
mod wycheproof;

use super::{Curve, DhCurve, SharedSecret, SigningCurve};
#[cfg(any(target_os = "macos", target_os = "ios", test))]
use crate::asn1::ASN1Reader;
use cryptoxide::{digest::Digest as _, sha2::Sha256};
use eccoxide::curve::{
    Sign,
    sec2::p256r1::{FieldElement, Point, PointAffine, Scalar},
};
use packtool::Packed;
use std::fmt;

pub use self::software::P256r1PrivateKey;

/// Re-exported so it can surface as the [`source`](std::error::Error::source)
/// of [`Error::InvalidSignatureEncoding`] (strict-DER signature decoding).
pub use crate::asn1::Asn1Error;

// ── Curve marker ────────────────────────────────────────────────

/// NIST P-256 (secp256r1) curve marker.
///
/// Zero-sized type implementing [`Curve`] that ties together the
/// concrete [`P256r1PublicKey`], [`P256Signature`], and
/// [`SharedSecret`] types. Used as a type parameter for
/// [`Noise`](crate::noise::Noise) and
/// [`DhProviderAsync`](crate::provider::DhProviderAsync).
pub struct P256;

impl Curve for P256 {
    const NAME: &'static str = "P256";
    const PUBLIC_KEY_SIZE: usize = 65;
    const PRIVATE_KEY_SIZE: usize = 32;

    type Error = Error;
    type PublicKey = P256r1PublicKey;

    fn public_key_from_bytes(bytes: &[u8]) -> Result<Self::PublicKey, Self::Error> {
        P256r1PublicKey::from_bytes(bytes)
    }
}

impl DhCurve for P256 {
    const DHLEN: usize = 32;
    type SharedSecret = SharedSecret;
}

impl SigningCurve for P256 {
    type Signature = P256Signature;
}

// ── Errors ──────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("invalid field element")]
    InvalidFieldElement,
    #[error("invalid curve point")]
    InvalidPoint,
    #[error("ECDH produced a degenerate shared secret (identity or low-order peer key)")]
    InvalidSharedSecret,
    #[error("invalid private key: must be a non-zero scalar less than the P-256 curve order")]
    InvalidPrivateKey,
    #[error("unknown point encoding prefix 0x{0:02x}")]
    UnknownPrefix(u8),
    #[error("invalid public key length")]
    InvalidPublicKeyLength,
    #[error("invalid signature length")]
    InvalidSignatureLength,
    /// The signature's ASN.1/DER structure is invalid (strict DER).
    #[error(transparent)]
    InvalidSignatureEncoding(#[from] crate::asn1::Asn1Error),
    /// A signature component (`r` or `s`) is not a canonical 32-byte
    /// P-256 scalar (too long, or 33 bytes without a leading `0x00`).
    #[error("ECDSA signature component is not a canonical 32-byte P-256 scalar")]
    SignatureComponentTooLarge,
    /// A signature component (`r` or `s`) encodes a negative integer.
    #[error("ECDSA signature component is a negative integer")]
    SignatureComponentNegative,
    #[error("the RNG repeatedly failed to produce a valid P-256 scalar")]
    ScalarSamplingFailed,
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
        // Validate length against the encoding before indexing, so
        // truncated/empty input yields an error rather than a panic.
        let prefix = *public_key.first().ok_or(Error::InvalidPublicKeyLength)?;
        let expected = match prefix {
            0x04 => 65,
            0x02 | 0x03 => 33,
            other => return Err(Error::UnknownPrefix(other)),
        };
        if public_key.len() < expected {
            return Err(Error::InvalidPublicKeyLength);
        }

        let x = FieldElement::from_slice(&public_key[1..33]).ok_or(Error::InvalidFieldElement)?;

        let pa = match prefix {
            0x04 => {
                let y = FieldElement::from_slice(&public_key[33..65])
                    .ok_or(Error::InvalidFieldElement)?;
                PointAffine::from_coordinate(&x, &y).ok_or(Error::InvalidPoint)?
            }
            0x02 => PointAffine::decompress(&x, Sign::Positive).ok_or(Error::InvalidPoint)?,
            0x03 => PointAffine::decompress(&x, Sign::Negative).ok_or(Error::InvalidPoint)?,
            _ => unreachable!("prefix already validated above"),
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
        // u1·G + u2·Q. Variable-time multiplication is safe and faster on the
        // verify path: every input (signature, message hash, public key) is public.
        let rp = Point::generator().mul_vartime(&u1) + point.mul_vartime(&u2);

        match rp.to_affine() {
            None => false,
            Some(rpa) => {
                let (xr, _) = rpa.to_coordinate();
                // Compare `r` to x(R) reduced mod n. The affine x is a field
                // element in [0, p); since p > n for P-256, the reduction
                // matters for the rare x in [n, p) and mirrors how signing
                // derives `r`.
                reduce_be_mod_order(&xr.to_bytes()) == r
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
        let reader = reader.sequence()?;
        let (reader, r) = reader.integer()?;
        let (reader, s) = reader.integer()?;

        if !(r.len() <= 32 || (r.len() == 33 && r[0] == 0)) {
            return Err(Error::SignatureComponentTooLarge);
        }
        if !(s.len() <= 32 || (s.len() == 33 && s[0] == 0)) {
            return Err(Error::SignatureComponentTooLarge);
        }
        // ECDSA `r`/`s` are positive. Minimal DER (enforced by the reader)
        // encodes a positive value whose top bit is set with a leading
        // 0x00 sign byte, so any content whose first byte has the high bit
        // set is a negative integer and must be rejected.
        if r[0] & 0x80 != 0 || s[0] & 0x80 != 0 {
            return Err(Error::SignatureComponentNegative);
        }
        if !reader.is_empty() {
            return Err(Asn1Error::TrailingData.into());
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
    // Internal invariant: only ever called on points produced by `d·G`
    // (d ∈ [1, n-1]) or by lifting an already-validated, on-curve affine
    // peer key — never the identity, so `to_affine` always succeeds.
    let point = point
        .to_affine()
        .expect("internal point is never the identity (d·G or validated on-curve parse)");
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

// ── ECDSA signing (RFC 6979 deterministic nonces) ───────────────

/// Half the curve order, ⌊n/2⌋ = (n − 1) / 2, big-endian. A signature
/// component `s` greater than this is "high"; low-S normalization replaces
/// it with `n − s`, giving every signature a single canonical encoding and
/// removing ECDSA's `(r, s)` / `(r, n − s)` malleability.
const HALF_ORDER: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42, 0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31, 0x92, 0xa8,
];

/// HMAC-SHA256 over the concatenation of `parts`, keyed by `key`.
fn hmac_sha256(key: &[u8; 32], parts: &[&[u8]]) -> [u8; 32] {
    use cryptoxide::{hmac::Hmac, mac::Mac};
    let mut mac = Hmac::new(Sha256::new(), key);
    for part in parts {
        mac.input(part);
    }
    let mut out = [0u8; 32];
    mac.raw_result(&mut out);
    out
}

/// Raw ECDSA signing with a supplied nonce `k` (no low-S normalization).
///
/// Returns `(r, s)`, or `None` if `r == 0` or `s == 0` — in which case the
/// caller must derive a fresh nonce (the ECDSA / RFC 6979 retry rule).
fn ecdsa_raw_sign(d: &Scalar, e: &Scalar, k: &Scalar) -> Option<(Scalar, Scalar)> {
    // R = k·G ; r = x(R) mod n.
    let r_point = Point::mul_base(k).to_affine()?;
    let (x, _) = r_point.to_coordinate();
    let r = reduce_be_mod_order(&x.to_bytes());
    if r == Scalar::zero() {
        return None;
    }
    // s = k⁻¹ · (e + r·d) mod n.
    let kinv = k.inverse();
    let s = &kinv * &((&r * d) + e);
    if s == Scalar::zero() {
        return None;
    }
    Some((r, s))
}

/// Deterministic ECDSA signing per RFC 6979 (HMAC-SHA256 DRBG).
///
/// The nonce is derived solely from the private key and the message — no
/// RNG — so the same `(key, message)` always yields the same signature, and
/// a leaked or repeated nonce (the usual way ECDSA keys are compromised) is
/// impossible. With `low_s = true` the result is low-S normalized (the
/// public path); `low_s = false` yields the raw `(r, s)` and exists only to
/// check against the published RFC 6979 vectors. Returns the 64-byte
/// `r ‖ s` encoding.
pub(crate) fn ecdsa_sign_rfc6979_inner(
    d_bytes: &[u8; 32],
    message: &[u8],
    low_s: bool,
) -> [u8; 64] {
    // Every private-key constructor validates the scalar, so this is canonical.
    let d = Scalar::from_slice(d_bytes).expect("private key is a canonical scalar");

    // h1 = SHA-256(message); e = bits2int(h1) reduced mod n. For P-256 with
    // SHA-256, hlen == qlen == 256, so bits2int is the digest as an integer.
    let mut h1 = [0u8; 32];
    let mut hasher = Sha256::new();
    hasher.input(message);
    hasher.result(&mut h1);
    let e = reduce_be_mod_order(&h1);
    let bits2octets = e.to_bytes(); // int2octets(bits2int(h1) mod n)

    // RFC 6979 §3.2 (b)–(g): seed the HMAC-DRBG with the key and message.
    let mut v = [0x01u8; 32];
    let mut k = [0x00u8; 32];
    k = hmac_sha256(&k, &[&v[..], &[0x00u8][..], &d_bytes[..], &bits2octets[..]]);
    v = hmac_sha256(&k, &[&v[..]]);
    k = hmac_sha256(&k, &[&v[..], &[0x01u8][..], &d_bytes[..], &bits2octets[..]]);
    v = hmac_sha256(&k, &[&v[..]]);

    // RFC 6979 §3.2 (h): draw candidate nonces T = V (one block, since
    // tlen == qlen == 256) until one yields a valid signature. For P-256 the
    // first candidate succeeds with overwhelming probability; this loop is
    // guaranteed to terminate.
    loop {
        v = hmac_sha256(&k, &[&v[..]]);
        // bits2int(T): accept only T in [1, n−1]; from_slice rejects T ≥ n.
        if let Some(nonce) = Scalar::from_slice(&v)
            && nonce != Scalar::zero()
            && let Some((r, s)) = ecdsa_raw_sign(&d, &e, &nonce)
        {
            let s = if low_s && s.to_bytes() > HALF_ORDER {
                -&s
            } else {
                s
            };
            let mut out = [0u8; 64];
            out[..32].copy_from_slice(&r.to_bytes());
            out[32..].copy_from_slice(&s.to_bytes());
            return out;
        }
        // Candidate rejected (T ∉ [1, n−1], or r/s == 0): reseed and retry.
        k = hmac_sha256(&k, &[&v[..], &[0x00u8][..]]);
        v = hmac_sha256(&k, &[&v[..]]);
    }
}

/// Deterministic ECDSA signature (RFC 6979 nonce, low-S normalized).
pub(crate) fn ecdsa_sign_rfc6979(d_bytes: &[u8; 32], message: &[u8]) -> P256Signature {
    P256Signature(ecdsa_sign_rfc6979_inner(d_bytes, message, true))
}

// ── Tests ───────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

    fn hex32(s: &str) -> [u8; 32] {
        hex::decode(s).unwrap().try_into().unwrap()
    }

    /// RFC 6979 Appendix A.2.5 — NIST P-256 with SHA-256. The raw (no
    /// low-S) `(r, s)` must match the published vectors exactly, which pins
    /// the HMAC-DRBG nonce derivation, the digest reduction, and the ECDSA
    /// arithmetic against an authoritative source.
    #[test]
    fn rfc6979_p256_sha256_known_answer_vectors() {
        let x = hex32("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721");
        let cases: [(&[u8], &str, &str); 2] = [
            (
                b"sample",
                "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716",
                "F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8",
            ),
            (
                b"test",
                "F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367",
                "019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083",
            ),
        ];
        for (msg, r_hex, s_hex) in cases {
            let raw = ecdsa_sign_rfc6979_inner(&x, msg, false);
            assert_eq!(
                hex::encode_upper(&raw[..32]),
                r_hex,
                "r mismatch for {msg:?}"
            );
            assert_eq!(
                hex::encode_upper(&raw[32..]),
                s_hex,
                "s mismatch for {msg:?}"
            );
        }
    }

    /// The public signing path: derives the RFC 6979 public key, signs,
    /// verifies, is deterministic, and produces low-S signatures.
    #[test]
    fn rfc6979_public_path_verifies_and_is_low_s() {
        let x = hex32("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721");
        let sk = P256r1PrivateKey::from_bytes(x).unwrap();
        let pk = sk.public();

        // Public key matches RFC 6979 A.2.5 (uncompressed 0x04 ‖ X ‖ Y).
        assert_eq!(
            hex::encode_upper(&pk.as_ref()[1..33]),
            "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6"
        );
        assert_eq!(
            hex::encode_upper(&pk.as_ref()[33..65]),
            "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299"
        );

        for msg in [&b"sample"[..], &b"test"[..]] {
            let sig = sk.sign(msg).unwrap();
            assert!(pk.verify(sig, msg), "verify failed for {msg:?}");
            // Deterministic: signing again yields the identical signature.
            assert_eq!(sig, sk.sign(msg).unwrap(), "non-deterministic for {msg:?}");
            // Low-S: s ≤ (n−1)/2.
            assert!(sig.as_ref()[32..] <= HALF_ORDER[..], "high-S for {msg:?}");
        }
    }

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
    fn pk_from_bytes_empty_is_rejected() {
        // Previously panicked indexing public_key[0].
        let err = P256r1PublicKey::from_bytes(&[]).unwrap_err();
        assert!(matches!(err, Error::InvalidPublicKeyLength));
    }

    #[test]
    fn pk_from_bytes_prefix_only_is_rejected() {
        // A lone prefix byte — previously panicked slicing [1..33].
        let err = P256r1PublicKey::from_bytes(&[0x04]).unwrap_err();
        assert!(matches!(err, Error::InvalidPublicKeyLength));
    }

    #[test]
    fn pk_from_bytes_truncated_uncompressed_is_rejected() {
        // 0x04 prefix with only 64 bytes (needs 65) — previously
        // panicked slicing [33..65].
        let mut bytes = [0u8; 64];
        bytes[0] = 0x04;
        let err = P256r1PublicKey::from_bytes(&bytes).unwrap_err();
        assert!(matches!(err, Error::InvalidPublicKeyLength));
    }

    #[test]
    fn pk_from_bytes_truncated_compressed_is_rejected() {
        // 0x02 prefix with only 32 bytes (needs 33).
        let mut bytes = [0u8; 32];
        bytes[0] = 0x02;
        let err = P256r1PublicKey::from_bytes(&bytes).unwrap_err();
        assert!(matches!(err, Error::InvalidPublicKeyLength));
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
        let sk = software::P256r1PrivateKey::generate(rand::rng()).unwrap();
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
        let sk = software::P256r1PrivateKey::generate(rand::rng()).unwrap();
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
        let sk = software::P256r1PrivateKey::generate(rand::rng()).unwrap();
        let pk = sk.public();
        let sig = sk.sign(b"correct message").unwrap();

        assert!(!pk.verify(sig, b"wrong message"));
    }

    #[test]
    fn verify_wrong_key_fails() {
        let sk1 = software::P256r1PrivateKey::generate(rand::rng()).unwrap();
        let sk2 = software::P256r1PrivateKey::generate(rand::rng()).unwrap();
        let pk2 = sk2.public();

        let sig = sk1.sign(b"signed by sk1").unwrap();
        assert!(!pk2.verify(sig, b"signed by sk1"));
    }

    #[test]
    fn verify_corrupted_signature_fails() {
        let sk = software::P256r1PrivateKey::generate(rand::rng()).unwrap();
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
        let sk = software::P256r1PrivateKey::generate(rand::rng()).unwrap();
        let pk = sk.public();

        let zero_sig = P256Signature::try_from_bytes([0u8; 64]).unwrap();
        assert!(!pk.verify(zero_sig, b"anything"));
    }

    // ── ECDH negative tests ───────────────────────────────────────

    #[test]
    fn dh_different_peers_produce_different_secrets() {
        let sk = software::P256r1PrivateKey::generate(rand::rng()).unwrap();
        let peer1 = software::P256r1PrivateKey::generate(rand::rng())
            .unwrap()
            .public();
        let peer2 = software::P256r1PrivateKey::generate(rand::rng())
            .unwrap()
            .public();

        let ss1 = sk.dh(&peer1).unwrap();
        let ss2 = sk.dh(&peer2).unwrap();
        assert_ne!(ss1, ss2);
    }

    #[test]
    fn dh_is_not_commutative_with_different_keys() {
        // dh(sk1, pk2) == dh(sk2, pk1) — ECDH symmetry.
        let sk1 = software::P256r1PrivateKey::generate(rand::rng()).unwrap();
        let pk1 = sk1.public();
        let sk2 = software::P256r1PrivateKey::generate(rand::rng()).unwrap();
        let pk2 = sk2.public();

        let ss1 = sk1.dh(&pk2).unwrap();
        let ss2 = sk2.dh(&pk1).unwrap();
        assert_eq!(ss1, ss2);

        // But dh(sk1, pk1) != dh(sk1, pk2) — different peers.
        let ss_self = sk1.dh(&pk1).unwrap();
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
        Scalar::from_slice(&bytes)
            .expect("canonical scalar")
            .to_bytes()
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
        assert_eq!(
            reduce_be_mod_order(&N_BYTES).to_bytes(),
            Scalar::zero().to_bytes()
        );
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
