//! Regenerators for hiss's frozen P-256 known-answer vectors.
//!
//! These are the `#[ignore]` generators that *produce*
//! `tests/vectors/noise/p256_chachapoly_*.json` **in the hiss crate next
//! door**. They live here because they are the only thing in the pair that
//! links `snow`: hiss's replays read the committed JSON and never touch it.
//!
//! Run them, and read the additions-only discipline that governs the diff,
//! per `hiss-interop/README.md`.
//!
//! # Why the schema is duplicated
//!
//! `VectorFile` / `Vector` / `HandshakeMessage` / `TransportMessage` and the
//! frozen constants below are copies of the ones in hiss's
//! `tests/noise_kat.rs`. The alternative — reaching across the crate boundary
//! with `#[path]` — would rebuild exactly the coupling this crate exists to
//! remove. The duplication is safe because its failure mode is loud: a schema
//! that drifts writes JSON that hiss's replays cannot deserialize, and the KAT
//! gate goes red on the next run.

use hiss::noise::{Curve, P256};
use hiss::provider::{CryptoKeyProvider, EphemeralOnly, ProviderExt};
use rand::{TryCryptoRng, TryRng};
use serde::{Deserialize, Serialize};
use std::convert::Infallible;

// ── Output paths ─────────────────────────────────────────────────
//
// `CARGO_MANIFEST_DIR` is `hiss-interop/`, so the `../` is deliberate: this
// crate writes into its parent's test-vector directory. It is the one line
// that encodes "the generator lives here, the corpus lives there".

const VECTORS_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../tests/vectors/noise/p256_chachapoly_blake2b.json"
);

const SHA256_VECTORS_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../tests/vectors/noise/p256_chachapoly_sha256.json"
);

// ── Fixed inputs (frozen) ────────────────────────────────────────
//
// Copies of hiss `tests/noise_kat.rs`'s constants. Changing any of them
// changes every generated vector.

const INIT_STATIC: [u8; 32] = [0x11; 32];
const INIT_EPHEMERAL: [u8; 32] = [0x22; 32];
const RESP_STATIC: [u8; 32] = [0x33; 32];
const RESP_EPHEMERAL: [u8; 32] = [0x44; 32];
const PSK_BYTES: [u8; 32] = [0x55; 32];

const TRANSPORT_I2R: &[u8] = b"hiss KAT: initiator -> responder";
const TRANSPORT_R2I: &[u8] = b"hiss KAT: responder -> initiator";

// ── Vector schema (copy of hiss's) ───────────────────────────────

#[derive(Serialize, Deserialize)]
struct VectorFile {
    note: String,
    vectors: Vec<Vector>,
}

#[derive(Serialize, Deserialize)]
struct Vector {
    protocol_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    init_static: Option<String>,
    init_ephemeral: String,
    resp_static: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    resp_ephemeral: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    psk: Option<String>,
    /// `messages[i].ciphertext` is handshake message i+1; payload is empty.
    messages: Vec<HandshakeMessage>,
    handshake_hash: String,
    transport: Vec<TransportMessage>,
}

#[derive(Serialize, Deserialize)]
struct HandshakeMessage {
    payload: String,
    ciphertext: String,
}

#[derive(Serialize, Deserialize)]
struct TransportMessage {
    sender: String,
    payload: String,
    ciphertext: String,
}

// ── Fixed-key minting (P-256) ────────────────────────────────────

/// A deterministic RNG replaying a fixed byte stream — the minimal slice of
/// hiss's `tests/common/mod.rs` `ScriptedRng` this file needs, so that
/// `public_key` below mints the same key hiss's replays expect.
struct ScriptedRng {
    bytes: Vec<u8>,
    pos: usize,
}

impl ScriptedRng {
    fn new(seed: &[u8; 32]) -> Self {
        Self {
            bytes: seed.to_vec(),
            pos: 0,
        }
    }

    fn take(&mut self, n: usize) -> &[u8] {
        let end = self.pos + n;
        assert!(end <= self.bytes.len(), "ScriptedRng exhausted");
        let out = &self.bytes[self.pos..end];
        self.pos = end;
        out
    }
}

// rand_core 0.10 makes `TryRng` the base trait; the infallible `Rng` and
// `CryptoRng` that hiss's bounds want arrive via blanket impls over
// `Error = Infallible`. Exhausting the script still panics inside `take` —
// infallible is the type-level claim, not a promise the script is long
// enough.
impl TryRng for ScriptedRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        Ok(u32::from_le_bytes(self.take(4).try_into().unwrap()))
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        Ok(u64::from_le_bytes(self.take(8).try_into().unwrap()))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        let n = dst.len();
        dst.copy_from_slice(self.take(n));
        Ok(())
    }
}

impl TryCryptoRng for ScriptedRng {}

/// The P-256 public key for a fixed private scalar.
fn public_key(seed: &[u8; 32]) -> <P256 as Curve>::PublicKey {
    let mut p = EphemeralOnly::new(ScriptedRng::new(seed));
    let sk = CryptoKeyProvider::<P256>::generate_static_key(&mut p).unwrap();
    p.public(&sk).unwrap()
}

// ── Generator (reference: snow) ──────────────────────────────────

fn hh(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

fn resp_pub_bytes() -> Vec<u8> {
    public_key(&RESP_STATIC).to_bytes().to_vec()
}

fn init_pub_bytes() -> Vec<u8> {
    public_key(&INIT_STATIC).to_bytes().to_vec()
}

/// Run a one-message pattern through snow and capture msg1, the
/// handshake hash, and the initiator->responder transport ciphertext.
fn one_message(
    mut init: snow::HandshakeState,
    mut resp: snow::HandshakeState,
) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let mut b = [0u8; 512];
    let n = init.write_message(&[], &mut b).unwrap();
    let msg1 = b[..n].to_vec();

    let mut rb = [0u8; 512];
    resp.read_message(&msg1, &mut rb).unwrap();

    let hash = init.get_handshake_hash().to_vec();
    assert_eq!(hash, resp.get_handshake_hash(), "snow hashes diverged");

    let mut it = init.into_transport_mode().unwrap();
    let mut rt = resp.into_transport_mode().unwrap();

    let mut c = [0u8; 512];
    let cn = it.write_message(TRANSPORT_I2R, &mut c).unwrap();
    let i2r = c[..cn].to_vec();
    let mut chk = [0u8; 512];
    rt.read_message(&i2r, &mut chk).unwrap();

    (msg1, hash, i2r)
}

fn one_message_vector(
    protocol_name: &str,
    init_static: Option<String>,
    psk: Option<String>,
    init: snow::HandshakeState,
    resp: snow::HandshakeState,
) -> Vector {
    let (msg1, hash, i2r) = one_message(init, resp);
    Vector {
        protocol_name: protocol_name.to_string(),
        init_static,
        init_ephemeral: hh(&INIT_EPHEMERAL),
        resp_static: hh(&RESP_STATIC),
        resp_ephemeral: None,
        psk,
        messages: vec![HandshakeMessage {
            payload: String::new(),
            ciphertext: hh(&msg1),
        }],
        handshake_hash: hh(&hash),
        transport: vec![TransportMessage {
            sender: "initiator".to_string(),
            payload: hh(TRANSPORT_I2R),
            ciphertext: hh(&i2r),
        }],
    }
}

/// Captured bytes from a two-message handshake run.
struct TwoMessageRun {
    msg1: Vec<u8>,
    msg2: Vec<u8>,
    hash: Vec<u8>,
    i2r: Vec<u8>,
    r2i: Vec<u8>,
}

/// Run a two-message pattern (initiator msg1, responder msg2) through
/// snow and capture both messages, the handshake hash, and both
/// transport directions.
fn two_message(mut init: snow::HandshakeState, mut resp: snow::HandshakeState) -> TwoMessageRun {
    let mut b1 = [0u8; 512];
    let n1 = init.write_message(&[], &mut b1).unwrap();
    let msg1 = b1[..n1].to_vec();
    let mut rb = [0u8; 512];
    resp.read_message(&msg1, &mut rb).unwrap();

    let mut b2 = [0u8; 512];
    let n2 = resp.write_message(&[], &mut b2).unwrap();
    let msg2 = b2[..n2].to_vec();
    let mut ib = [0u8; 512];
    init.read_message(&msg2, &mut ib).unwrap();

    let hash = init.get_handshake_hash().to_vec();
    assert_eq!(hash, resp.get_handshake_hash(), "snow hashes diverged");

    let mut it = init.into_transport_mode().unwrap();
    let mut rt = resp.into_transport_mode().unwrap();

    let mut c = [0u8; 512];
    let cn = it.write_message(TRANSPORT_I2R, &mut c).unwrap();
    let i2r = c[..cn].to_vec();
    let mut c2 = [0u8; 512];
    let cn2 = rt.write_message(TRANSPORT_R2I, &mut c2).unwrap();
    let r2i = c2[..cn2].to_vec();

    TwoMessageRun {
        msg1,
        msg2,
        hash,
        i2r,
        r2i,
    }
}

fn two_message_vector(
    protocol_name: &str,
    init_static: Option<String>,
    psk: Option<String>,
    init: snow::HandshakeState,
    resp: snow::HandshakeState,
) -> Vector {
    let TwoMessageRun {
        msg1,
        msg2,
        hash,
        i2r,
        r2i,
    } = two_message(init, resp);
    Vector {
        protocol_name: protocol_name.to_string(),
        init_static,
        init_ephemeral: hh(&INIT_EPHEMERAL),
        resp_static: hh(&RESP_STATIC),
        resp_ephemeral: Some(hh(&RESP_EPHEMERAL)),
        psk,
        messages: vec![
            HandshakeMessage {
                payload: String::new(),
                ciphertext: hh(&msg1),
            },
            HandshakeMessage {
                payload: String::new(),
                ciphertext: hh(&msg2),
            },
        ],
        handshake_hash: hh(&hash),
        transport: vec![
            TransportMessage {
                sender: "initiator".to_string(),
                payload: hh(TRANSPORT_I2R),
                ciphertext: hh(&i2r),
            },
            TransportMessage {
                sender: "responder".to_string(),
                payload: hh(TRANSPORT_R2I),
                ciphertext: hh(&r2i),
            },
        ],
    }
}

/// Captured bytes from a three-message handshake run.
struct ThreeMessageRun {
    msg1: Vec<u8>,
    msg2: Vec<u8>,
    msg3: Vec<u8>,
    hash: Vec<u8>,
    i2r: Vec<u8>,
    r2i: Vec<u8>,
}

/// Run a three-message pattern through snow (msg1 ->, msg2 <-, msg3 ->)
/// and capture every handshake message, the handshake hash, and both
/// transport directions.
fn three_message(
    mut init: snow::HandshakeState,
    mut resp: snow::HandshakeState,
) -> ThreeMessageRun {
    let mut b1 = [0u8; 512];
    let n1 = init.write_message(&[], &mut b1).unwrap();
    let msg1 = b1[..n1].to_vec();
    let mut rb = [0u8; 512];
    resp.read_message(&msg1, &mut rb).unwrap();

    let mut b2 = [0u8; 512];
    let n2 = resp.write_message(&[], &mut b2).unwrap();
    let msg2 = b2[..n2].to_vec();
    let mut ib = [0u8; 512];
    init.read_message(&msg2, &mut ib).unwrap();

    let mut b3 = [0u8; 512];
    let n3 = init.write_message(&[], &mut b3).unwrap();
    let msg3 = b3[..n3].to_vec();
    let mut rb3 = [0u8; 512];
    resp.read_message(&msg3, &mut rb3).unwrap();

    let hash = init.get_handshake_hash().to_vec();
    assert_eq!(hash, resp.get_handshake_hash(), "snow hashes diverged");

    let mut it = init.into_transport_mode().unwrap();
    let mut rt = resp.into_transport_mode().unwrap();

    let mut c = [0u8; 512];
    let cn = it.write_message(TRANSPORT_I2R, &mut c).unwrap();
    let i2r = c[..cn].to_vec();
    let mut c2 = [0u8; 512];
    let cn2 = rt.write_message(TRANSPORT_R2I, &mut c2).unwrap();
    let r2i = c2[..cn2].to_vec();

    ThreeMessageRun {
        msg1,
        msg2,
        msg3,
        hash,
        i2r,
        r2i,
    }
}

fn three_message_vector(
    protocol_name: &str,
    init_static: Option<String>,
    psk: Option<String>,
    init: snow::HandshakeState,
    resp: snow::HandshakeState,
) -> Vector {
    let ThreeMessageRun {
        msg1,
        msg2,
        msg3,
        hash,
        i2r,
        r2i,
    } = three_message(init, resp);
    Vector {
        protocol_name: protocol_name.to_string(),
        init_static,
        init_ephemeral: hh(&INIT_EPHEMERAL),
        resp_static: hh(&RESP_STATIC),
        resp_ephemeral: Some(hh(&RESP_EPHEMERAL)),
        psk,
        messages: vec![
            HandshakeMessage {
                payload: String::new(),
                ciphertext: hh(&msg1),
            },
            HandshakeMessage {
                payload: String::new(),
                ciphertext: hh(&msg2),
            },
            HandshakeMessage {
                payload: String::new(),
                ciphertext: hh(&msg3),
            },
        ],
        handshake_hash: hh(&hash),
        transport: vec![
            TransportMessage {
                sender: "initiator".to_string(),
                payload: hh(TRANSPORT_I2R),
                ciphertext: hh(&i2r),
            },
            TransportMessage {
                sender: "responder".to_string(),
                payload: hh(TRANSPORT_R2I),
                ciphertext: hh(&r2i),
            },
        ],
    }
}

fn vector_n(proto: &str) -> Vector {
    let init = snow::Builder::new(proto.parse().unwrap())
        .remote_public_key(&resp_pub_bytes())
        .unwrap()
        .fixed_ephemeral_key_for_testing_only(&INIT_EPHEMERAL)
        .build_initiator()
        .unwrap();
    let resp = snow::Builder::new(proto.parse().unwrap())
        .local_private_key(&RESP_STATIC)
        .unwrap()
        .build_responder()
        .unwrap();
    one_message_vector(proto, None, None, init, resp)
}

fn vector_k() -> Vector {
    let proto = "Noise_K_P256_ChaChaPoly_BLAKE2b";
    let init = snow::Builder::new(proto.parse().unwrap())
        .local_private_key(&INIT_STATIC)
        .unwrap()
        .remote_public_key(&resp_pub_bytes())
        .unwrap()
        .fixed_ephemeral_key_for_testing_only(&INIT_EPHEMERAL)
        .build_initiator()
        .unwrap();
    let resp = snow::Builder::new(proto.parse().unwrap())
        .local_private_key(&RESP_STATIC)
        .unwrap()
        .remote_public_key(&init_pub_bytes())
        .unwrap()
        .build_responder()
        .unwrap();
    one_message_vector(proto, Some(hh(&INIT_STATIC)), None, init, resp)
}

fn vector_kpsk0() -> Vector {
    let proto = "Noise_Kpsk0_P256_ChaChaPoly_BLAKE2b";
    let init = snow::Builder::new(proto.parse().unwrap())
        .local_private_key(&INIT_STATIC)
        .unwrap()
        .remote_public_key(&resp_pub_bytes())
        .unwrap()
        .psk(0, &PSK_BYTES)
        .unwrap()
        .fixed_ephemeral_key_for_testing_only(&INIT_EPHEMERAL)
        .build_initiator()
        .unwrap();
    let resp = snow::Builder::new(proto.parse().unwrap())
        .local_private_key(&RESP_STATIC)
        .unwrap()
        .remote_public_key(&init_pub_bytes())
        .unwrap()
        .psk(0, &PSK_BYTES)
        .unwrap()
        .build_responder()
        .unwrap();
    one_message_vector(
        proto,
        Some(hh(&INIT_STATIC)),
        Some(hh(&PSK_BYTES)),
        init,
        resp,
    )
}

fn vector_ikpsk1(proto: &str) -> Vector {
    let init = snow::Builder::new(proto.parse().unwrap())
        .local_private_key(&INIT_STATIC)
        .unwrap()
        .remote_public_key(&resp_pub_bytes())
        .unwrap()
        .psk(1, &PSK_BYTES)
        .unwrap()
        .fixed_ephemeral_key_for_testing_only(&INIT_EPHEMERAL)
        .build_initiator()
        .unwrap();
    let resp = snow::Builder::new(proto.parse().unwrap())
        .local_private_key(&RESP_STATIC)
        .unwrap()
        .psk(1, &PSK_BYTES)
        .unwrap()
        .fixed_ephemeral_key_for_testing_only(&RESP_EPHEMERAL)
        .build_responder()
        .unwrap();
    two_message_vector(
        proto,
        Some(hh(&INIT_STATIC)),
        Some(hh(&PSK_BYTES)),
        init,
        resp,
    )
}

fn vector_ik() -> Vector {
    let proto = "Noise_IK_P256_ChaChaPoly_BLAKE2b";
    let init = snow::Builder::new(proto.parse().unwrap())
        .local_private_key(&INIT_STATIC)
        .unwrap()
        .remote_public_key(&resp_pub_bytes())
        .unwrap()
        .fixed_ephemeral_key_for_testing_only(&INIT_EPHEMERAL)
        .build_initiator()
        .unwrap();
    let resp = snow::Builder::new(proto.parse().unwrap())
        .local_private_key(&RESP_STATIC)
        .unwrap()
        .fixed_ephemeral_key_for_testing_only(&RESP_EPHEMERAL)
        .build_responder()
        .unwrap();
    two_message_vector(proto, Some(hh(&INIT_STATIC)), None, init, resp)
}

fn vector_nk() -> Vector {
    let proto = "Noise_NK_P256_ChaChaPoly_BLAKE2b";
    // NK: anonymous initiator (no local static), responder static
    // known up front.
    let init = snow::Builder::new(proto.parse().unwrap())
        .remote_public_key(&resp_pub_bytes())
        .unwrap()
        .fixed_ephemeral_key_for_testing_only(&INIT_EPHEMERAL)
        .build_initiator()
        .unwrap();
    let resp = snow::Builder::new(proto.parse().unwrap())
        .local_private_key(&RESP_STATIC)
        .unwrap()
        .fixed_ephemeral_key_for_testing_only(&RESP_EPHEMERAL)
        .build_responder()
        .unwrap();
    two_message_vector(proto, None, None, init, resp)
}

fn vector_ix() -> Vector {
    let proto = "Noise_IX_P256_ChaChaPoly_BLAKE2b";
    // IX: no pre-messages. Both sides carry a local static (sent
    // in-handshake) and neither pre-knows the other's static, so
    // there is no `remote_public_key` on either builder.
    let init = snow::Builder::new(proto.parse().unwrap())
        .local_private_key(&INIT_STATIC)
        .unwrap()
        .fixed_ephemeral_key_for_testing_only(&INIT_EPHEMERAL)
        .build_initiator()
        .unwrap();
    let resp = snow::Builder::new(proto.parse().unwrap())
        .local_private_key(&RESP_STATIC)
        .unwrap()
        .fixed_ephemeral_key_for_testing_only(&RESP_EPHEMERAL)
        .build_responder()
        .unwrap();
    two_message_vector(proto, Some(hh(&INIT_STATIC)), None, init, resp)
}

fn vector_xk() -> Vector {
    let proto = "Noise_XK_P256_ChaChaPoly_BLAKE2b";
    // XK: pre-message `<- s` — the initiator pre-knows the responder's
    // static (remote_public_key) and carries its own static, sent
    // encrypted in msg3. The responder carries its own static (pre-known
    // to the peer) and does NOT pre-know the initiator's static.
    let init = snow::Builder::new(proto.parse().unwrap())
        .local_private_key(&INIT_STATIC)
        .unwrap()
        .remote_public_key(&resp_pub_bytes())
        .unwrap()
        .fixed_ephemeral_key_for_testing_only(&INIT_EPHEMERAL)
        .build_initiator()
        .unwrap();
    let resp = snow::Builder::new(proto.parse().unwrap())
        .local_private_key(&RESP_STATIC)
        .unwrap()
        .fixed_ephemeral_key_for_testing_only(&RESP_EPHEMERAL)
        .build_responder()
        .unwrap();
    three_message_vector(proto, Some(hh(&INIT_STATIC)), None, init, resp)
}

fn vector_nn() -> Vector {
    let proto = "Noise_NN_P256_ChaChaPoly_BLAKE2b";
    // NN: both parties anonymous — no static keys, no pre-messages, no
    // PSK. Only the fixed ephemerals are pinned on each side.
    let init = snow::Builder::new(proto.parse().unwrap())
        .fixed_ephemeral_key_for_testing_only(&INIT_EPHEMERAL)
        .build_initiator()
        .unwrap();
    let resp = snow::Builder::new(proto.parse().unwrap())
        .fixed_ephemeral_key_for_testing_only(&RESP_EPHEMERAL)
        .build_responder()
        .unwrap();
    two_message_vector(proto, None, None, init, resp)
}

fn vector_xx(proto: &str) -> Vector {
    // XX: no pre-messages. Both sides carry a local static (sent
    // in-handshake, encrypted after `ee`) and neither pre-knows the
    // other's static, so there is no `remote_public_key` on either
    // builder.
    let init = snow::Builder::new(proto.parse().unwrap())
        .local_private_key(&INIT_STATIC)
        .unwrap()
        .fixed_ephemeral_key_for_testing_only(&INIT_EPHEMERAL)
        .build_initiator()
        .unwrap();
    let resp = snow::Builder::new(proto.parse().unwrap())
        .local_private_key(&RESP_STATIC)
        .unwrap()
        .fixed_ephemeral_key_for_testing_only(&RESP_EPHEMERAL)
        .build_responder()
        .unwrap();
    three_message_vector(proto, Some(hh(&INIT_STATIC)), None, init, resp)
}

fn vector_x() -> Vector {
    let proto = "Noise_X_P256_ChaChaPoly_BLAKE2b";
    // X: pre-message `<- s` — the initiator pre-knows the responder's
    // static (remote_public_key) and carries its own static, sent
    // encrypted in msg1. Unlike K, the responder does NOT pre-know the
    // initiator's static (it is transmitted in-handshake), so there is no
    // `remote_public_key` on the responder builder.
    let init = snow::Builder::new(proto.parse().unwrap())
        .local_private_key(&INIT_STATIC)
        .unwrap()
        .remote_public_key(&resp_pub_bytes())
        .unwrap()
        .fixed_ephemeral_key_for_testing_only(&INIT_EPHEMERAL)
        .build_initiator()
        .unwrap();
    let resp = snow::Builder::new(proto.parse().unwrap())
        .local_private_key(&RESP_STATIC)
        .unwrap()
        .build_responder()
        .unwrap();
    one_message_vector(proto, Some(hh(&INIT_STATIC)), None, init, resp)
}

fn vector_nx() -> Vector {
    let proto = "Noise_NX_P256_ChaChaPoly_BLAKE2b";
    // NX: no pre-messages. The initiator is anonymous (no local static);
    // the responder carries its own, sent encrypted in msg2.
    let init = snow::Builder::new(proto.parse().unwrap())
        .fixed_ephemeral_key_for_testing_only(&INIT_EPHEMERAL)
        .build_initiator()
        .unwrap();
    let resp = snow::Builder::new(proto.parse().unwrap())
        .local_private_key(&RESP_STATIC)
        .unwrap()
        .fixed_ephemeral_key_for_testing_only(&RESP_EPHEMERAL)
        .build_responder()
        .unwrap();
    two_message_vector(proto, None, None, init, resp)
}

fn vector_xn() -> Vector {
    let proto = "Noise_XN_P256_ChaChaPoly_BLAKE2b";
    // XN: no pre-messages, three messages. The mirror of NX — the
    // initiator carries the only static, sent encrypted in msg3, and the
    // responder is anonymous.
    let init = snow::Builder::new(proto.parse().unwrap())
        .local_private_key(&INIT_STATIC)
        .unwrap()
        .fixed_ephemeral_key_for_testing_only(&INIT_EPHEMERAL)
        .build_initiator()
        .unwrap();
    let resp = snow::Builder::new(proto.parse().unwrap())
        .fixed_ephemeral_key_for_testing_only(&RESP_EPHEMERAL)
        .build_responder()
        .unwrap();
    three_message_vector(proto, Some(hh(&INIT_STATIC)), None, init, resp)
}

fn vector_kn() -> Vector {
    let proto = "Noise_KN_P256_ChaChaPoly_BLAKE2b";
    // KN: pre-message `-> s` — the responder pre-knows the initiator's
    // static and holds none of its own.
    let init = snow::Builder::new(proto.parse().unwrap())
        .local_private_key(&INIT_STATIC)
        .unwrap()
        .fixed_ephemeral_key_for_testing_only(&INIT_EPHEMERAL)
        .build_initiator()
        .unwrap();
    let resp = snow::Builder::new(proto.parse().unwrap())
        .remote_public_key(&init_pub_bytes())
        .unwrap()
        .fixed_ephemeral_key_for_testing_only(&RESP_EPHEMERAL)
        .build_responder()
        .unwrap();
    two_message_vector(proto, Some(hh(&INIT_STATIC)), None, init, resp)
}

fn vector_kk() -> Vector {
    let proto = "Noise_KK_P256_ChaChaPoly_BLAKE2b";
    // KK: both pre-messages — each side holds its own static and
    // pre-knows the other's, so msg1's payload is already encrypted.
    let init = snow::Builder::new(proto.parse().unwrap())
        .local_private_key(&INIT_STATIC)
        .unwrap()
        .remote_public_key(&resp_pub_bytes())
        .unwrap()
        .fixed_ephemeral_key_for_testing_only(&INIT_EPHEMERAL)
        .build_initiator()
        .unwrap();
    let resp = snow::Builder::new(proto.parse().unwrap())
        .local_private_key(&RESP_STATIC)
        .unwrap()
        .remote_public_key(&init_pub_bytes())
        .unwrap()
        .fixed_ephemeral_key_for_testing_only(&RESP_EPHEMERAL)
        .build_responder()
        .unwrap();
    two_message_vector(proto, Some(hh(&INIT_STATIC)), None, init, resp)
}

fn vector_kx() -> Vector {
    let proto = "Noise_KX_P256_ChaChaPoly_BLAKE2b";
    // KX: pre-message `-> s` as in KN, but the responder also carries a
    // static of its own, sent encrypted in msg2.
    let init = snow::Builder::new(proto.parse().unwrap())
        .local_private_key(&INIT_STATIC)
        .unwrap()
        .fixed_ephemeral_key_for_testing_only(&INIT_EPHEMERAL)
        .build_initiator()
        .unwrap();
    let resp = snow::Builder::new(proto.parse().unwrap())
        .local_private_key(&RESP_STATIC)
        .unwrap()
        .remote_public_key(&init_pub_bytes())
        .unwrap()
        .fixed_ephemeral_key_for_testing_only(&RESP_EPHEMERAL)
        .build_responder()
        .unwrap();
    two_message_vector(proto, Some(hh(&INIT_STATIC)), None, init, resp)
}

fn vector_in() -> Vector {
    let proto = "Noise_IN_P256_ChaChaPoly_BLAKE2b";
    // IN: no pre-messages. The initiator's static rides msg1 in the
    // clear; the responder is anonymous.
    let init = snow::Builder::new(proto.parse().unwrap())
        .local_private_key(&INIT_STATIC)
        .unwrap()
        .fixed_ephemeral_key_for_testing_only(&INIT_EPHEMERAL)
        .build_initiator()
        .unwrap();
    let resp = snow::Builder::new(proto.parse().unwrap())
        .fixed_ephemeral_key_for_testing_only(&RESP_EPHEMERAL)
        .build_responder()
        .unwrap();
    two_message_vector(proto, Some(hh(&INIT_STATIC)), None, init, resp)
}

/// Regenerate the frozen vectors from snow. Ignored: run manually with
/// `cargo test --test noise_kat generate_noise_kat_vectors -- --ignored`.
#[test]
#[ignore]
fn generate_noise_kat_vectors() {
    let file = VectorFile {
        note: "Noise KAT vectors for P256/ChaChaPoly/BLAKE2b, generated \
               from snow with fixed keys + pinned ephemerals. One-way \
               patterns (N, K, Kpsk0, X) freeze msg1 + the initiator->responder \
               transport; the interactive patterns (IKpsk1, IK, NK, IX, XK, NN, XX, NX, XN, \
               KN, KK, KX, IN) freeze every handshake message + both transport directions. \
               Provenance: agreement with snow (no spec P-256 vectors exist)."
            .to_string(),
        vectors: vec![
            vector_n("Noise_N_P256_ChaChaPoly_BLAKE2b"),
            vector_k(),
            vector_kpsk0(),
            vector_ikpsk1("Noise_IKpsk1_P256_ChaChaPoly_BLAKE2b"),
            vector_ik(),
            vector_nk(),
            vector_ix(),
            vector_xk(),
            vector_nn(),
            vector_xx("Noise_XX_P256_ChaChaPoly_BLAKE2b"),
            vector_x(),
            vector_nx(),
            vector_xn(),
            vector_kn(),
            vector_kk(),
            vector_kx(),
            vector_in(),
        ],
    };
    let json = serde_json::to_string_pretty(&file).unwrap();
    std::fs::write(VECTORS_PATH, json + "\n").unwrap();
    eprintln!("wrote {VECTORS_PATH}");
}

/// Regenerate the frozen SHA-256 vectors from snow. Ignored: run
/// manually with `cargo test --test noise_kat
/// generate_noise_kat_sha256_vectors -- --ignored`.
#[test]
#[ignore]
fn generate_noise_kat_sha256_vectors() {
    let file = VectorFile {
        note: "Noise KAT vectors for P256/ChaChaPoly/SHA256, generated \
               from snow with fixed keys + pinned ephemerals. Three \
               patterns, one per code path the hash choice reaches: N \
               (one-way, HKDF-2, protocol name padded), XX (three \
               messages, split, both transport directions), IKpsk1 (PSK \
               => HKDF-3, and a 35-byte protocol name => hashed rather \
               than padded at HASHLEN 32). \
               Provenance: agreement with snow (no spec P-256 vectors exist)."
            .to_string(),
        vectors: vec![
            vector_n("Noise_N_P256_ChaChaPoly_SHA256"),
            vector_ikpsk1("Noise_IKpsk1_P256_ChaChaPoly_SHA256"),
            vector_xx("Noise_XX_P256_ChaChaPoly_SHA256"),
        ],
    };
    let json = serde_json::to_string_pretty(&file).unwrap();
    std::fs::write(SHA256_VECTORS_PATH, json + "\n").unwrap();
    eprintln!("wrote {SHA256_VECTORS_PATH}");
}
