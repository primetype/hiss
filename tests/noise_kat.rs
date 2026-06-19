//! Frozen Noise known-answer-test (KAT) vectors.
//!
//! The vectors in `tests/vectors/noise/p256_chachapoly_blake2b.json` are
//! **frozen** byte-for-byte expectations for the six supported patterns
//! (N, K, Kpsk0, IKpsk1, IK, NK) over `P256 / ChaChaPoly / BLAKE2b`, produced from
//! the `snow` reference implementation with fixed keys and pinned
//! ephemerals (`generate_noise_kat_vectors`, `#[ignore]`).
//!
//! [`noise_kat_*`] replay each vector through this crate: a [`ScriptedRng`]
//! injects the recorded ephemeral, statics are set from the recorded key
//! bytes, and every handshake-message ciphertext, the final handshake
//! hash, and the transport ciphertexts must match the frozen bytes. This
//! is the byte-for-byte regression lock; continuous agreement with `snow`
//! is additionally covered by `tests/snow_interop.rs`.
//!
//! Provenance note: P-256 is not in the Noise spec and no third-party
//! P-256 Noise vectors exist, so these are "agreement with snow", not
//! agreement with a standards body.

mod common;
use common::{ScriptedRng, private_key, public_key};

use hiss::noise::*;
use hiss::provider::EphemeralOnly;
use hiss::psk::Psk;
use serde::{Deserialize, Serialize};

// ── Fixed inputs (frozen) ────────────────────────────────────────

const INIT_STATIC: [u8; 32] = [0x11; 32];
const INIT_EPHEMERAL: [u8; 32] = [0x22; 32];
const RESP_STATIC: [u8; 32] = [0x33; 32];
const RESP_EPHEMERAL: [u8; 32] = [0x44; 32];
const PSK_BYTES: [u8; 32] = [0x55; 32];

const TRANSPORT_I2R: &[u8] = b"hiss KAT: initiator -> responder";
const TRANSPORT_R2I: &[u8] = b"hiss KAT: responder -> initiator";

const VECTORS_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/vectors/noise/p256_chachapoly_blake2b.json"
);

// ── Vector schema ────────────────────────────────────────────────

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

// ── Helpers ──────────────────────────────────────────────────────

fn load_vectors() -> VectorFile {
    let raw = std::fs::read_to_string(VECTORS_PATH).unwrap_or_else(|e| {
        panic!(
            "missing {VECTORS_PATH}: run `cargo test --test noise_kat \
             generate_noise_kat_vectors -- --ignored` first ({e})"
        )
    });
    serde_json::from_str(&raw).expect("valid noise KAT json")
}

fn vector<'a>(file: &'a VectorFile, protocol_name: &str) -> &'a Vector {
    file.vectors
        .iter()
        .find(|v| v.protocol_name == protocol_name)
        .unwrap_or_else(|| panic!("no vector for {protocol_name}"))
}

fn decode(hex_str: &str) -> Vec<u8> {
    hex::decode(hex_str).expect("hex")
}

// ── Replay tests (drive this crate's initiator) ──────────────────

#[tokio::test]
async fn noise_kat_n() {
    let file = load_vectors();
    let v = vector(&file, "Noise_N_P256_ChaChaPoly_BLAKE2b");

    let provider = EphemeralOnly::new(ScriptedRng::new(&[&INIT_EPHEMERAL]));
    let hs = N::initiate(provider, &[])
        .set_rs(public_key(&RESP_STATIC));

    let mut buf = [0u8; 256];
    let (msg1, mut transport) = hs.e(&mut buf).await.unwrap().es().await.unwrap();

    assert_eq!(msg1.to_vec(), decode(&v.messages[0].ciphertext), "N msg1");
    assert_eq!(
        transport.session_id().as_ref(),
        decode(&v.handshake_hash),
        "N handshake hash"
    );

    let mut ct = [0u8; 256];
    let n = transport.send(TRANSPORT_I2R, &mut ct).unwrap();
    assert_eq!(&ct[..n], decode(&v.transport[0].ciphertext), "N transport i->r");
}

#[tokio::test]
async fn noise_kat_k() {
    let file = load_vectors();
    let v = vector(&file, "Noise_K_P256_ChaChaPoly_BLAKE2b");

    let provider = EphemeralOnly::new(ScriptedRng::new(&[&INIT_EPHEMERAL]));
    let hs = K::initiate(provider, &[])
        .set_s(private_key(&INIT_STATIC))
        .unwrap()
        .set_rs(public_key(&RESP_STATIC));

    let mut buf = [0u8; 256];
    let (msg1, mut transport) = hs
        .e(&mut buf)
        .await
        .unwrap()
        .es()
        .await
        .unwrap()
        .ss()
        .await
        .unwrap();

    assert_eq!(msg1.to_vec(), decode(&v.messages[0].ciphertext), "K msg1");
    assert_eq!(
        transport.session_id().as_ref(),
        decode(&v.handshake_hash),
        "K handshake hash"
    );

    let mut ct = [0u8; 256];
    let n = transport.send(TRANSPORT_I2R, &mut ct).unwrap();
    assert_eq!(&ct[..n], decode(&v.transport[0].ciphertext), "K transport i->r");
}

#[tokio::test]
async fn noise_kat_kpsk0() {
    let file = load_vectors();
    let v = vector(&file, "Noise_Kpsk0_P256_ChaChaPoly_BLAKE2b");

    let psk = Psk::from_bytes(PSK_BYTES);
    let provider = EphemeralOnly::new(ScriptedRng::new(&[&INIT_EPHEMERAL]));
    let hs = Kpsk0::initiate(provider, &[])
        .set_s(private_key(&INIT_STATIC))
        .unwrap()
        .set_rs(public_key(&RESP_STATIC));

    let mut buf = [0u8; 256];
    let (msg1, mut transport) = hs
        .psk(&mut buf, &psk)
        .await
        .unwrap()
        .e()
        .await
        .unwrap()
        .es()
        .await
        .unwrap()
        .ss()
        .await
        .unwrap();

    assert_eq!(msg1.to_vec(), decode(&v.messages[0].ciphertext), "Kpsk0 msg1");
    assert_eq!(
        transport.session_id().as_ref(),
        decode(&v.handshake_hash),
        "Kpsk0 handshake hash"
    );

    let mut ct = [0u8; 256];
    let n = transport.send(TRANSPORT_I2R, &mut ct).unwrap();
    assert_eq!(
        &ct[..n],
        decode(&v.transport[0].ciphertext),
        "Kpsk0 transport i->r"
    );
}

#[tokio::test]
async fn noise_kat_ikpsk1() {
    let file = load_vectors();
    let v = vector(&file, "Noise_IKpsk1_P256_ChaChaPoly_BLAKE2b");

    let psk = Psk::from_bytes(PSK_BYTES);
    let provider = EphemeralOnly::new(ScriptedRng::new(&[&INIT_EPHEMERAL]));
    let hs = IKpsk1::initiate(provider, &[])
        .set_rs(public_key(&RESP_STATIC));

    // msg1: -> e, es, s, ss, psk
    let mut buf1 = [0u8; 256];
    let (msg1, hs) = hs
        .e(&mut buf1)
        .await
        .unwrap()
        .es()
        .await
        .unwrap()
        .s(private_key(&INIT_STATIC))
        .await
        .unwrap()
        .ss()
        .await
        .unwrap()
        .psk(&psk)
        .await
        .unwrap();
    assert_eq!(msg1.to_vec(), decode(&v.messages[0].ciphertext), "IKpsk1 msg1");

    // msg2: <- e, ee, se (read the frozen responder message)
    let msg2 = decode(&v.messages[1].ciphertext);
    let (_, recv) = hs.read(&msg2).unwrap().e().await.unwrap();
    let mut transport = recv.ee().await.unwrap().se().await.unwrap();

    assert_eq!(
        transport.session_id().as_ref(),
        decode(&v.handshake_hash),
        "IKpsk1 handshake hash"
    );

    // transport: initiator -> responder (we produce it)
    let mut ct = [0u8; 256];
    let n = transport.send(TRANSPORT_I2R, &mut ct).unwrap();
    assert_eq!(
        &ct[..n],
        decode(&v.transport[0].ciphertext),
        "IKpsk1 transport i->r"
    );

    // transport: responder -> initiator (we decrypt the frozen ciphertext)
    let r2i = decode(&v.transport[1].ciphertext);
    let mut pt = [0u8; 256];
    let pn = transport.receive(&r2i, &mut pt).unwrap();
    assert_eq!(&pt[..pn], TRANSPORT_R2I, "IKpsk1 transport r->i plaintext");
}

#[tokio::test]
async fn noise_kat_ik() {
    let file = load_vectors();
    let v = vector(&file, "Noise_IK_P256_ChaChaPoly_BLAKE2b");

    let provider = EphemeralOnly::new(ScriptedRng::new(&[&INIT_EPHEMERAL]));
    let hs = IK::initiate(provider, &[]).set_rs(public_key(&RESP_STATIC));

    // msg1: -> e, es, s, ss
    let mut buf1 = [0u8; 256];
    let (msg1, hs) = hs
        .e(&mut buf1)
        .await
        .unwrap()
        .es()
        .await
        .unwrap()
        .s(private_key(&INIT_STATIC))
        .await
        .unwrap()
        .ss()
        .await
        .unwrap();
    assert_eq!(msg1.to_vec(), decode(&v.messages[0].ciphertext), "IK msg1");

    // msg2: <- e, ee, se (read the frozen responder message)
    let msg2 = decode(&v.messages[1].ciphertext);
    let (_, recv) = hs.read(&msg2).unwrap().e().await.unwrap();
    let mut transport = recv.ee().await.unwrap().se().await.unwrap();

    assert_eq!(
        transport.session_id().as_ref(),
        decode(&v.handshake_hash),
        "IK handshake hash"
    );

    // transport: initiator -> responder (we produce it)
    let mut ct = [0u8; 256];
    let n = transport.send(TRANSPORT_I2R, &mut ct).unwrap();
    assert_eq!(
        &ct[..n],
        decode(&v.transport[0].ciphertext),
        "IK transport i->r"
    );

    // transport: responder -> initiator (we decrypt the frozen ciphertext)
    let r2i = decode(&v.transport[1].ciphertext);
    let mut pt = [0u8; 256];
    let pn = transport.receive(&r2i, &mut pt).unwrap();
    assert_eq!(&pt[..pn], TRANSPORT_R2I, "IK transport r->i plaintext");
}

#[tokio::test]
async fn noise_kat_nk() {
    let file = load_vectors();
    let v = vector(&file, "Noise_NK_P256_ChaChaPoly_BLAKE2b");

    let provider = EphemeralOnly::new(ScriptedRng::new(&[&INIT_EPHEMERAL]));
    // NK initiator is anonymous: no static, only the responder's
    // static key is pre-known.
    let hs = NK::initiate(provider, &[]).set_rs(public_key(&RESP_STATIC));

    // msg1: -> e, es
    let mut buf1 = [0u8; 256];
    let (msg1, hs) = hs.e(&mut buf1).await.unwrap().es().await.unwrap();
    assert_eq!(msg1.to_vec(), decode(&v.messages[0].ciphertext), "NK msg1");

    // msg2: <- e, ee (read the frozen responder message)
    let msg2 = decode(&v.messages[1].ciphertext);
    let (_, recv) = hs.read(&msg2).unwrap().e().await.unwrap();
    let mut transport = recv.ee().await.unwrap();

    assert_eq!(
        transport.session_id().as_ref(),
        decode(&v.handshake_hash),
        "NK handshake hash"
    );

    // transport: initiator -> responder (we produce it)
    let mut ct = [0u8; 256];
    let n = transport.send(TRANSPORT_I2R, &mut ct).unwrap();
    assert_eq!(
        &ct[..n],
        decode(&v.transport[0].ciphertext),
        "NK transport i->r"
    );

    // transport: responder -> initiator (we decrypt the frozen ciphertext)
    let r2i = decode(&v.transport[1].ciphertext);
    let mut pt = [0u8; 256];
    let pn = transport.receive(&r2i, &mut pt).unwrap();
    assert_eq!(&pt[..pn], TRANSPORT_R2I, "NK transport r->i plaintext");
}

// ── Generator (reference: snow) ──────────────────────────────────

#[cfg(test)]
mod generate {
    use super::*;

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
    fn two_message(
        mut init: snow::HandshakeState,
        mut resp: snow::HandshakeState,
    ) -> TwoMessageRun {
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

    fn vector_n() -> Vector {
        let proto = "Noise_N_P256_ChaChaPoly_BLAKE2b";
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
        one_message_vector(proto, Some(hh(&INIT_STATIC)), Some(hh(&PSK_BYTES)), init, resp)
    }

    fn vector_ikpsk1() -> Vector {
        let proto = "Noise_IKpsk1_P256_ChaChaPoly_BLAKE2b";
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
        two_message_vector(proto, Some(hh(&INIT_STATIC)), Some(hh(&PSK_BYTES)), init, resp)
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

    /// Regenerate the frozen vectors from snow. Ignored: run manually with
    /// `cargo test --test noise_kat generate_noise_kat_vectors -- --ignored`.
    #[test]
    #[ignore]
    fn generate_noise_kat_vectors() {
        let file = VectorFile {
            note: "Noise KAT vectors for P256/ChaChaPoly/BLAKE2b, generated \
                   from snow with fixed keys + pinned ephemerals. One-way \
                   patterns freeze msg1 + the initiator->responder transport; \
                   the interactive patterns (IKpsk1, IK, NK) freeze both \
                   messages + both transport directions. \
                   Provenance: agreement with snow (no spec P-256 vectors exist)."
                .to_string(),
            vectors: vec![
                vector_n(),
                vector_k(),
                vector_kpsk0(),
                vector_ikpsk1(),
                vector_ik(),
                vector_nk(),
            ],
        };
        let json = serde_json::to_string_pretty(&file).unwrap();
        std::fs::write(VECTORS_PATH, json + "\n").unwrap();
        eprintln!("wrote {VECTORS_PATH}");
    }
}
