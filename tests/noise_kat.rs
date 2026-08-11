//! Frozen Noise known-answer-test (KAT) vectors.
//!
//! The vectors in `tests/vectors/noise/p256_chachapoly_blake2b.json` are
//! **frozen** byte-for-byte expectations for the seventeen supported patterns
//! (N, K, Kpsk0, IKpsk1, IK, NK, IX, XK, NN, XX, X) over `P256 / ChaChaPoly / BLAKE2b`, produced from
//! the `snow` reference implementation with fixed keys and pinned
//! ephemerals (`generate_noise_kat_vectors`, `#[ignore]`).
//!
//! `tests/vectors/noise/p256_chachapoly_sha256.json` is the same thing over
//! `P256 / ChaChaPoly / SHA256`, for the three patterns the hash choice can
//! reach anything new in — N, IKpsk1 and XX (`generate_noise_kat_sha256_vectors`,
//! `#[ignore]`); it is replayed by [`mod sha256`].
//!
//! [`noise_kat_*`] replay each vector through this crate: a [`ScriptedRng`]
//! injects the recorded ephemeral, statics are set from the recorded key
//! bytes, and every handshake-message ciphertext, the final handshake
//! hash, and the transport ciphertexts must match the frozen bytes. This
//! is the byte-for-byte regression lock; continuous agreement with `snow`
//! is additionally covered by `hiss-interop/tests/snow_interop.rs`.
//!
//! Provenance note: P-256 is not in the Noise spec and no third-party
//! P-256 Noise vectors exist, so these are "agreement with snow", not
//! agreement with a standards body.

mod common;
use common::{ScriptedRng, private_key, public_key};

use hiss::noise::{Blake2b, ChaChaPoly, P256, Sha256};
use hiss::provider::EphemeralOnly;
use hiss::psk::Psk;
use serde::{Deserialize, Serialize};

// One `noise!` declaration per pattern, in the Noise specification's own
// notation — the same token sequences as `src/noise/pattern.rs`, bound here
// to a concrete suite so every handshake message is a fixed-size array whose
// length is a compile-time constant.
hiss::noise! { pub N<P256, ChaChaPoly, Blake2b>      { <- s ... -> e, es } }
hiss::noise! { pub K<P256, ChaChaPoly, Blake2b>      { -> s <- s ... -> e, es, ss } }
hiss::noise! { pub Kpsk0<P256, ChaChaPoly, Blake2b>  { -> s <- s ... -> psk, e, es, ss } }
hiss::noise! { pub IKpsk1<P256, ChaChaPoly, Blake2b> { <- s ... -> e, es, s, ss, psk <- e, ee, se } }
hiss::noise! { pub IK<P256, ChaChaPoly, Blake2b>     { <- s ... -> e, es, s, ss <- e, ee, se } }
hiss::noise! { pub NK<P256, ChaChaPoly, Blake2b>     { <- s ... -> e, es <- e, ee } }
hiss::noise! { pub IX<P256, ChaChaPoly, Blake2b>     { -> e, s <- e, ee, se, s, es } }
hiss::noise! { pub XK<P256, ChaChaPoly, Blake2b>     { <- s ... -> e, es <- e, ee -> s, se } }
hiss::noise! { pub NN<P256, ChaChaPoly, Blake2b>     { -> e <- e, ee } }
hiss::noise! { pub XX<P256, ChaChaPoly, Blake2b>     { -> e <- e, ee, s, es -> s, se } }
hiss::noise! { pub X<P256, ChaChaPoly, Blake2b>      { <- s ... -> e, es, s, ss } }
hiss::noise! { pub NX<P256, ChaChaPoly, Blake2b>     { -> e <- e, ee, s, es } }
hiss::noise! { pub XN<P256, ChaChaPoly, Blake2b>     { -> e <- e, ee -> s, se } }
hiss::noise! { pub KN<P256, ChaChaPoly, Blake2b>     { -> s ... -> e <- e, ee, se } }
hiss::noise! { pub KK<P256, ChaChaPoly, Blake2b>     { -> s <- s ... -> e, es, ss <- e, ee, se } }
hiss::noise! { pub KX<P256, ChaChaPoly, Blake2b>     { -> s ... -> e <- e, ee, se, s, es } }
hiss::noise! { pub IN<P256, ChaChaPoly, Blake2b>     { -> e, s <- e, ee, se } }

// ── Fixed inputs (frozen) ────────────────────────────────────────

const INIT_STATIC: [u8; 32] = [0x11; 32];
const INIT_EPHEMERAL: [u8; 32] = [0x22; 32];
const RESP_STATIC: [u8; 32] = [0x33; 32];
const PSK_BYTES: [u8; 32] = [0x55; 32];

// The responder's ephemeral (`0x44`) is deliberately absent: these replays
// drive the *initiator*, reading the responder's messages from the frozen
// bytes rather than minting them. It lives with the generator that does mint
// it, in `hiss-interop/tests/generate_p256_vectors.rs`.

const TRANSPORT_I2R: &[u8] = b"hiss KAT: initiator -> responder";
const TRANSPORT_R2I: &[u8] = b"hiss KAT: responder -> initiator";

const VECTORS_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/vectors/noise/p256_chachapoly_blake2b.json"
);

const SHA256_VECTORS_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/vectors/noise/p256_chachapoly_sha256.json"
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

/// A frozen responder message, as the fixed-size array the generated reader
/// takes.
///
/// The conversion is itself an assertion: the generated `read_message_N`
/// accepts only `&[u8; MSGn_SIZE]`, so a vector whose length disagrees with
/// the compile-time wire size cannot be replayed at all. Under the old
/// streaming driver a wrong length was a runtime read error; here it is a
/// panic at the boundary, before any crypto runs.
fn frozen<const N: usize>(hex_str: &str) -> [u8; N] {
    decode(hex_str)
        .try_into()
        .expect("frozen message length matches the generated wire size")
}

/// Compare a generated handshake message against its frozen ciphertext.
fn assert_wire<const N: usize>(got: &[u8; N], want_hex: &str, label: &str) {
    assert_eq!(got.as_slice(), decode(want_hex).as_slice(), "{label}");
}

// ── Replay tests (drive this crate's initiator) ──────────────────

#[test]
fn noise_kat_n() {
    let file = load_vectors();
    let v = vector(&file, "Noise_N_P256_ChaChaPoly_BLAKE2b");

    let provider = EphemeralOnly::new(ScriptedRng::new(&[&INIT_EPHEMERAL]));
    // N's one message is also its last, so the writer yields the `Transport`
    // directly rather than a further handshake state.
    let (msg1, mut transport) = N::initiator(provider, &[], public_key(&RESP_STATIC))
        .write_message_1()
        .unwrap();
    assert_wire(&msg1, &v.messages[0].ciphertext, "N msg1");

    assert_eq!(
        transport.session_id().as_ref(),
        decode(&v.handshake_hash),
        "N handshake hash"
    );

    let mut ct = [0u8; 256];
    let n = transport.send(TRANSPORT_I2R, &mut ct).unwrap();
    assert_eq!(
        &ct[..n],
        decode(&v.transport[0].ciphertext),
        "N transport i->r"
    );
}

#[test]
fn noise_kat_k() {
    let file = load_vectors();
    let v = vector(&file, "Noise_K_P256_ChaChaPoly_BLAKE2b");

    let provider = EphemeralOnly::new(ScriptedRng::new(&[&INIT_EPHEMERAL]));
    // Both statics are pre-messages, so they are constructor arguments in
    // pattern order: `-> s` (ours) then `<- s` (theirs).
    let (msg1, mut transport) = K::initiator(
        provider,
        &[],
        private_key(&INIT_STATIC),
        public_key(&RESP_STATIC),
    )
    .unwrap()
    .write_message_1()
    .unwrap();
    assert_wire(&msg1, &v.messages[0].ciphertext, "K msg1");

    assert_eq!(
        transport.session_id().as_ref(),
        decode(&v.handshake_hash),
        "K handshake hash"
    );

    let mut ct = [0u8; 256];
    let n = transport.send(TRANSPORT_I2R, &mut ct).unwrap();
    assert_eq!(
        &ct[..n],
        decode(&v.transport[0].ciphertext),
        "K transport i->r"
    );
}

#[test]
fn noise_kat_kpsk0() {
    let file = load_vectors();
    let v = vector(&file, "Noise_Kpsk0_P256_ChaChaPoly_BLAKE2b");

    let psk = Psk::from_bytes(PSK_BYTES);
    let provider = EphemeralOnly::new(ScriptedRng::new(&[&INIT_EPHEMERAL]));
    // Same pre-messages as K; `psk` is a message token, so it is a writer
    // argument rather than a constructor one.
    let (msg1, mut transport) = Kpsk0::initiator(
        provider,
        &[],
        private_key(&INIT_STATIC),
        public_key(&RESP_STATIC),
    )
    .unwrap()
    .write_message_1(&psk)
    .unwrap();
    assert_wire(&msg1, &v.messages[0].ciphertext, "Kpsk0 msg1");

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

#[test]
fn noise_kat_ikpsk1() {
    let file = load_vectors();
    let v = vector(&file, "Noise_IKpsk1_P256_ChaChaPoly_BLAKE2b");

    let psk = Psk::from_bytes(PSK_BYTES);
    let provider = EphemeralOnly::new(ScriptedRng::new(&[&INIT_EPHEMERAL]));

    // msg1: -> e, es, s, ss, psk — the `s` token makes our static a writer
    // argument, and the `psk` token follows it.
    let (msg1, hs) = IKpsk1::initiator(provider, &[], public_key(&RESP_STATIC))
        .write_message_1(private_key(&INIT_STATIC), &psk)
        .unwrap();
    assert_wire(&msg1, &v.messages[0].ciphertext, "IKpsk1 msg1");

    // msg2: <- e, ee, se — replay the frozen responder message; it is final,
    // so the reader yields the `Transport`.
    let msg2 = frozen(&v.messages[1].ciphertext);
    let mut transport = hs.read_message_2(&msg2).unwrap();

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

#[test]
fn noise_kat_ik() {
    let file = load_vectors();
    let v = vector(&file, "Noise_IK_P256_ChaChaPoly_BLAKE2b");

    let provider = EphemeralOnly::new(ScriptedRng::new(&[&INIT_EPHEMERAL]));

    // msg1: -> e, es, s, ss
    let (msg1, hs) = IK::initiator(provider, &[], public_key(&RESP_STATIC))
        .write_message_1(private_key(&INIT_STATIC))
        .unwrap();
    assert_wire(&msg1, &v.messages[0].ciphertext, "IK msg1");

    // msg2: <- e, ee, se (read the frozen responder message)
    let msg2 = frozen(&v.messages[1].ciphertext);
    let mut transport = hs.read_message_2(&msg2).unwrap();

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

#[test]
fn noise_kat_nk() {
    let file = load_vectors();
    let v = vector(&file, "Noise_NK_P256_ChaChaPoly_BLAKE2b");

    let provider = EphemeralOnly::new(ScriptedRng::new(&[&INIT_EPHEMERAL]));
    // NK's initiator is anonymous: it has no static of its own, only the
    // responder's public key as a pre-message.
    let (msg1, hs) = NK::initiator(provider, &[], public_key(&RESP_STATIC))
        .write_message_1()
        .unwrap();
    assert_wire(&msg1, &v.messages[0].ciphertext, "NK msg1");

    // msg2: <- e, ee (read the frozen responder message)
    let msg2 = frozen(&v.messages[1].ciphertext);
    let mut transport = hs.read_message_2(&msg2).unwrap();

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

#[test]
fn noise_kat_ix() {
    let file = load_vectors();
    let v = vector(&file, "Noise_IX_P256_ChaChaPoly_BLAKE2b");

    let provider = EphemeralOnly::new(ScriptedRng::new(&[&INIT_EPHEMERAL]));
    // IX has no pre-messages, so the constructor takes none and is
    // infallible; the initiator transmits its static in msg1's `s` token.
    let (msg1, hs) = IX::initiator(provider, &[])
        .write_message_1(private_key(&INIT_STATIC))
        .unwrap();
    assert_wire(&msg1, &v.messages[0].ciphertext, "IX msg1");

    // msg2: <- e, ee, se, s, es — final, and its `s` token reveals the
    // responder's static, which survives onto the transport.
    let msg2 = frozen(&v.messages[1].ciphertext);
    let mut transport = hs.read_message_2(&msg2).unwrap();
    assert_eq!(
        transport.remote_static().unwrap().to_bytes(),
        public_key(&RESP_STATIC).to_bytes(),
        "IX revealed responder static"
    );

    assert_eq!(
        transport.session_id().as_ref(),
        decode(&v.handshake_hash),
        "IX handshake hash"
    );

    // transport: initiator -> responder (we produce it)
    let mut ct = [0u8; 256];
    let n = transport.send(TRANSPORT_I2R, &mut ct).unwrap();
    assert_eq!(
        &ct[..n],
        decode(&v.transport[0].ciphertext),
        "IX transport i->r"
    );

    // transport: responder -> initiator (we decrypt the frozen ciphertext)
    let r2i = decode(&v.transport[1].ciphertext);
    let mut pt = [0u8; 256];
    let pn = transport.receive(&r2i, &mut pt).unwrap();
    assert_eq!(&pt[..pn], TRANSPORT_R2I, "IX transport r->i plaintext");
}

#[test]
fn noise_kat_xk() {
    let file = load_vectors();
    let v = vector(&file, "Noise_XK_P256_ChaChaPoly_BLAKE2b");

    let provider = EphemeralOnly::new(ScriptedRng::new(&[&INIT_EPHEMERAL]));
    // XK pre-message `<- s`: the initiator pre-knows the responder static.
    let (msg1, hs) = XK::initiator(provider, &[], public_key(&RESP_STATIC))
        .write_message_1()
        .unwrap();
    assert_wire(&msg1, &v.messages[0].ciphertext, "XK msg1");

    // msg2: <- e, ee (read the frozen responder message)
    let msg2 = frozen(&v.messages[1].ciphertext);
    let hs = hs.read_message_2(&msg2).unwrap();

    // msg3: -> s, se — the initiator's static goes out encrypted (after ee).
    let (msg3, mut transport) = hs.write_message_3(private_key(&INIT_STATIC)).unwrap();
    assert_wire(&msg3, &v.messages[2].ciphertext, "XK msg3");

    assert_eq!(
        transport.session_id().as_ref(),
        decode(&v.handshake_hash),
        "XK handshake hash"
    );

    // transport: initiator -> responder (we produce it)
    let mut ct = [0u8; 256];
    let n = transport.send(TRANSPORT_I2R, &mut ct).unwrap();
    assert_eq!(
        &ct[..n],
        decode(&v.transport[0].ciphertext),
        "XK transport i->r"
    );

    // transport: responder -> initiator (we decrypt the frozen ciphertext)
    let r2i = decode(&v.transport[1].ciphertext);
    let mut pt = [0u8; 256];
    let pn = transport.receive(&r2i, &mut pt).unwrap();
    assert_eq!(&pt[..pn], TRANSPORT_R2I, "XK transport r->i plaintext");
}

#[test]
fn noise_kat_nn() {
    let file = load_vectors();
    let v = vector(&file, "Noise_NN_P256_ChaChaPoly_BLAKE2b");

    let provider = EphemeralOnly::new(ScriptedRng::new(&[&INIT_EPHEMERAL]));
    // NN: both parties anonymous — no static keys, no pre-messages.
    let (msg1, hs) = NN::initiator(provider, &[]).write_message_1().unwrap();
    assert_wire(&msg1, &v.messages[0].ciphertext, "NN msg1");

    // msg2: <- e, ee (read the frozen responder message)
    let msg2 = frozen(&v.messages[1].ciphertext);
    let mut transport = hs.read_message_2(&msg2).unwrap();

    assert_eq!(
        transport.session_id().as_ref(),
        decode(&v.handshake_hash),
        "NN handshake hash"
    );

    // transport: initiator -> responder (we produce it)
    let mut ct = [0u8; 256];
    let n = transport.send(TRANSPORT_I2R, &mut ct).unwrap();
    assert_eq!(
        &ct[..n],
        decode(&v.transport[0].ciphertext),
        "NN transport i->r"
    );

    // transport: responder -> initiator (we decrypt the frozen ciphertext)
    let r2i = decode(&v.transport[1].ciphertext);
    let mut pt = [0u8; 256];
    let pn = transport.receive(&r2i, &mut pt).unwrap();
    assert_eq!(&pt[..pn], TRANSPORT_R2I, "NN transport r->i plaintext");
}

#[test]
fn noise_kat_xx() {
    let file = load_vectors();
    let v = vector(&file, "Noise_XX_P256_ChaChaPoly_BLAKE2b");

    let provider = EphemeralOnly::new(ScriptedRng::new(&[&INIT_EPHEMERAL]));
    // XX has no pre-messages: both parties transmit their statics
    // in-handshake, encrypted, after `ee`.
    let (msg1, hs) = XX::initiator(provider, &[]).write_message_1().unwrap();
    assert_wire(&msg1, &v.messages[0].ciphertext, "XX msg1");

    // msg2: <- e, ee, s, es — the `s` token reveals the responder's static.
    let msg2 = frozen(&v.messages[1].ciphertext);
    let hs = hs.read_message_2(&msg2).unwrap();
    assert_eq!(
        hs.remote_static().to_bytes(),
        public_key(&RESP_STATIC).to_bytes(),
        "XX revealed responder static"
    );

    // msg3: -> s, se — the initiator's static goes out encrypted (after ee).
    let (msg3, mut transport) = hs.write_message_3(private_key(&INIT_STATIC)).unwrap();
    assert_wire(&msg3, &v.messages[2].ciphertext, "XX msg3");

    assert_eq!(
        transport.session_id().as_ref(),
        decode(&v.handshake_hash),
        "XX handshake hash"
    );

    // transport: initiator -> responder (we produce it)
    let mut ct = [0u8; 256];
    let n = transport.send(TRANSPORT_I2R, &mut ct).unwrap();
    assert_eq!(
        &ct[..n],
        decode(&v.transport[0].ciphertext),
        "XX transport i->r"
    );

    // transport: responder -> initiator (we decrypt the frozen ciphertext)
    let r2i = decode(&v.transport[1].ciphertext);
    let mut pt = [0u8; 256];
    let pn = transport.receive(&r2i, &mut pt).unwrap();
    assert_eq!(&pt[..pn], TRANSPORT_R2I, "XX transport r->i plaintext");
}

#[test]
fn noise_kat_x() {
    let file = load_vectors();
    let v = vector(&file, "Noise_X_P256_ChaChaPoly_BLAKE2b");

    let provider = EphemeralOnly::new(ScriptedRng::new(&[&INIT_EPHEMERAL]));
    // X pre-message `<- s`: the initiator pre-knows the responder static and
    // transmits its own in msg1's `s` token — IK's msg1 with no reply.
    let (msg1, mut transport) = X::initiator(provider, &[], public_key(&RESP_STATIC))
        .write_message_1(private_key(&INIT_STATIC))
        .unwrap();
    assert_wire(&msg1, &v.messages[0].ciphertext, "X msg1");

    assert_eq!(
        transport.session_id().as_ref(),
        decode(&v.handshake_hash),
        "X handshake hash"
    );

    let mut ct = [0u8; 256];
    let n = transport.send(TRANSPORT_I2R, &mut ct).unwrap();
    assert_eq!(
        &ct[..n],
        decode(&v.transport[0].ciphertext),
        "X transport i->r"
    );
}

#[test]
fn noise_kat_nx() {
    let file = load_vectors();
    let v = vector(&file, "Noise_NX_P256_ChaChaPoly_BLAKE2b");

    let provider = EphemeralOnly::new(ScriptedRng::new(&[&INIT_EPHEMERAL]));
    // NX: no pre-messages and an anonymous initiator, so the constructor
    // takes nothing but a provider and the prologue.
    let (msg1, hs) = NX::initiator(provider, &[]).write_message_1().unwrap();
    assert_wire(&msg1, &v.messages[0].ciphertext, "NX msg1");

    // msg2: <- e, ee, s, es — final, and its `s` reveals the responder's
    // static onto the transport.
    let msg2 = frozen(&v.messages[1].ciphertext);
    let mut transport = hs.read_message_2(&msg2).unwrap();
    assert_eq!(
        transport.remote_static().unwrap().to_bytes(),
        public_key(&RESP_STATIC).to_bytes(),
        "NX revealed responder static"
    );

    assert_eq!(
        transport.session_id().as_ref(),
        decode(&v.handshake_hash),
        "NX handshake hash"
    );

    let mut ct = [0u8; 256];
    let n = transport.send(TRANSPORT_I2R, &mut ct).unwrap();
    assert_eq!(
        &ct[..n],
        decode(&v.transport[0].ciphertext),
        "NX transport i->r"
    );

    let r2i = decode(&v.transport[1].ciphertext);
    let mut pt = [0u8; 256];
    let pn = transport.receive(&r2i, &mut pt).unwrap();
    assert_eq!(&pt[..pn], TRANSPORT_R2I, "NX transport r->i plaintext");
}

#[test]
fn noise_kat_xn() {
    let file = load_vectors();
    let v = vector(&file, "Noise_XN_P256_ChaChaPoly_BLAKE2b");

    let provider = EphemeralOnly::new(ScriptedRng::new(&[&INIT_EPHEMERAL]));
    // XN: three messages, and the responder is anonymous — the only static
    // on the wire is ours, sent encrypted in msg3.
    let (msg1, hs) = XN::initiator(provider, &[]).write_message_1().unwrap();
    assert_wire(&msg1, &v.messages[0].ciphertext, "XN msg1");

    let msg2 = frozen(&v.messages[1].ciphertext);
    let hs = hs.read_message_2(&msg2).unwrap();

    let (msg3, mut transport) = hs.write_message_3(private_key(&INIT_STATIC)).unwrap();
    assert_wire(&msg3, &v.messages[2].ciphertext, "XN msg3");

    assert_eq!(
        transport.session_id().as_ref(),
        decode(&v.handshake_hash),
        "XN handshake hash"
    );

    let mut ct = [0u8; 256];
    let n = transport.send(TRANSPORT_I2R, &mut ct).unwrap();
    assert_eq!(
        &ct[..n],
        decode(&v.transport[0].ciphertext),
        "XN transport i->r"
    );

    let r2i = decode(&v.transport[1].ciphertext);
    let mut pt = [0u8; 256];
    let pn = transport.receive(&r2i, &mut pt).unwrap();
    assert_eq!(&pt[..pn], TRANSPORT_R2I, "XN transport r->i plaintext");
}

#[test]
fn noise_kat_kn() {
    let file = load_vectors();
    let v = vector(&file, "Noise_KN_P256_ChaChaPoly_BLAKE2b");

    let provider = EphemeralOnly::new(ScriptedRng::new(&[&INIT_EPHEMERAL]));
    // KN pre-message `-> s`: our own static is pre-shared, so it is a
    // constructor argument and nothing identifying rides the wire.
    let (msg1, hs) = KN::initiator(provider, &[], private_key(&INIT_STATIC))
        .unwrap()
        .write_message_1()
        .unwrap();
    assert_wire(&msg1, &v.messages[0].ciphertext, "KN msg1");

    let msg2 = frozen(&v.messages[1].ciphertext);
    let mut transport = hs.read_message_2(&msg2).unwrap();

    assert_eq!(
        transport.session_id().as_ref(),
        decode(&v.handshake_hash),
        "KN handshake hash"
    );

    let mut ct = [0u8; 256];
    let n = transport.send(TRANSPORT_I2R, &mut ct).unwrap();
    assert_eq!(
        &ct[..n],
        decode(&v.transport[0].ciphertext),
        "KN transport i->r"
    );

    let r2i = decode(&v.transport[1].ciphertext);
    let mut pt = [0u8; 256];
    let pn = transport.receive(&r2i, &mut pt).unwrap();
    assert_eq!(&pt[..pn], TRANSPORT_R2I, "KN transport r->i plaintext");
}

#[test]
fn noise_kat_kk() {
    let file = load_vectors();
    let v = vector(&file, "Noise_KK_P256_ChaChaPoly_BLAKE2b");

    let provider = EphemeralOnly::new(ScriptedRng::new(&[&INIT_EPHEMERAL]));
    // KK: both statics are pre-messages, in pattern order — `-> s` (ours)
    // then `<- s` (theirs). msg1's payload is already encrypted.
    let (msg1, hs) = KK::initiator(
        provider,
        &[],
        private_key(&INIT_STATIC),
        public_key(&RESP_STATIC),
    )
    .unwrap()
    .write_message_1()
    .unwrap();
    assert_wire(&msg1, &v.messages[0].ciphertext, "KK msg1");

    let msg2 = frozen(&v.messages[1].ciphertext);
    let mut transport = hs.read_message_2(&msg2).unwrap();

    assert_eq!(
        transport.session_id().as_ref(),
        decode(&v.handshake_hash),
        "KK handshake hash"
    );

    let mut ct = [0u8; 256];
    let n = transport.send(TRANSPORT_I2R, &mut ct).unwrap();
    assert_eq!(
        &ct[..n],
        decode(&v.transport[0].ciphertext),
        "KK transport i->r"
    );

    let r2i = decode(&v.transport[1].ciphertext);
    let mut pt = [0u8; 256];
    let pn = transport.receive(&r2i, &mut pt).unwrap();
    assert_eq!(&pt[..pn], TRANSPORT_R2I, "KK transport r->i plaintext");
}

#[test]
fn noise_kat_kx() {
    let file = load_vectors();
    let v = vector(&file, "Noise_KX_P256_ChaChaPoly_BLAKE2b");

    let provider = EphemeralOnly::new(ScriptedRng::new(&[&INIT_EPHEMERAL]));
    // KX: our static pre-shared as in KN, theirs revealed encrypted in msg2.
    let (msg1, hs) = KX::initiator(provider, &[], private_key(&INIT_STATIC))
        .unwrap()
        .write_message_1()
        .unwrap();
    assert_wire(&msg1, &v.messages[0].ciphertext, "KX msg1");

    let msg2 = frozen(&v.messages[1].ciphertext);
    let mut transport = hs.read_message_2(&msg2).unwrap();
    assert_eq!(
        transport.remote_static().unwrap().to_bytes(),
        public_key(&RESP_STATIC).to_bytes(),
        "KX revealed responder static"
    );

    assert_eq!(
        transport.session_id().as_ref(),
        decode(&v.handshake_hash),
        "KX handshake hash"
    );

    let mut ct = [0u8; 256];
    let n = transport.send(TRANSPORT_I2R, &mut ct).unwrap();
    assert_eq!(
        &ct[..n],
        decode(&v.transport[0].ciphertext),
        "KX transport i->r"
    );

    let r2i = decode(&v.transport[1].ciphertext);
    let mut pt = [0u8; 256];
    let pn = transport.receive(&r2i, &mut pt).unwrap();
    assert_eq!(&pt[..pn], TRANSPORT_R2I, "KX transport r->i plaintext");
}

#[test]
fn noise_kat_in() {
    let file = load_vectors();
    let v = vector(&file, "Noise_IN_P256_ChaChaPoly_BLAKE2b");

    let provider = EphemeralOnly::new(ScriptedRng::new(&[&INIT_EPHEMERAL]));
    // IN: no pre-messages, so the constructor is infallible; the `s` token
    // makes our static a writer argument, and it travels in the clear.
    let (msg1, hs) = IN::initiator(provider, &[])
        .write_message_1(private_key(&INIT_STATIC))
        .unwrap();
    assert_wire(&msg1, &v.messages[0].ciphertext, "IN msg1");

    let msg2 = frozen(&v.messages[1].ciphertext);
    let mut transport = hs.read_message_2(&msg2).unwrap();

    assert_eq!(
        transport.session_id().as_ref(),
        decode(&v.handshake_hash),
        "IN handshake hash"
    );

    let mut ct = [0u8; 256];
    let n = transport.send(TRANSPORT_I2R, &mut ct).unwrap();
    assert_eq!(
        &ct[..n],
        decode(&v.transport[0].ciphertext),
        "IN transport i->r"
    );

    let r2i = decode(&v.transport[1].ciphertext);
    let mut pt = [0u8; 256];
    let pn = transport.receive(&r2i, &mut pt).unwrap();
    assert_eq!(&pt[..pn], TRANSPORT_R2I, "IN transport r->i plaintext");
}

// ── SHA-256 replay tests ─────────────────────────────────────────

/// The same replay, over `P256 / ChaChaPoly / SHA256`.
///
/// A module rather than three more file-scope declarations: the pattern
/// identifier *is* `Pattern::NAME` and reaches the protocol name, so these
/// have to keep the names `N`, `XX` and `IKpsk1` and cannot sit alongside
/// their BLAKE2b twins.
///
/// Three patterns, not seventeen. The token sequences are hash-independent and
/// already frozen by the BLAKE2b corpus; what varies with the hash is
/// HKDF-2 (`N`), `split` plus both transport directions (`XX`), and HKDF-3
/// via the PSK (`IKpsk1`). `IKpsk1` earns its place twice over: at HASHLEN
/// 32 its 35-byte protocol name is the only one in this crate that exceeds
/// HASHLEN, so it is the only oracle-checked run of the hashing branch of
/// `SymmetricState::initialize`.
mod sha256 {
    use super::*;

    hiss::noise! { pub N<P256, ChaChaPoly, Sha256>      { <- s ... -> e, es } }
    hiss::noise! { pub IKpsk1<P256, ChaChaPoly, Sha256> { <- s ... -> e, es, s, ss, psk <- e, ee, se } }
    hiss::noise! { pub XX<P256, ChaChaPoly, Sha256>     { -> e <- e, ee, s, es -> s, se } }

    fn load() -> VectorFile {
        let raw = std::fs::read_to_string(SHA256_VECTORS_PATH).unwrap_or_else(|e| {
            panic!(
                "missing {SHA256_VECTORS_PATH}: run `cargo test --test noise_kat \
                 generate_noise_kat_sha256_vectors -- --ignored` first ({e})"
            )
        });
        serde_json::from_str(&raw).expect("valid noise KAT json")
    }

    #[test]
    fn noise_kat_sha256_n() {
        let file = load();
        let v = vector(&file, "Noise_N_P256_ChaChaPoly_SHA256");

        let provider = EphemeralOnly::new(ScriptedRng::new(&[&INIT_EPHEMERAL]));
        let (msg1, mut transport) = N::initiator(provider, &[], public_key(&RESP_STATIC))
            .write_message_1()
            .unwrap();
        assert_wire(&msg1, &v.messages[0].ciphertext, "N/SHA256 msg1");

        // 32 bytes here, where the BLAKE2b twin sees 64.
        assert_eq!(
            transport.session_id().as_ref(),
            decode(&v.handshake_hash),
            "N/SHA256 handshake hash"
        );

        let mut ct = [0u8; 256];
        let n = transport.send(TRANSPORT_I2R, &mut ct).unwrap();
        assert_eq!(
            &ct[..n],
            decode(&v.transport[0].ciphertext),
            "N/SHA256 transport i->r"
        );
    }

    #[test]
    fn noise_kat_sha256_ikpsk1() {
        let file = load();
        // 35 bytes: the one protocol name in this crate that exceeds its
        // HASHLEN, so the frozen bytes below are what pins the hashing
        // branch of `SymmetricState::initialize` against snow.
        let v = vector(&file, "Noise_IKpsk1_P256_ChaChaPoly_SHA256");

        let psk = Psk::from_bytes(PSK_BYTES);
        let provider = EphemeralOnly::new(ScriptedRng::new(&[&INIT_EPHEMERAL]));

        // msg1: -> e, es, s, ss, psk
        let (msg1, hs) = IKpsk1::initiator(provider, &[], public_key(&RESP_STATIC))
            .write_message_1(private_key(&INIT_STATIC), &psk)
            .unwrap();
        assert_wire(&msg1, &v.messages[0].ciphertext, "IKpsk1/SHA256 msg1");

        // msg2: <- e, ee, se — final, so the reader yields the `Transport`.
        let msg2 = frozen(&v.messages[1].ciphertext);
        let mut transport = hs.read_message_2(&msg2).unwrap();

        assert_eq!(
            transport.session_id().as_ref(),
            decode(&v.handshake_hash),
            "IKpsk1/SHA256 handshake hash"
        );

        let mut ct = [0u8; 256];
        let n = transport.send(TRANSPORT_I2R, &mut ct).unwrap();
        assert_eq!(
            &ct[..n],
            decode(&v.transport[0].ciphertext),
            "IKpsk1/SHA256 transport i->r"
        );

        let r2i = decode(&v.transport[1].ciphertext);
        let mut pt = [0u8; 256];
        let pn = transport.receive(&r2i, &mut pt).unwrap();
        assert_eq!(
            &pt[..pn],
            TRANSPORT_R2I,
            "IKpsk1/SHA256 transport r->i plaintext"
        );
    }

    #[test]
    fn noise_kat_sha256_xx() {
        let file = load();
        let v = vector(&file, "Noise_XX_P256_ChaChaPoly_SHA256");

        let provider = EphemeralOnly::new(ScriptedRng::new(&[&INIT_EPHEMERAL]));
        let (msg1, hs) = XX::initiator(provider, &[]).write_message_1().unwrap();
        assert_wire(&msg1, &v.messages[0].ciphertext, "XX/SHA256 msg1");

        // msg2: <- e, ee, s, es — the `s` token reveals the responder's static.
        let msg2 = frozen(&v.messages[1].ciphertext);
        let hs = hs.read_message_2(&msg2).unwrap();
        assert_eq!(
            hs.remote_static().to_bytes(),
            public_key(&RESP_STATIC).to_bytes(),
            "XX/SHA256 revealed responder static"
        );

        // msg3: -> s, se
        let (msg3, mut transport) = hs.write_message_3(private_key(&INIT_STATIC)).unwrap();
        assert_wire(&msg3, &v.messages[2].ciphertext, "XX/SHA256 msg3");

        assert_eq!(
            transport.session_id().as_ref(),
            decode(&v.handshake_hash),
            "XX/SHA256 handshake hash"
        );

        let mut ct = [0u8; 256];
        let n = transport.send(TRANSPORT_I2R, &mut ct).unwrap();
        assert_eq!(
            &ct[..n],
            decode(&v.transport[0].ciphertext),
            "XX/SHA256 transport i->r"
        );

        let r2i = decode(&v.transport[1].ciphertext);
        let mut pt = [0u8; 256];
        let pn = transport.receive(&r2i, &mut pt).unwrap();
        assert_eq!(
            &pt[..pn],
            TRANSPORT_R2I,
            "XX/SHA256 transport r->i plaintext"
        );
    }
}
