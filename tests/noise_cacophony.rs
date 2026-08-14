//! Frozen **third-party** Noise known-answer-test (KAT) vectors, from the
//! `cacophony` corpus.
//!
//! `tests/vectors/cacophony/cacophony.json` is a 160-vector subset of a
//! 944-vector community corpus that neither hiss nor `snow` produced —
//! acquired from the `snow` 0.10.0 crate package and byte-identical to the
//! copy in the Cacophony Haskell implementation's own repository. See
//! `tests/vectors/cacophony/PROVENANCE.md` for the pins, the filter, and the
//! licence chain.
//!
//! This file is deliberately **separate** from `tests/noise_kat.rs`, which
//! holds the frozen `P256` vectors. Those are agreement-with-`snow` by
//! necessity — P-256 is not in the Noise specification and no third-party
//! P-256 Noise vectors exist. These are agreement with an implementation that
//! is not `snow`, on a corpus neither project generated, and they are the only
//! cross-implementation check X448 has at all: `snow`'s default resolver
//! returns `None` for `448`, so `snow`'s own harness skips every `448` vector
//! it ships.
//!
//! The schema below is cacophony's own, not hiss's. That is the point: the
//! vendored entries are `jq`-comparable to the upstream file entry for entry,
//! with no conversion step whose transcription bugs would silently weaken the
//! KAT.
//!
//! # Shape
//!
//! 160 initiator replays and 160 responder replays — every one of the
//! seventeen patterns hiss implements plus the three psk-placement variants
//! `NNpsk0`, `NNpsk2` and `XXpsk3`, in **both roles**, over
//! `{25519, 448} × ChaChaPoly × {BLAKE2b, BLAKE2s, SHA256, SHA512}`, for 320
//! tests. With `Kpsk0` and `IKpsk1`, every position a `pskN` modifier can
//! name — psk0 through psk3 — has a third-party-pinned representative;
//! there is no psk4 to pin, because no fundamental pattern has a fourth
//! message.
//!
//! The two roles do not buy the same thing, and the split is worth stating.
//! The thirteen interactive patterns have a responder-**written** message, so
//! their responder replay pins those bytes against the corpus. The four
//! one-way patterns (`N`, `K`, `Kpsk0`, `X`) have none, so theirs adds no
//! wire-byte assertion — what it pins is the recipient **read** path: msg1
//! with its pre-message key schedule driven from the responder's side, the
//! recovered payload, `X`'s revealed initiator static, and five transport
//! `receive`s. For X448 nothing else in the tree covers that path.
//!
//! Each replay asserts, per vector:
//!
//! 1. every outbound handshake message equals the frozen ciphertext
//!    byte-for-byte;
//! 2. every inbound handshake message decrypts to the vector's payload
//!    (cacophony's payloads are non-empty on all six messages, so every
//!    handshake message carries a declared `[N]` application payload);
//! 3. where a read reveals the peer's static, `remote_static()` equals the
//!    public key derived from the recorded private scalar;
//! 4. `session_id()` equals `handshake_hash` — **stricter than `snow`**,
//!    whose `TestVector` does not declare that field at all, so serde drops
//!    it before its harness ever sees it;
//! 5. every transport message, in order and in the direction the corpus
//!    gives it — which for the one-way patterns (`N`, `K`, `Kpsk0`, `X`) is
//!    five consecutive initiator→responder messages, exercising transport
//!    nonces 0..4 in one direction.
//!
//! # What this does not prove
//!
//! hiss did not audit the Cacophony implementation, and `snow`'s package
//! documents no provenance for the file at all. What these vectors buy is
//! agreement with a *second, independent* implementation — not vectors from a
//! standards body.
//!
//! These replays also call only the plain readers. The `read_message_N_with`
//! per-peer-PSK and verification-closure variants are never exercised against
//! third-party vectors; they are covered elsewhere
//! (`tests/noise_macro_shapes.rs`, and the walkthroughs
//! `scripts/downstream-build.sh` compiles) but not here.

mod common;
use common::ScriptedRng;

use hiss::curve::x448::SoftwareX448PrivateKey;
use hiss::curve::x25519::SoftwareX25519PrivateKey;
use hiss::noise::{
    Blake2b, Blake2s, ChaChaPoly, Curve, Protocol, Sha256, Sha512, Transport, X448, X25519,
};
use hiss::provider::EphemeralOnly;
use hiss::psk::Psk;
use serde::{Deserialize, Serialize};

const VECTORS_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/vectors/cacophony/cacophony.json"
);

/// The payload byte-length of each of a vector's six messages.
///
/// Fixed by message *index* across the whole corpus, which is what lets the
/// `noise!` declarations below spell `[16]`, `[15]` and `[11]` uniformly
/// across all twenty patterns.
const PAYLOAD_LENS: [usize; 6] = [16, 15, 11, 11, 17, 21];

// ── Vector schema (cacophony's own) ──────────────────────────────

/// Upstream's top level is an object, not a bare array.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct VectorFile {
    vectors: Vec<Vector>,
}

/// The thirteen keys the corpus actually uses.
///
/// `deny_unknown_fields` is stricter than `snow`'s deserializer, which
/// declares seventeen fields (five of them absent from every entry) and
/// silently drops `handshake_hash`. A refresh that introduces a new key —
/// a hybrid suite, a fallback pattern — fails here loudly rather than
/// quietly replaying less than it claims to.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Vector {
    protocol_name: String,
    init_prologue: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    init_psks: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    init_static: Option<String>,
    init_ephemeral: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    init_remote_static: Option<String>,
    resp_prologue: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    resp_psks: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    resp_static: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    resp_ephemeral: Option<String>,
    /// Present on 272 of the upstream 944 and unused by an initiator replay;
    /// retained so the vendored entries stay byte-comparable to upstream.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    resp_remote_static: Option<String>,
    handshake_hash: String,
    /// Six per vector: the pattern's handshake messages followed by
    /// transport messages, split positionally.
    messages: Vec<Message>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Message {
    payload: String,
    ciphertext: String,
}

// ── Helpers ──────────────────────────────────────────────────────

fn load() -> VectorFile {
    let raw = std::fs::read_to_string(VECTORS_PATH).unwrap_or_else(|e| {
        panic!(
            "missing {VECTORS_PATH}: run `CACOPHONY_SRC=… cargo test --all-features \
             --test noise_cacophony extract_cacophony_subset -- --ignored` first ({e})"
        )
    });
    serde_json::from_str(&raw).expect("valid cacophony json")
}

fn vector<'a>(file: &'a VectorFile, protocol_name: &str) -> &'a Vector {
    file.vectors
        .iter()
        .find(|v| v.protocol_name == protocol_name)
        .unwrap_or_else(|| panic!("no vector for {protocol_name}"))
}

/// Look a vector up and check the data invariants every replay relies on.
fn load_vector<'a>(file: &'a VectorFile, protocol_name: &str) -> &'a Vector {
    let v = vector(file, protocol_name);
    check_invariants(v);
    v
}

fn decode(hex_str: &str) -> Vec<u8> {
    hex::decode(hex_str).expect("hex")
}

/// A frozen peer message, as the fixed-size array the generated reader takes.
///
/// The conversion is itself an assertion: `read_message_N` accepts only
/// `&[u8; MSGn_SIZE]`, so a vector whose length disagrees with the
/// compile-time wire size cannot be replayed at all.
fn frozen<const N: usize>(hex_str: &str) -> [u8; N] {
    decode(hex_str)
        .try_into()
        .expect("frozen message length matches the generated wire size")
}

/// A declared `[N]` application payload, as the array the generated writer
/// takes and the generated reader returns.
fn payload<const N: usize>(hex_str: &str) -> [u8; N] {
    decode(hex_str)
        .try_into()
        .expect("payload length matches the declared size")
}

/// Compare a generated handshake message against its frozen ciphertext.
fn assert_wire<const N: usize>(got: &[u8; N], want_hex: &str, label: &str) {
    assert_eq!(got.as_slice(), decode(want_hex).as_slice(), "{label}");
}

/// The prologue both parties mix in — one fixed value across the corpus,
/// `"John Galt"`, and non-empty, unlike hiss's own frozen vectors.
fn prologue(v: &Vector) -> Vec<u8> {
    decode(&v.init_prologue)
}

/// The vector's single 32-byte pre-shared key.
fn psk(v: &Vector) -> Psk {
    let psks = v.init_psks.as_ref().expect("pattern has a psk modifier");
    Psk::from_bytes(decode(&psks[0]).try_into().expect("psk is 32 bytes"))
}

/// The provider for a **one-way pattern's responder**, scripted with nothing.
///
/// A one-way pattern has no `<-` message, so its responder has no `e` token
/// and draws no randomness at all — which is why the corpus carries no
/// `resp_ephemeral` for `N`, `K`, `Kpsk0` or `X` (0 of 8 suites each,
/// counted). The empty script turns that absence into a positive assertion:
/// [`ScriptedRng`] panics the moment anything is drawn, so a change that made
/// a one-way recipient generate a key fails loudly here instead of silently
/// diverging from the frozen bytes.
fn oneway_resp_provider() -> EphemeralOnly<ScriptedRng> {
    EphemeralOnly::new(ScriptedRng::new(&[]))
}

fn assert_session_id<P: Protocol>(t: &Transport<P>, v: &Vector) {
    assert_eq!(
        t.session_id().as_ref(),
        decode(&v.handshake_hash),
        "{} handshake hash",
        v.protocol_name
    );
}

/// Which side of the recorded exchange a replay is driving.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Side {
    Initiator,
    Responder,
}

/// Replay every transport message from index `first` onward.
///
/// Direction follows `snow`'s own driver: for interactive patterns the
/// sender alternates by index parity, and for one-way patterns every
/// transport message is initiator→responder.
fn replay_transport<P: Protocol>(
    t: &mut Transport<P>,
    v: &Vector,
    first: usize,
    one_way: bool,
    side: Side,
) {
    for (i, m) in v.messages.iter().enumerate().skip(first) {
        let sender_is_initiator = one_way || i % 2 == 0;
        let we_send = sender_is_initiator == (side == Side::Initiator);
        let want = decode(&m.ciphertext);
        let plain = decode(&m.payload);
        let mut buf = [0u8; 256];
        if we_send {
            let n = t.send(&plain, &mut buf).unwrap();
            assert_eq!(
                &buf[..n],
                want.as_slice(),
                "{} transport message {i} (sent)",
                v.protocol_name
            );
        } else {
            let n = t.receive(&want, &mut buf).unwrap();
            assert_eq!(
                &buf[..n],
                plain.as_slice(),
                "{} transport message {i} (received)",
                v.protocol_name
            );
        }
    }
}

/// Assert the properties of the *vendored data* that every replay below
/// relies on, so a bad refresh fails here rather than as a misleading crypto
/// failure two hundred lines later.
fn check_invariants(v: &Vector) {
    let name = &v.protocol_name;
    assert_eq!(v.messages.len(), 6, "{name}: six messages per vector");
    assert_eq!(
        v.init_prologue, v.resp_prologue,
        "{name}: both parties share one prologue"
    );
    match (&v.init_psks, &v.resp_psks) {
        (Some(i), Some(r)) => {
            assert_eq!(i, r, "{name}: both parties share one psk list");
            assert_eq!(i.len(), 1, "{name}: exactly one psk (no `psk2` spellings)");
            assert_eq!(decode(&i[0]).len(), 32, "{name}: psk is 32 bytes");
        }
        (None, None) => {}
        _ => panic!("{name}: psks present on one side only"),
    }
    for (i, m) in v.messages.iter().enumerate() {
        assert_eq!(
            decode(&m.payload).len(),
            PAYLOAD_LENS[i],
            "{name}: message {i} payload length"
        );
    }
}

// ── Per-suite replays ────────────────────────────────────────────

/// The twenty patterns and their replays, instantiated once per suite.
///
/// A `macro_rules!` rather than three hundred and twenty hand-written
/// bodies: the
/// declarations and the replay logic are hash- and curve-independent, so
/// writing them once and substituting the suite is the only way the full
/// cross product costs one line per cell.
///
/// `$curve` and `$hash` are `ident` fragments, not `ty`: a `ty` fragment
/// substitutes as an opaque `None`-delimited group, which `hiss-macros`'
/// `syn::Path` parse of the suite would reject. `$sk` is a `ty` because it is
/// only ever used in expression position.
///
/// The generated types are module-local, so the pattern identifiers stay
/// `N`/`XX`/… — which they must, since the identifier *is* `Pattern::NAME`
/// and reaches the protocol name that is mixed into the initial handshake
/// hash.
macro_rules! cacophony_suite {
    ($module:ident, $curve:ident, $sk:ty, $hash:ident, $suite:literal) => {
        pub mod $module {
            use super::*;

            // Every handshake message carries a payload, because every
            // cacophony message does; the lengths are fixed by message index
            // across the whole corpus (16, 15, 11).
            hiss::noise! { pub N<$curve, ChaChaPoly, $hash>      { <- s ... -> e, es [16] } }
            hiss::noise! { pub K<$curve, ChaChaPoly, $hash>      { -> s <- s ... -> e, es, ss [16] } }
            hiss::noise! { pub Kpsk0<$curve, ChaChaPoly, $hash>  { -> s <- s ... -> psk, e, es, ss [16] } }
            hiss::noise! { pub IKpsk1<$curve, ChaChaPoly, $hash> { <- s ... -> e, es, s, ss, psk [16] <- e, ee, se [15] } }
            hiss::noise! { pub IK<$curve, ChaChaPoly, $hash>     { <- s ... -> e, es, s, ss [16] <- e, ee, se [15] } }
            hiss::noise! { pub NK<$curve, ChaChaPoly, $hash>     { <- s ... -> e, es [16] <- e, ee [15] } }
            hiss::noise! { pub IX<$curve, ChaChaPoly, $hash>     { -> e, s [16] <- e, ee, se, s, es [15] } }
            hiss::noise! { pub XK<$curve, ChaChaPoly, $hash>     { <- s ... -> e, es [16] <- e, ee [15] -> s, se [11] } }
            hiss::noise! { pub NN<$curve, ChaChaPoly, $hash>     { -> e [16] <- e, ee [15] } }
            hiss::noise! { pub XX<$curve, ChaChaPoly, $hash>     { -> e [16] <- e, ee, s, es [15] -> s, se [11] } }
            hiss::noise! { pub X<$curve, ChaChaPoly, $hash>      { <- s ... -> e, es, s, ss [16] } }
            hiss::noise! { pub NX<$curve, ChaChaPoly, $hash>     { -> e [16] <- e, ee, s, es [15] } }
            hiss::noise! { pub XN<$curve, ChaChaPoly, $hash>     { -> e [16] <- e, ee [15] -> s, se [11] } }
            hiss::noise! { pub KN<$curve, ChaChaPoly, $hash>     { -> s ... -> e [16] <- e, ee, se [15] } }
            hiss::noise! { pub KK<$curve, ChaChaPoly, $hash>     { -> s <- s ... -> e, es, ss [16] <- e, ee, se [15] } }
            hiss::noise! { pub KX<$curve, ChaChaPoly, $hash>     { -> s ... -> e [16] <- e, ee, se, s, es [15] } }
            hiss::noise! { pub IN<$curve, ChaChaPoly, $hash>     { -> e, s [16] <- e, ee, se [15] } }
            // The three psk-placement variants: together with `Kpsk0` (psk
            // first) and `IKpsk1` (psk ends message 1) above, every position
            // a `pskN` modifier can name — psk0 through psk3 — has a
            // third-party-pinned representative. There is no psk4 to pin: no
            // fundamental pattern has a fourth message.
            hiss::noise! { pub NNpsk0<$curve, ChaChaPoly, $hash> { -> psk, e [16] <- e, ee [15] } }
            hiss::noise! { pub NNpsk2<$curve, ChaChaPoly, $hash> { -> e [16] <- e, ee, psk [15] } }
            hiss::noise! { pub XXpsk3<$curve, ChaChaPoly, $hash> { -> e [16] <- e, ee, s, es [15] -> s, se, psk [11] } }

            /// A recorded private scalar, verbatim.
            ///
            /// Cacophony's scalars are **not** pre-clamped, and hiss stores
            /// them raw and clamps at use time — as curve25519-dalek and
            /// `snow` do — so feeding the recorded bytes in unmodified is
            /// what the corpus expects.
            fn sk(hex_str: &str) -> $sk {
                <$sk>::from_bytes(
                    decode(hex_str)
                        .try_into()
                        .expect("recorded private scalar has the curve's scalar size"),
                )
            }

            /// A recorded public key.
            fn pk(hex_str: &str) -> <$curve as Curve>::PublicKey {
                <$curve as Curve>::public_key_from_bytes(&decode(hex_str))
                    .expect("recorded public key")
            }

            /// The initiator's scripted ephemeral: `EphemeralOnly`'s key
            /// generation is exactly one `fill_bytes` into an N-byte array
            /// stored verbatim, so the scripted stream *is* the ephemeral.
            fn init_provider(v: &Vector) -> EphemeralOnly<ScriptedRng> {
                let eph = decode(&v.init_ephemeral);
                EphemeralOnly::new(ScriptedRng::new(&[&eph]))
            }

            fn resp_provider(v: &Vector) -> EphemeralOnly<ScriptedRng> {
                let eph = decode(
                    v.resp_ephemeral
                        .as_deref()
                        .expect("pattern has a responder ephemeral"),
                );
                EphemeralOnly::new(ScriptedRng::new(&[&eph]))
            }

            fn remote_static(v: &Vector) -> <$curve as Curve>::PublicKey {
                pk(v.init_remote_static
                    .as_deref()
                    .expect("pattern pre-shares the responder's static"))
            }

            /// The initiator's public static, pre-shared with the responder
            /// by a `-> s` pre-message. Present on `K` and `Kpsk0` only —
            /// exactly the two patterns whose responder pre-knows it.
            fn resp_remote_static(v: &Vector) -> <$curve as Curve>::PublicKey {
                pk(v.resp_remote_static
                    .as_deref()
                    .expect("pattern pre-shares the initiator's static"))
            }

            fn init_static(v: &Vector) -> $sk {
                sk(v.init_static
                    .as_deref()
                    .expect("pattern uses an initiator static"))
            }

            /// The responder's own static, minted fresh at every use —
            /// private keys are not `Clone` (they zeroize on drop).
            fn resp_static(v: &Vector) -> $sk {
                sk(v.resp_static
                    .as_deref()
                    .expect("pattern uses a responder static"))
            }

            #[test]
            fn cacophony_n() {
                let file = load();
                let v = load_vector(&file, concat!("Noise_N_", $suite));

                // N's one message is also its last, so the writer yields the
                // `Transport` directly.
                let (msg1, mut transport) =
                    N::initiator(init_provider(v), &prologue(v), remote_static(v))
                        .write_message_1(&payload(&v.messages[0].payload))
                        .unwrap();
                assert_wire(&msg1, &v.messages[0].ciphertext, concat!("N/", $suite, " msg1"));

                assert_session_id(&transport, v);
                replay_transport(&mut transport, v, 1, true, Side::Initiator);
            }

            #[test]
            fn cacophony_k() {
                let file = load();
                let v = load_vector(&file, concat!("Noise_K_", $suite));

                // Both statics are pre-messages, so both are constructor
                // arguments, in pattern order: `-> s` (ours), `<- s` (theirs).
                let (msg1, mut transport) = K::initiator(
                    init_provider(v),
                    &prologue(v),
                    init_static(v),
                    remote_static(v),
                )
                .unwrap()
                .write_message_1(&payload(&v.messages[0].payload))
                .unwrap();
                assert_wire(&msg1, &v.messages[0].ciphertext, concat!("K/", $suite, " msg1"));

                assert_session_id(&transport, v);
                replay_transport(&mut transport, v, 1, true, Side::Initiator);
            }

            #[test]
            fn cacophony_kpsk0() {
                let file = load();
                let v = load_vector(&file, concat!("Noise_Kpsk0_", $suite));

                // `psk` is a message token, so it is a writer argument; the
                // payload is the tail and comes last.
                let (msg1, mut transport) = Kpsk0::initiator(
                    init_provider(v),
                    &prologue(v),
                    init_static(v),
                    remote_static(v),
                )
                .unwrap()
                .write_message_1(&psk(v), &payload(&v.messages[0].payload))
                .unwrap();
                assert_wire(
                    &msg1,
                    &v.messages[0].ciphertext,
                    concat!("Kpsk0/", $suite, " msg1"),
                );

                assert_session_id(&transport, v);
                replay_transport(&mut transport, v, 1, true, Side::Initiator);
            }

            #[test]
            fn cacophony_ikpsk1() {
                let file = load();
                let v = load_vector(&file, concat!("Noise_IKpsk1_", $suite));

                // msg1: -> e, es, s, ss, psk [16]
                let (msg1, hs) = IKpsk1::initiator(init_provider(v), &prologue(v), remote_static(v))
                    .write_message_1(
                        init_static(v),
                        &psk(v),
                        &payload(&v.messages[0].payload),
                    )
                    .unwrap();
                assert_wire(
                    &msg1,
                    &v.messages[0].ciphertext,
                    concat!("IKpsk1/", $suite, " msg1"),
                );

                // msg2: <- e, ee, se [15] — final, so the reader yields the
                // `Transport` alongside the recovered payload.
                let msg2 = frozen(&v.messages[1].ciphertext);
                let (got, mut transport) = hs.read_message_2(&msg2).unwrap();
                assert_eq!(
                    got,
                    payload::<15>(&v.messages[1].payload),
                    concat!("IKpsk1/", $suite, " msg2 payload")
                );

                assert_session_id(&transport, v);
                replay_transport(&mut transport, v, 2, false, Side::Initiator);
            }

            #[test]
            fn cacophony_ik() {
                let file = load();
                let v = load_vector(&file, concat!("Noise_IK_", $suite));

                let (msg1, hs) = IK::initiator(init_provider(v), &prologue(v), remote_static(v))
                    .write_message_1(init_static(v), &payload(&v.messages[0].payload))
                    .unwrap();
                assert_wire(&msg1, &v.messages[0].ciphertext, concat!("IK/", $suite, " msg1"));

                let msg2 = frozen(&v.messages[1].ciphertext);
                let (got, mut transport) = hs.read_message_2(&msg2).unwrap();
                assert_eq!(
                    got,
                    payload::<15>(&v.messages[1].payload),
                    concat!("IK/", $suite, " msg2 payload")
                );

                assert_session_id(&transport, v);
                replay_transport(&mut transport, v, 2, false, Side::Initiator);
            }

            #[test]
            fn cacophony_nk() {
                let file = load();
                let v = load_vector(&file, concat!("Noise_NK_", $suite));

                // NK's initiator is anonymous: no static of its own.
                let (msg1, hs) = NK::initiator(init_provider(v), &prologue(v), remote_static(v))
                    .write_message_1(&payload(&v.messages[0].payload))
                    .unwrap();
                assert_wire(&msg1, &v.messages[0].ciphertext, concat!("NK/", $suite, " msg1"));

                let msg2 = frozen(&v.messages[1].ciphertext);
                let (got, mut transport) = hs.read_message_2(&msg2).unwrap();
                assert_eq!(
                    got,
                    payload::<15>(&v.messages[1].payload),
                    concat!("NK/", $suite, " msg2 payload")
                );

                assert_session_id(&transport, v);
                replay_transport(&mut transport, v, 2, false, Side::Initiator);
            }

            #[test]
            fn cacophony_ix() {
                let file = load();
                let v = load_vector(&file, concat!("Noise_IX_", $suite));

                // No pre-messages, so the constructor is infallible; the
                // initiator transmits its static in msg1's `s` token, in the
                // clear (nothing is keyed yet).
                let (msg1, hs) = IX::initiator(init_provider(v), &prologue(v))
                    .write_message_1(init_static(v), &payload(&v.messages[0].payload))
                    .unwrap();
                assert_wire(&msg1, &v.messages[0].ciphertext, concat!("IX/", $suite, " msg1"));

                // msg2: <- e, ee, se, s, es [15] — final, and its `s` reveals
                // the responder's static onto the transport.
                let msg2 = frozen(&v.messages[1].ciphertext);
                let (got, mut transport) = hs.read_message_2(&msg2).unwrap();
                assert_eq!(
                    got,
                    payload::<15>(&v.messages[1].payload),
                    concat!("IX/", $suite, " msg2 payload")
                );
                assert_eq!(
                    transport.remote_static().unwrap().as_bytes(),
                    sk(v.resp_static.as_deref().unwrap()).public_key().as_bytes(),
                    concat!("IX/", $suite, " revealed responder static")
                );

                assert_session_id(&transport, v);
                replay_transport(&mut transport, v, 2, false, Side::Initiator);
            }

            #[test]
            fn cacophony_xk() {
                let file = load();
                let v = load_vector(&file, concat!("Noise_XK_", $suite));

                let (msg1, hs) = XK::initiator(init_provider(v), &prologue(v), remote_static(v))
                    .write_message_1(&payload(&v.messages[0].payload))
                    .unwrap();
                assert_wire(&msg1, &v.messages[0].ciphertext, concat!("XK/", $suite, " msg1"));

                let msg2 = frozen(&v.messages[1].ciphertext);
                let (got, hs) = hs.read_message_2(&msg2).unwrap();
                assert_eq!(
                    got,
                    payload::<15>(&v.messages[1].payload),
                    concat!("XK/", $suite, " msg2 payload")
                );

                // msg3: -> s, se [11] — the initiator's static goes out
                // encrypted, after `ee`.
                let (msg3, mut transport) = hs
                    .write_message_3(init_static(v), &payload(&v.messages[2].payload))
                    .unwrap();
                assert_wire(&msg3, &v.messages[2].ciphertext, concat!("XK/", $suite, " msg3"));

                assert_session_id(&transport, v);
                replay_transport(&mut transport, v, 3, false, Side::Initiator);
            }

            #[test]
            fn cacophony_nn() {
                let file = load();
                let v = load_vector(&file, concat!("Noise_NN_", $suite));

                // `-> e [16]` closes before any DH, so msg1's payload rides
                // the wire verbatim — the same property `noise_macro_shapes`
                // pins for `NNPayload`.
                let (msg1, hs) = NN::initiator(init_provider(v), &prologue(v))
                    .write_message_1(&payload(&v.messages[0].payload))
                    .unwrap();
                assert_wire(&msg1, &v.messages[0].ciphertext, concat!("NN/", $suite, " msg1"));

                let msg2 = frozen(&v.messages[1].ciphertext);
                let (got, mut transport) = hs.read_message_2(&msg2).unwrap();
                assert_eq!(
                    got,
                    payload::<15>(&v.messages[1].payload),
                    concat!("NN/", $suite, " msg2 payload")
                );

                assert_session_id(&transport, v);
                replay_transport(&mut transport, v, 2, false, Side::Initiator);
            }

            #[test]
            fn cacophony_xx() {
                let file = load();
                let v = load_vector(&file, concat!("Noise_XX_", $suite));

                let (msg1, hs) = XX::initiator(init_provider(v), &prologue(v))
                    .write_message_1(&payload(&v.messages[0].payload))
                    .unwrap();
                assert_wire(&msg1, &v.messages[0].ciphertext, concat!("XX/", $suite, " msg1"));

                // msg2: <- e, ee, s, es [15] — the `s` token reveals the
                // responder's static mid-handshake.
                let msg2 = frozen(&v.messages[1].ciphertext);
                let (got, hs) = hs.read_message_2(&msg2).unwrap();
                assert_eq!(
                    got,
                    payload::<15>(&v.messages[1].payload),
                    concat!("XX/", $suite, " msg2 payload")
                );
                assert_eq!(
                    hs.remote_static().as_bytes(),
                    sk(v.resp_static.as_deref().unwrap()).public_key().as_bytes(),
                    concat!("XX/", $suite, " revealed responder static")
                );

                let (msg3, mut transport) = hs
                    .write_message_3(init_static(v), &payload(&v.messages[2].payload))
                    .unwrap();
                assert_wire(&msg3, &v.messages[2].ciphertext, concat!("XX/", $suite, " msg3"));

                assert_session_id(&transport, v);
                replay_transport(&mut transport, v, 3, false, Side::Initiator);
            }

            #[test]
            fn cacophony_x() {
                let file = load();
                let v = load_vector(&file, concat!("Noise_X_", $suite));

                // X is IK's msg1 with no reply: the initiator pre-knows the
                // responder static and transmits its own in the `s` token.
                let (msg1, mut transport) =
                    X::initiator(init_provider(v), &prologue(v), remote_static(v))
                        .write_message_1(init_static(v), &payload(&v.messages[0].payload))
                        .unwrap();
                assert_wire(&msg1, &v.messages[0].ciphertext, concat!("X/", $suite, " msg1"));

                assert_session_id(&transport, v);
                replay_transport(&mut transport, v, 1, true, Side::Initiator);
            }

            /// `NX` — `XX` without msg3: the initiator is anonymous, so only
            /// the responder's static is ever revealed.
            #[test]
            fn cacophony_nx() {
                let file = load();
                let v = load_vector(&file, concat!("Noise_NX_", $suite));

                let (msg1, hs) = NX::initiator(init_provider(v), &prologue(v))
                    .write_message_1(&payload(&v.messages[0].payload))
                    .unwrap();
                assert_wire(&msg1, &v.messages[0].ciphertext, concat!("NX/", $suite, " msg1"));

                // msg2: <- e, ee, s, es [15] — final, so the reveal lands on
                // the transport rather than a further handshake state.
                let msg2 = frozen(&v.messages[1].ciphertext);
                let (got, mut transport) = hs.read_message_2(&msg2).unwrap();
                assert_eq!(
                    got,
                    payload::<15>(&v.messages[1].payload),
                    concat!("NX/", $suite, " msg2 payload")
                );
                assert_eq!(
                    transport.remote_static().unwrap().as_bytes(),
                    resp_static(v).public_key().as_bytes(),
                    concat!("NX/", $suite, " revealed responder static")
                );

                assert_session_id(&transport, v);
                replay_transport(&mut transport, v, 2, false, Side::Initiator);
            }

            /// `XN` — three messages, and the only static on the wire is
            /// ours, sent encrypted in msg3.
            #[test]
            fn cacophony_xn() {
                let file = load();
                let v = load_vector(&file, concat!("Noise_XN_", $suite));

                let (msg1, hs) = XN::initiator(init_provider(v), &prologue(v))
                    .write_message_1(&payload(&v.messages[0].payload))
                    .unwrap();
                assert_wire(&msg1, &v.messages[0].ciphertext, concat!("XN/", $suite, " msg1"));

                let msg2 = frozen(&v.messages[1].ciphertext);
                let (got, hs) = hs.read_message_2(&msg2).unwrap();
                assert_eq!(
                    got,
                    payload::<15>(&v.messages[1].payload),
                    concat!("XN/", $suite, " msg2 payload")
                );

                // msg3: -> s, se [11] — the responder is anonymous, so there
                // is nothing to reveal in the other direction.
                let (msg3, mut transport) = hs
                    .write_message_3(init_static(v), &payload(&v.messages[2].payload))
                    .unwrap();
                assert_wire(&msg3, &v.messages[2].ciphertext, concat!("XN/", $suite, " msg3"));

                assert_session_id(&transport, v);
                replay_transport(&mut transport, v, 3, false, Side::Initiator);
            }

            /// `KN` — our static is pre-shared, so nothing identifying rides
            /// the wire and nothing is revealed to us.
            #[test]
            fn cacophony_kn() {
                let file = load();
                let v = load_vector(&file, concat!("Noise_KN_", $suite));

                // `-> s` is our own static: a constructor argument, and the
                // constructor is fallible because it holds a local key.
                let (msg1, hs) = KN::initiator(init_provider(v), &prologue(v), init_static(v))
                    .unwrap()
                    .write_message_1(&payload(&v.messages[0].payload))
                    .unwrap();
                assert_wire(&msg1, &v.messages[0].ciphertext, concat!("KN/", $suite, " msg1"));

                let msg2 = frozen(&v.messages[1].ciphertext);
                let (got, mut transport) = hs.read_message_2(&msg2).unwrap();
                assert_eq!(
                    got,
                    payload::<15>(&v.messages[1].payload),
                    concat!("KN/", $suite, " msg2 payload")
                );

                assert_session_id(&transport, v);
                replay_transport(&mut transport, v, 2, false, Side::Initiator);
            }

            /// `KK` — both statics pre-shared, so msg1's payload is already
            /// encrypted: the zero-RTT pattern.
            #[test]
            fn cacophony_kk() {
                let file = load();
                let v = load_vector(&file, concat!("Noise_KK_", $suite));

                // Both pre-messages, in pattern order: `-> s` (ours) then
                // `<- s` (theirs).
                let (msg1, hs) = KK::initiator(
                    init_provider(v),
                    &prologue(v),
                    init_static(v),
                    remote_static(v),
                )
                .unwrap()
                .write_message_1(&payload(&v.messages[0].payload))
                .unwrap();
                assert_wire(&msg1, &v.messages[0].ciphertext, concat!("KK/", $suite, " msg1"));

                let msg2 = frozen(&v.messages[1].ciphertext);
                let (got, mut transport) = hs.read_message_2(&msg2).unwrap();
                assert_eq!(
                    got,
                    payload::<15>(&v.messages[1].payload),
                    concat!("KK/", $suite, " msg2 payload")
                );

                assert_session_id(&transport, v);
                replay_transport(&mut transport, v, 2, false, Side::Initiator);
            }

            /// `KX` — our static pre-shared, theirs revealed encrypted in
            /// msg2.
            #[test]
            fn cacophony_kx() {
                let file = load();
                let v = load_vector(&file, concat!("Noise_KX_", $suite));

                let (msg1, hs) = KX::initiator(init_provider(v), &prologue(v), init_static(v))
                    .unwrap()
                    .write_message_1(&payload(&v.messages[0].payload))
                    .unwrap();
                assert_wire(&msg1, &v.messages[0].ciphertext, concat!("KX/", $suite, " msg1"));

                let msg2 = frozen(&v.messages[1].ciphertext);
                let (got, mut transport) = hs.read_message_2(&msg2).unwrap();
                assert_eq!(
                    got,
                    payload::<15>(&v.messages[1].payload),
                    concat!("KX/", $suite, " msg2 payload")
                );
                assert_eq!(
                    transport.remote_static().unwrap().as_bytes(),
                    resp_static(v).public_key().as_bytes(),
                    concat!("KX/", $suite, " revealed responder static")
                );

                assert_session_id(&transport, v);
                replay_transport(&mut transport, v, 2, false, Side::Initiator);
            }

            /// `IN` — our static rides msg1 **in the clear**, before any DH
            /// keys the cipher.
            #[test]
            fn cacophony_in() {
                let file = load();
                let v = load_vector(&file, concat!("Noise_IN_", $suite));

                // No pre-messages, so the constructor is infallible and the
                // `s` token makes our static a writer argument instead.
                let (msg1, hs) = IN::initiator(init_provider(v), &prologue(v))
                    .write_message_1(init_static(v), &payload(&v.messages[0].payload))
                    .unwrap();
                assert_wire(&msg1, &v.messages[0].ciphertext, concat!("IN/", $suite, " msg1"));

                let msg2 = frozen(&v.messages[1].ciphertext);
                let (got, mut transport) = hs.read_message_2(&msg2).unwrap();
                assert_eq!(
                    got,
                    payload::<15>(&v.messages[1].payload),
                    concat!("IN/", $suite, " msg2 payload")
                );

                assert_session_id(&transport, v);
                replay_transport(&mut transport, v, 2, false, Side::Initiator);
            }

            #[test]
            fn cacophony_nnpsk0() {
                let file = load();
                let v = load_vector(&file, concat!("Noise_NNpsk0_", $suite));

                // msg1: -> psk, e [16] — the psk keys the cipher before
                // anything else, so unlike NN's, this msg1 payload goes out
                // encrypted.
                let (msg1, hs) = NNpsk0::initiator(init_provider(v), &prologue(v))
                    .write_message_1(&psk(v), &payload(&v.messages[0].payload))
                    .unwrap();
                assert_wire(
                    &msg1,
                    &v.messages[0].ciphertext,
                    concat!("NNpsk0/", $suite, " msg1"),
                );

                let msg2 = frozen(&v.messages[1].ciphertext);
                let (got, mut transport) = hs.read_message_2(&msg2).unwrap();
                assert_eq!(
                    got,
                    payload::<15>(&v.messages[1].payload),
                    concat!("NNpsk0/", $suite, " msg2 payload")
                );

                assert_session_id(&transport, v);
                replay_transport(&mut transport, v, 2, false, Side::Initiator);
            }

            #[test]
            fn cacophony_nnpsk2() {
                let file = load();
                let v = load_vector(&file, concat!("Noise_NNpsk2_", $suite));

                let (msg1, hs) = NNpsk2::initiator(init_provider(v), &prologue(v))
                    .write_message_1(&payload(&v.messages[0].payload))
                    .unwrap();
                assert_wire(
                    &msg1,
                    &v.messages[0].ciphertext,
                    concat!("NNpsk2/", $suite, " msg1"),
                );

                // msg2: <- e, ee, psk [15] — the psk token sits in a message
                // we *read*, so the plain reader takes it as an argument.
                let msg2 = frozen(&v.messages[1].ciphertext);
                let (got, mut transport) = hs.read_message_2(&msg2, &psk(v)).unwrap();
                assert_eq!(
                    got,
                    payload::<15>(&v.messages[1].payload),
                    concat!("NNpsk2/", $suite, " msg2 payload")
                );

                assert_session_id(&transport, v);
                replay_transport(&mut transport, v, 2, false, Side::Initiator);
            }

            #[test]
            fn cacophony_xxpsk3() {
                let file = load();
                let v = load_vector(&file, concat!("Noise_XXpsk3_", $suite));

                let (msg1, hs) = XXpsk3::initiator(init_provider(v), &prologue(v))
                    .write_message_1(&payload(&v.messages[0].payload))
                    .unwrap();
                assert_wire(
                    &msg1,
                    &v.messages[0].ciphertext,
                    concat!("XXpsk3/", $suite, " msg1"),
                );

                let msg2 = frozen(&v.messages[1].ciphertext);
                let (got, hs) = hs.read_message_2(&msg2).unwrap();
                assert_eq!(
                    got,
                    payload::<15>(&v.messages[1].payload),
                    concat!("XXpsk3/", $suite, " msg2 payload")
                );
                assert_eq!(
                    hs.remote_static().as_bytes(),
                    sk(v.resp_static.as_deref().unwrap()).public_key().as_bytes(),
                    concat!("XXpsk3/", $suite, " revealed responder static")
                );

                // msg3: -> s, se, psk [11] — writer arguments in token order,
                // static then psk, payload last.
                let (msg3, mut transport) = hs
                    .write_message_3(init_static(v), &psk(v), &payload(&v.messages[2].payload))
                    .unwrap();
                assert_wire(
                    &msg3,
                    &v.messages[2].ciphertext,
                    concat!("XXpsk3/", $suite, " msg3"),
                );

                assert_session_id(&transport, v);
                replay_transport(&mut transport, v, 3, false, Side::Initiator);
            }

            // ── Responder-role replays ───────────────────────────
            //
            // Every pattern from the responder's side. The initiator replays
            // above prove our *read* path against a third party; only a
            // responder replay proves that a **responder write** produces the
            // same bytes, and for X448 these remain the only
            // cross-implementation check of a responder write that exists
            // anywhere — `snow`'s resolver returns `None` for `448`.
            //
            // The four one-way patterns have no responder-written message, so
            // theirs assert the recipient read path and five transport
            // receives instead; for X448 nothing else in the tree covers that
            // path either.

            /// `XX` from the other side: msg2 carries the responder's static
            /// outbound, and the final msg3 read reveals the initiator's.
            #[test]
            fn cacophony_xx_responder() {
                let file = load();
                let v = load_vector(&file, concat!("Noise_XX_", $suite));

                let hs = XX::responder(resp_provider(v), &prologue(v));

                // msg1: -> e [16], read from the frozen initiator bytes.
                let msg1 = frozen(&v.messages[0].ciphertext);
                let (got, hs) = hs.read_message_1(&msg1).unwrap();
                assert_eq!(
                    got,
                    payload::<16>(&v.messages[0].payload),
                    concat!("XX/", $suite, " responder msg1 payload")
                );

                // msg2: <- e, ee, s, es [15] — ours to write.
                let (msg2, hs) = hs
                    .write_message_2(resp_static(v), &payload(&v.messages[1].payload))
                    .unwrap();
                assert_wire(
                    &msg2,
                    &v.messages[1].ciphertext,
                    concat!("XX/", $suite, " responder msg2"),
                );

                // msg3: -> s, se [11] — final, and its `s` reveals the
                // initiator's static onto the transport.
                let msg3 = frozen(&v.messages[2].ciphertext);
                let (got, mut transport) = hs.read_message_3(&msg3).unwrap();
                assert_eq!(
                    got,
                    payload::<11>(&v.messages[2].payload),
                    concat!("XX/", $suite, " responder msg3 payload")
                );
                assert_eq!(
                    transport.remote_static().unwrap().as_bytes(),
                    init_static(v).public_key().as_bytes(),
                    concat!("XX/", $suite, " revealed initiator static")
                );

                assert_session_id(&transport, v);
                replay_transport(&mut transport, v, 3, false, Side::Responder);
            }

            /// `IK` from the other side: msg1 reveals the initiator's static
            /// mid-handshake, and msg2 is ours to write.
            #[test]
            fn cacophony_ik_responder() {
                let file = load();
                let v = load_vector(&file, concat!("Noise_IK_", $suite));

                // `<- s` is the responder's own static, so it is a
                // constructor argument and the constructor is fallible.
                let hs = IK::responder(resp_provider(v), &prologue(v), resp_static(v)).unwrap();

                let msg1 = frozen(&v.messages[0].ciphertext);
                let (got, hs) = hs.read_message_1(&msg1).unwrap();
                assert_eq!(
                    got,
                    payload::<16>(&v.messages[0].payload),
                    concat!("IK/", $suite, " responder msg1 payload")
                );
                assert_eq!(
                    hs.remote_static().as_bytes(),
                    init_static(v).public_key().as_bytes(),
                    concat!("IK/", $suite, " revealed initiator static")
                );

                // msg2: <- e, ee, se [15] — final, so writing it yields the
                // transport.
                let (msg2, mut transport) = hs
                    .write_message_2(&payload(&v.messages[1].payload))
                    .unwrap();
                assert_wire(
                    &msg2,
                    &v.messages[1].ciphertext,
                    concat!("IK/", $suite, " responder msg2"),
                );

                assert_session_id(&transport, v);
                replay_transport(&mut transport, v, 2, false, Side::Responder);
            }

            /// `IK` from the other side, read **staged**: intro reveals the
            /// claimed initiator static after one DH, `complete()` recovers
            /// the payload, and the msg2 the previously-suspended responder
            /// writes is byte-identical to the corpus — a third-party oracle
            /// that suspension leaves no trace in the transcript.
            #[test]
            fn cacophony_ik_responder_staged() {
                let file = load();
                let v = load_vector(&file, concat!("Noise_IK_", $suite));

                let hs = IK::responder(resp_provider(v), &prologue(v), resp_static(v)).unwrap();

                let msg1 = frozen(&v.messages[0].ciphertext);
                let (claimed, mid) = hs.read_message_1_intro(&msg1).unwrap();
                assert_eq!(
                    claimed.as_bytes(),
                    init_static(v).public_key().as_bytes(),
                    concat!("IK/", $suite, " claimed initiator static at intro")
                );
                let (got, hs) = mid.complete().unwrap();
                assert_eq!(
                    got,
                    payload::<16>(&v.messages[0].payload),
                    concat!("IK/", $suite, " staged msg1 payload")
                );

                let (msg2, mut transport) = hs
                    .write_message_2(&payload(&v.messages[1].payload))
                    .unwrap();
                assert_wire(
                    &msg2,
                    &v.messages[1].ciphertext,
                    concat!("IK/", $suite, " staged responder msg2"),
                );

                assert_session_id(&transport, v);
                replay_transport(&mut transport, v, 2, false, Side::Responder);
            }

            /// `IKpsk1` from the other side. The `psk` token trails the `s`
            /// it protects, so the plain read takes the PSK as an argument.
            #[test]
            fn cacophony_ikpsk1_responder() {
                let file = load();
                let v = load_vector(&file, concat!("Noise_IKpsk1_", $suite));

                let hs = IKpsk1::responder(resp_provider(v), &prologue(v), resp_static(v)).unwrap();

                let msg1 = frozen(&v.messages[0].ciphertext);
                let (got, hs) = hs.read_message_1(&msg1, &psk(v)).unwrap();
                assert_eq!(
                    got,
                    payload::<16>(&v.messages[0].payload),
                    concat!("IKpsk1/", $suite, " responder msg1 payload")
                );
                assert_eq!(
                    hs.remote_static().as_bytes(),
                    init_static(v).public_key().as_bytes(),
                    concat!("IKpsk1/", $suite, " revealed initiator static")
                );

                let (msg2, mut transport) = hs
                    .write_message_2(&payload(&v.messages[1].payload))
                    .unwrap();
                assert_wire(
                    &msg2,
                    &v.messages[1].ciphertext,
                    concat!("IKpsk1/", $suite, " responder msg2"),
                );

                assert_session_id(&transport, v);
                replay_transport(&mut transport, v, 2, false, Side::Responder);
            }

            /// `NK` from the other side. Msg1 carries no `s`, so nothing is
            /// revealed — the initiator stays anonymous throughout.
            #[test]
            fn cacophony_nk_responder() {
                let file = load();
                let v = load_vector(&file, concat!("Noise_NK_", $suite));

                let hs = NK::responder(resp_provider(v), &prologue(v), resp_static(v)).unwrap();

                let msg1 = frozen(&v.messages[0].ciphertext);
                let (got, hs) = hs.read_message_1(&msg1).unwrap();
                assert_eq!(
                    got,
                    payload::<16>(&v.messages[0].payload),
                    concat!("NK/", $suite, " responder msg1 payload")
                );

                let (msg2, mut transport) = hs
                    .write_message_2(&payload(&v.messages[1].payload))
                    .unwrap();
                assert_wire(
                    &msg2,
                    &v.messages[1].ciphertext,
                    concat!("NK/", $suite, " responder msg2"),
                );

                assert_session_id(&transport, v);
                replay_transport(&mut transport, v, 2, false, Side::Responder);
            }

            /// `NN` from the other side: no statics exist at all, so the
            /// constructor takes none and is infallible.
            #[test]
            fn cacophony_nn_responder() {
                let file = load();
                let v = load_vector(&file, concat!("Noise_NN_", $suite));

                let hs = NN::responder(resp_provider(v), &prologue(v));

                // `-> e [16]` closes before any DH, so msg1's payload arrives
                // in the clear and unverified — the read still recovers it.
                let msg1 = frozen(&v.messages[0].ciphertext);
                let (got, hs) = hs.read_message_1(&msg1).unwrap();
                assert_eq!(
                    got,
                    payload::<16>(&v.messages[0].payload),
                    concat!("NN/", $suite, " responder msg1 payload")
                );

                let (msg2, mut transport) = hs
                    .write_message_2(&payload(&v.messages[1].payload))
                    .unwrap();
                assert_wire(
                    &msg2,
                    &v.messages[1].ciphertext,
                    concat!("NN/", $suite, " responder msg2"),
                );

                assert_session_id(&transport, v);
                replay_transport(&mut transport, v, 2, false, Side::Responder);
            }

            /// `IX` from the other side. Both statics travel in-handshake:
            /// the initiator's arrives in msg1's `s`, ours leaves in msg2's.
            #[test]
            fn cacophony_ix_responder() {
                let file = load();
                let v = load_vector(&file, concat!("Noise_IX_", $suite));

                // No pre-messages, so the constructor is infallible; our own
                // static becomes a writer argument on msg2 instead.
                let hs = IX::responder(resp_provider(v), &prologue(v));

                let msg1 = frozen(&v.messages[0].ciphertext);
                let (got, hs) = hs.read_message_1(&msg1).unwrap();
                assert_eq!(
                    got,
                    payload::<16>(&v.messages[0].payload),
                    concat!("IX/", $suite, " responder msg1 payload")
                );
                assert_eq!(
                    hs.remote_static().as_bytes(),
                    init_static(v).public_key().as_bytes(),
                    concat!("IX/", $suite, " revealed initiator static")
                );

                let (msg2, mut transport) = hs
                    .write_message_2(resp_static(v), &payload(&v.messages[1].payload))
                    .unwrap();
                assert_wire(
                    &msg2,
                    &v.messages[1].ciphertext,
                    concat!("IX/", $suite, " responder msg2"),
                );

                assert_session_id(&transport, v);
                replay_transport(&mut transport, v, 2, false, Side::Responder);
            }

            /// `XK` from the other side — the three-message shape, so our
            /// msg2 write yields a further handshake state rather than the
            /// transport, and the initiator's static only arrives in msg3.
            #[test]
            fn cacophony_xk_responder() {
                let file = load();
                let v = load_vector(&file, concat!("Noise_XK_", $suite));

                let hs = XK::responder(resp_provider(v), &prologue(v), resp_static(v)).unwrap();

                let msg1 = frozen(&v.messages[0].ciphertext);
                let (got, hs) = hs.read_message_1(&msg1).unwrap();
                assert_eq!(
                    got,
                    payload::<16>(&v.messages[0].payload),
                    concat!("XK/", $suite, " responder msg1 payload")
                );

                // msg2: <- e, ee [15] — not final, so this yields `hs`.
                let (msg2, hs) = hs
                    .write_message_2(&payload(&v.messages[1].payload))
                    .unwrap();
                assert_wire(
                    &msg2,
                    &v.messages[1].ciphertext,
                    concat!("XK/", $suite, " responder msg2"),
                );

                // msg3: -> s, se [11] — final, and its `s` reveals the
                // initiator's static onto the transport.
                let msg3 = frozen(&v.messages[2].ciphertext);
                let (got, mut transport) = hs.read_message_3(&msg3).unwrap();
                assert_eq!(
                    got,
                    payload::<11>(&v.messages[2].payload),
                    concat!("XK/", $suite, " responder msg3 payload")
                );
                assert_eq!(
                    transport.remote_static().unwrap().as_bytes(),
                    init_static(v).public_key().as_bytes(),
                    concat!("XK/", $suite, " revealed initiator static")
                );

                assert_session_id(&transport, v);
                replay_transport(&mut transport, v, 3, false, Side::Responder);
            }

            // The four one-way recipients. They write nothing, so there is no
            // wire-byte assertion to make; what they pin is the recipient read
            // path — the pre-message key schedule from the responder's side,
            // the recovered payload, `X`'s revealed initiator static — and
            // five consecutive transport receives on nonces 0..4.

            /// `N` from the other side: one message, anonymous sender.
            #[test]
            fn cacophony_n_responder() {
                let file = load();
                let v = load_vector(&file, concat!("Noise_N_", $suite));

                let hs =
                    N::responder(oneway_resp_provider(), &prologue(v), resp_static(v)).unwrap();

                // The pattern's only message is also its last, so the reader
                // yields the `Transport` alongside the payload.
                let msg1 = frozen(&v.messages[0].ciphertext);
                let (got, mut transport) = hs.read_message_1(&msg1).unwrap();
                assert_eq!(
                    got,
                    payload::<16>(&v.messages[0].payload),
                    concat!("N/", $suite, " responder msg1 payload")
                );

                assert_session_id(&transport, v);
                replay_transport(&mut transport, v, 1, true, Side::Responder);
            }

            /// `K` from the other side: both statics are pre-messages, so
            /// both are constructor arguments in pattern order — `-> s`
            /// (theirs) then `<- s` (ours).
            #[test]
            fn cacophony_k_responder() {
                let file = load();
                let v = load_vector(&file, concat!("Noise_K_", $suite));

                let hs = K::responder(
                    oneway_resp_provider(),
                    &prologue(v),
                    resp_remote_static(v),
                    resp_static(v),
                )
                .unwrap();

                let msg1 = frozen(&v.messages[0].ciphertext);
                let (got, mut transport) = hs.read_message_1(&msg1).unwrap();
                assert_eq!(
                    got,
                    payload::<16>(&v.messages[0].payload),
                    concat!("K/", $suite, " responder msg1 payload")
                );

                assert_session_id(&transport, v);
                replay_transport(&mut transport, v, 1, true, Side::Responder);
            }

            /// `Kpsk0` from the other side. `psk` is the first token and no
            /// `s` precedes it, so the read is the plain
            /// `read_message_1(&msg, &psk)` form.
            #[test]
            fn cacophony_kpsk0_responder() {
                let file = load();
                let v = load_vector(&file, concat!("Noise_Kpsk0_", $suite));

                let hs = Kpsk0::responder(
                    oneway_resp_provider(),
                    &prologue(v),
                    resp_remote_static(v),
                    resp_static(v),
                )
                .unwrap();

                let msg1 = frozen(&v.messages[0].ciphertext);
                let (got, mut transport) = hs.read_message_1(&msg1, &psk(v)).unwrap();
                assert_eq!(
                    got,
                    payload::<16>(&v.messages[0].payload),
                    concat!("Kpsk0/", $suite, " responder msg1 payload")
                );

                assert_session_id(&transport, v);
                replay_transport(&mut transport, v, 1, true, Side::Responder);
            }

            /// `X` from the other side — the one one-way pattern whose single
            /// message reveals the sender's static, so the read has something
            /// to hand back beyond the payload.
            #[test]
            fn cacophony_x_responder() {
                let file = load();
                let v = load_vector(&file, concat!("Noise_X_", $suite));

                let hs =
                    X::responder(oneway_resp_provider(), &prologue(v), resp_static(v)).unwrap();

                let msg1 = frozen(&v.messages[0].ciphertext);
                let (got, mut transport) = hs.read_message_1(&msg1).unwrap();
                assert_eq!(
                    got,
                    payload::<16>(&v.messages[0].payload),
                    concat!("X/", $suite, " responder msg1 payload")
                );
                assert_eq!(
                    transport.remote_static().unwrap().as_bytes(),
                    init_static(v).public_key().as_bytes(),
                    concat!("X/", $suite, " revealed initiator static")
                );

                assert_session_id(&transport, v);
                replay_transport(&mut transport, v, 1, true, Side::Responder);
            }

            /// `NX` from the other side: our static leaves in msg2, and the
            /// anonymous initiator gives us nothing to reveal.
            #[test]
            fn cacophony_nx_responder() {
                let file = load();
                let v = load_vector(&file, concat!("Noise_NX_", $suite));

                let hs = NX::responder(resp_provider(v), &prologue(v));

                let msg1 = frozen(&v.messages[0].ciphertext);
                let (got, hs) = hs.read_message_1(&msg1).unwrap();
                assert_eq!(
                    got,
                    payload::<16>(&v.messages[0].payload),
                    concat!("NX/", $suite, " responder msg1 payload")
                );

                // msg2's `s` token makes our static a writer argument; the
                // payload is the tail, so it comes last.
                let (msg2, mut transport) = hs
                    .write_message_2(resp_static(v), &payload(&v.messages[1].payload))
                    .unwrap();
                assert_wire(
                    &msg2,
                    &v.messages[1].ciphertext,
                    concat!("NX/", $suite, " responder msg2"),
                );

                assert_session_id(&transport, v);
                replay_transport(&mut transport, v, 2, false, Side::Responder);
            }

            /// `XN` from the other side: we are the anonymous party, so we
            /// hold no static at all — msg3 reveals the initiator's.
            #[test]
            fn cacophony_xn_responder() {
                let file = load();
                let v = load_vector(&file, concat!("Noise_XN_", $suite));

                let hs = XN::responder(resp_provider(v), &prologue(v));

                let msg1 = frozen(&v.messages[0].ciphertext);
                let (got, hs) = hs.read_message_1(&msg1).unwrap();
                assert_eq!(
                    got,
                    payload::<16>(&v.messages[0].payload),
                    concat!("XN/", $suite, " responder msg1 payload")
                );

                // msg2: <- e, ee [15] — not final, so this yields `hs`.
                let (msg2, hs) = hs
                    .write_message_2(&payload(&v.messages[1].payload))
                    .unwrap();
                assert_wire(
                    &msg2,
                    &v.messages[1].ciphertext,
                    concat!("XN/", $suite, " responder msg2"),
                );

                let msg3 = frozen(&v.messages[2].ciphertext);
                let (got, mut transport) = hs.read_message_3(&msg3).unwrap();
                assert_eq!(
                    got,
                    payload::<11>(&v.messages[2].payload),
                    concat!("XN/", $suite, " responder msg3 payload")
                );
                assert_eq!(
                    transport.remote_static().unwrap().as_bytes(),
                    init_static(v).public_key().as_bytes(),
                    concat!("XN/", $suite, " revealed initiator static")
                );

                assert_session_id(&transport, v);
                replay_transport(&mut transport, v, 3, false, Side::Responder);
            }

            /// `KN` from the other side. We hold **no** static — only the
            /// initiator's pre-shared public key — so the constructor is
            /// infallible even though it takes a pre-message argument.
            #[test]
            fn cacophony_kn_responder() {
                let file = load();
                let v = load_vector(&file, concat!("Noise_KN_", $suite));

                let hs = KN::responder(resp_provider(v), &prologue(v), resp_remote_static(v));

                let msg1 = frozen(&v.messages[0].ciphertext);
                let (got, hs) = hs.read_message_1(&msg1).unwrap();
                assert_eq!(
                    got,
                    payload::<16>(&v.messages[0].payload),
                    concat!("KN/", $suite, " responder msg1 payload")
                );

                let (msg2, mut transport) = hs
                    .write_message_2(&payload(&v.messages[1].payload))
                    .unwrap();
                assert_wire(
                    &msg2,
                    &v.messages[1].ciphertext,
                    concat!("KN/", $suite, " responder msg2"),
                );

                assert_session_id(&transport, v);
                replay_transport(&mut transport, v, 2, false, Side::Responder);
            }

            /// `KK` from the other side — both statics pre-shared, so unlike
            /// `KN` we do hold a local key and the constructor is fallible.
            #[test]
            fn cacophony_kk_responder() {
                let file = load();
                let v = load_vector(&file, concat!("Noise_KK_", $suite));

                // Pattern order again: `-> s` (theirs) then `<- s` (ours).
                let hs = KK::responder(
                    resp_provider(v),
                    &prologue(v),
                    resp_remote_static(v),
                    resp_static(v),
                )
                .unwrap();

                // msg1's payload arrives already encrypted — the zero-RTT
                // property no other interactive pattern here has.
                let msg1 = frozen(&v.messages[0].ciphertext);
                let (got, hs) = hs.read_message_1(&msg1).unwrap();
                assert_eq!(
                    got,
                    payload::<16>(&v.messages[0].payload),
                    concat!("KK/", $suite, " responder msg1 payload")
                );

                let (msg2, mut transport) = hs
                    .write_message_2(&payload(&v.messages[1].payload))
                    .unwrap();
                assert_wire(
                    &msg2,
                    &v.messages[1].ciphertext,
                    concat!("KK/", $suite, " responder msg2"),
                );

                assert_session_id(&transport, v);
                replay_transport(&mut transport, v, 2, false, Side::Responder);
            }

            /// `KX` from the other side: infallible constructor like `KN`,
            /// but our static goes out in msg2 as a writer argument.
            #[test]
            fn cacophony_kx_responder() {
                let file = load();
                let v = load_vector(&file, concat!("Noise_KX_", $suite));

                let hs = KX::responder(resp_provider(v), &prologue(v), resp_remote_static(v));

                let msg1 = frozen(&v.messages[0].ciphertext);
                let (got, hs) = hs.read_message_1(&msg1).unwrap();
                assert_eq!(
                    got,
                    payload::<16>(&v.messages[0].payload),
                    concat!("KX/", $suite, " responder msg1 payload")
                );

                let (msg2, mut transport) = hs
                    .write_message_2(resp_static(v), &payload(&v.messages[1].payload))
                    .unwrap();
                assert_wire(
                    &msg2,
                    &v.messages[1].ciphertext,
                    concat!("KX/", $suite, " responder msg2"),
                );

                assert_session_id(&transport, v);
                replay_transport(&mut transport, v, 2, false, Side::Responder);
            }

            /// `IN` from the other side. Msg1 is not final, so the revealed
            /// initiator static comes back on the handshake state directly
            /// rather than as an `Option` on a transport.
            #[test]
            fn cacophony_in_responder() {
                let file = load();
                let v = load_vector(&file, concat!("Noise_IN_", $suite));

                let hs = IN::responder(resp_provider(v), &prologue(v));

                let msg1 = frozen(&v.messages[0].ciphertext);
                let (got, hs) = hs.read_message_1(&msg1).unwrap();
                assert_eq!(
                    got,
                    payload::<16>(&v.messages[0].payload),
                    concat!("IN/", $suite, " responder msg1 payload")
                );
                assert_eq!(
                    hs.remote_static().as_bytes(),
                    init_static(v).public_key().as_bytes(),
                    concat!("IN/", $suite, " revealed initiator static")
                );

                let (msg2, mut transport) = hs
                    .write_message_2(&payload(&v.messages[1].payload))
                    .unwrap();
                assert_wire(
                    &msg2,
                    &v.messages[1].ciphertext,
                    concat!("IN/", $suite, " responder msg2"),
                );

                assert_session_id(&transport, v);
                replay_transport(&mut transport, v, 2, false, Side::Responder);
            }

            /// `NNpsk0` from the other side: the psk arrives with the very
            /// first read.
            #[test]
            fn cacophony_nnpsk0_responder() {
                let file = load();
                let v = load_vector(&file, concat!("Noise_NNpsk0_", $suite));

                let hs = NNpsk0::responder(resp_provider(v), &prologue(v));

                let msg1 = frozen(&v.messages[0].ciphertext);
                let (got, hs) = hs.read_message_1(&msg1, &psk(v)).unwrap();
                assert_eq!(
                    got,
                    payload::<16>(&v.messages[0].payload),
                    concat!("NNpsk0/", $suite, " responder msg1 payload")
                );

                let (msg2, mut transport) = hs
                    .write_message_2(&payload(&v.messages[1].payload))
                    .unwrap();
                assert_wire(
                    &msg2,
                    &v.messages[1].ciphertext,
                    concat!("NNpsk0/", $suite, " responder msg2"),
                );

                assert_session_id(&transport, v);
                replay_transport(&mut transport, v, 2, false, Side::Responder);
            }

            /// `NNpsk2` from the other side: the psk token sits in the
            /// message we *write*, so it is a writer argument here.
            #[test]
            fn cacophony_nnpsk2_responder() {
                let file = load();
                let v = load_vector(&file, concat!("Noise_NNpsk2_", $suite));

                let hs = NNpsk2::responder(resp_provider(v), &prologue(v));

                let msg1 = frozen(&v.messages[0].ciphertext);
                let (got, hs) = hs.read_message_1(&msg1).unwrap();
                assert_eq!(
                    got,
                    payload::<16>(&v.messages[0].payload),
                    concat!("NNpsk2/", $suite, " responder msg1 payload")
                );

                let (msg2, mut transport) = hs
                    .write_message_2(&psk(v), &payload(&v.messages[1].payload))
                    .unwrap();
                assert_wire(
                    &msg2,
                    &v.messages[1].ciphertext,
                    concat!("NNpsk2/", $suite, " responder msg2"),
                );

                assert_session_id(&transport, v);
                replay_transport(&mut transport, v, 2, false, Side::Responder);
            }

            /// `XXpsk3` from the other side: the final read carries `s`,
            /// `se` *and* the psk, so — as with `IKpsk1`'s msg1 — the plain
            /// read takes the PSK as an argument and reveals the initiator's
            /// static onto the transport.
            #[test]
            fn cacophony_xxpsk3_responder() {
                let file = load();
                let v = load_vector(&file, concat!("Noise_XXpsk3_", $suite));

                let hs = XXpsk3::responder(resp_provider(v), &prologue(v));

                let msg1 = frozen(&v.messages[0].ciphertext);
                let (got, hs) = hs.read_message_1(&msg1).unwrap();
                assert_eq!(
                    got,
                    payload::<16>(&v.messages[0].payload),
                    concat!("XXpsk3/", $suite, " responder msg1 payload")
                );

                let (msg2, hs) = hs
                    .write_message_2(resp_static(v), &payload(&v.messages[1].payload))
                    .unwrap();
                assert_wire(
                    &msg2,
                    &v.messages[1].ciphertext,
                    concat!("XXpsk3/", $suite, " responder msg2"),
                );

                let msg3 = frozen(&v.messages[2].ciphertext);
                let (got, mut transport) = hs.read_message_3(&msg3, &psk(v)).unwrap();
                assert_eq!(
                    got,
                    payload::<11>(&v.messages[2].payload),
                    concat!("XXpsk3/", $suite, " responder msg3 payload")
                );
                assert_eq!(
                    transport.remote_static().unwrap().as_bytes(),
                    init_static(v).public_key().as_bytes(),
                    concat!("XXpsk3/", $suite, " revealed initiator static")
                );

                assert_session_id(&transport, v);
                replay_transport(&mut transport, v, 3, false, Side::Responder);
            }
        }
    };
}

cacophony_suite!(
    x25519_blake2b,
    X25519,
    SoftwareX25519PrivateKey,
    Blake2b,
    "25519_ChaChaPoly_BLAKE2b"
);
cacophony_suite!(
    x25519_blake2s,
    X25519,
    SoftwareX25519PrivateKey,
    Blake2s,
    "25519_ChaChaPoly_BLAKE2s"
);
cacophony_suite!(
    x25519_sha256,
    X25519,
    SoftwareX25519PrivateKey,
    Sha256,
    "25519_ChaChaPoly_SHA256"
);
cacophony_suite!(
    x25519_sha512,
    X25519,
    SoftwareX25519PrivateKey,
    Sha512,
    "25519_ChaChaPoly_SHA512"
);
cacophony_suite!(
    x448_blake2b,
    X448,
    SoftwareX448PrivateKey,
    Blake2b,
    "448_ChaChaPoly_BLAKE2b"
);
cacophony_suite!(
    x448_blake2s,
    X448,
    SoftwareX448PrivateKey,
    Blake2s,
    "448_ChaChaPoly_BLAKE2s"
);
cacophony_suite!(
    x448_sha256,
    X448,
    SoftwareX448PrivateKey,
    Sha256,
    "448_ChaChaPoly_SHA256"
);
cacophony_suite!(
    x448_sha512,
    X448,
    SoftwareX448PrivateKey,
    Sha512,
    "448_ChaChaPoly_SHA512"
);

// ── Extractor (reproduces the vendored subset) ───────────────────

/// Re-derive `tests/vectors/cacophony/cacophony.json` from an upstream
/// corpus, so the filter is reproducible rather than trusted.
///
/// ```text
/// CACOPHONY_SRC=~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/\
///   snow-0.10.0/tests/vectors/cacophony.txt \
///   cargo test --all-features --test noise_cacophony \
///   extract_cacophony_subset -- --ignored
/// ```
///
/// Upstream order is preserved and values are re-emitted verbatim; only
/// whitespace and the absent-`Option` elisions differ from the source.
#[cfg(test)]
mod extract {
    use super::*;

    const PATTERNS: [&str; 20] = [
        "N", "K", "Kpsk0", "IKpsk1", "IK", "NK", "IX", "XK", "NN", "XX", "X", "NX", "XN", "KN",
        "KK", "KX", "IN", "NNpsk0", "NNpsk2", "XXpsk3",
    ];
    const SUITES: [&str; 8] = [
        "25519_ChaChaPoly_BLAKE2b",
        "25519_ChaChaPoly_BLAKE2s",
        "25519_ChaChaPoly_SHA256",
        "25519_ChaChaPoly_SHA512",
        "448_ChaChaPoly_BLAKE2b",
        "448_ChaChaPoly_BLAKE2s",
        "448_ChaChaPoly_SHA256",
        "448_ChaChaPoly_SHA512",
    ];

    #[test]
    #[ignore = "regenerates the vendored corpus from an upstream cacophony.txt"]
    fn extract_cacophony_subset() {
        let src =
            std::env::var("CACOPHONY_SRC").expect("set CACOPHONY_SRC to an upstream cacophony.txt");
        let raw = std::fs::read_to_string(&src).expect("read CACOPHONY_SRC");
        let mut file: VectorFile = serde_json::from_str(&raw).expect("valid cacophony json");

        let wanted: Vec<String> = PATTERNS
            .iter()
            .flat_map(|p| SUITES.iter().map(move |s| format!("Noise_{p}_{s}")))
            .collect();
        file.vectors.retain(|v| wanted.contains(&v.protocol_name));

        // The filter is a claim about the corpus, so it is checked rather
        // than assumed: a source missing a cell would otherwise vendor a
        // quietly smaller matrix.
        assert_eq!(
            file.vectors.len(),
            wanted.len(),
            "expected 20 patterns × 8 ChaChaPoly suites"
        );
        for v in &file.vectors {
            check_invariants(v);
        }

        let mut out = serde_json::to_string_pretty(&file).expect("serialize");
        out.push('\n');
        std::fs::write(VECTORS_PATH, out).expect("write vendored corpus");
    }
}
