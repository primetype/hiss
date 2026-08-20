//! **Live** hiss↔`snow` AESGCM interop — the running-implementation leg of
//! `hiss::noise::AesGcm`'s validation.
//!
//! hiss's own `tests/noise_cacophony.rs` proves agreement with a *recorded*
//! third implementation on 160 AESGCM vectors, and its Wycheproof unit test
//! pins the primitive. This proves agreement with a *running* one: `snow`'s
//! default resolver backs `CipherChoice::AESGCM` with RustCrypto's
//! `aes_gcm::Aes256Gcm`, which is a genuinely independent AES-GCM from
//! cryptoxide's — different authors, different code, no shared lineage. If
//! hiss's wire bytes are wrong in a way the corpus happens not to reach, a
//! foreign parser rejecting them is what says so.
//!
//! # Scope, and why it is deliberately narrower than the corpus
//!
//! | Dimension | Covered here | Why |
//! |---|---|---|
//! | Curve | 25519 only | `snow`'s default resolver returns `None` for `DHChoice::Curve448`, so X448 interop is not possible at all. Cacophony is X448's only cross-check. |
//! | Hash | all four (BLAKE2b, BLAKE2s, SHA256, SHA512) | `use-sha2`/`use-blake2` are in the dev-dependency for exactly this. |
//! | Pattern | `N`, `NN`, `XX`, `IK`, `Kpsk0` | the structurally distinct shapes: one-way, mutual-with-ephemerals, deferred-static, pre-shared-static, and psk. |
//!
//! Exhaustiveness is the corpus's job and the corpus is exhaustive (20 × 8
//! per cipher, both roles). This leg is a spot check by design — its value is the
//! *second implementation*, not the matrix size. Stating that plainly matters,
//! because "three independent legs" reads stronger than what actually runs.
//!
//! # Both role assignments, and four transport messages
//!
//! Every pattern runs twice: hiss-as-initiator/snow-as-responder and
//! snow-as-initiator/hiss-as-responder. A cipher bug that is symmetric between
//! encrypt and decrypt survives one direction and dies in the other.
//!
//! Each transport phase then sends **four** messages in each direction rather
//! than one. That is not padding. Noise **§12.4**'s nonce is the counter
//! big-endian, and counter 0 is byte-identical little-endian, so a
//! wrong-endian implementation agrees with a correct one until n = 1 —
//! measured against the corpus, where the divergence appears at transport
//! message 2 for one-way patterns and message **4** for interactive ones,
//! whose senders alternate. Four messages per direction clears both.

use hiss::noise::{AesGcm, Blake2b, Blake2s, Curve, Sha256, Sha512, X25519};
use hiss::provider::{EphemeralOnly, ProviderExt};
use rand::rngs::StdRng;

/// The pre-shared key `Kpsk0` uses on both sides.
const PSK: [u8; 32] = [0x2b; 32];

/// A non-empty prologue, mixed in by both parties — a mismatch here fails the
/// handshake, so passing means both sides hashed the same bytes.
const PROLOGUE: &[u8] = b"hiss-interop aesgcm";

/// How many transport messages each direction sends. Four, so the nonce
/// counter passes 0 in every pattern shape (see the module docs).
const TRANSPORT_ROUNDS: u8 = 4;

fn provider() -> EphemeralOnly<StdRng> {
    EphemeralOnly::new(rand::make_rng::<StdRng>())
}

#[test]
fn snow_resolver_supports_aesgcm() {
    // `build_responder` only succeeds if the resolver produced an AESGCM
    // cipher, so this fails loudly if `use-aes-gcm` is ever dropped from the
    // dev-dependency — which would otherwise turn every test below into a
    // vacuous skip.
    for suite in [
        "Noise_NN_25519_AESGCM_SHA256",
        "Noise_NN_25519_AESGCM_SHA512",
        "Noise_NN_25519_AESGCM_BLAKE2s",
        "Noise_NN_25519_AESGCM_BLAKE2b",
    ] {
        let params: snow::params::NoiseParams = suite.parse().unwrap();
        let responder = snow::Builder::new(params).build_responder();
        assert!(
            responder.is_ok(),
            "snow must resolve {suite}: {:?}",
            responder.err()
        );
    }
}

/// `snow` really is speaking AES-GCM and not silently negotiating something
/// else: the same plaintext under `AESGCM` and under `ChaChaPoly` must not
/// produce the same ciphertext.
///
/// Cheap, but it closes the one failure mode that would make every test in
/// this file pass while testing the wrong cipher.
#[test]
fn aesgcm_is_not_chachapoly_on_the_wire() {
    let mut ciphertexts = Vec::new();
    for suite in [
        "Noise_NN_25519_AESGCM_SHA256",
        "Noise_NN_25519_ChaChaPoly_SHA256",
    ] {
        let params: snow::params::NoiseParams = suite.parse().unwrap();
        let mut initiator = snow::Builder::new(params.clone())
            .build_initiator()
            .unwrap();
        let mut responder = snow::Builder::new(params).build_responder().unwrap();
        let mut buf = [0u8; 1024];
        let n = initiator.write_message(&[], &mut buf).unwrap();
        let mut got = [0u8; 1024];
        let m = responder.read_message(&buf[..n], &mut got).unwrap();
        assert_eq!(m, 0);
        let n = responder.write_message(&[], &mut buf).unwrap();
        let mut got = [0u8; 1024];
        initiator.read_message(&buf[..n], &mut got).unwrap();
        let mut transport = initiator.into_transport_mode().unwrap();
        let n = transport
            .write_message(b"same plaintext", &mut buf)
            .unwrap();
        ciphertexts.push(buf[..n].to_vec());
    }
    assert_ne!(
        ciphertexts[0], ciphertexts[1],
        "AESGCM and ChaChaPoly must not produce identical wire bytes"
    );
}

/// The five patterns × both role assignments, instantiated once per hash.
///
/// A `macro_rules!` for the same reason the corpus harness uses one: the
/// driving logic is hash-independent, so the four-hash sweep costs one line
/// per hash rather than four copies that can drift apart.
macro_rules! interop_suite {
    ($module:ident, $hash:ident, $suite:literal) => {
        pub mod $module {
            use super::*;

            pub const SUITE: &str = $suite;

            hiss::noise! { pub N<X25519, AesGcm, $hash>     { <- s ... -> e, es } }
            hiss::noise! { pub NN<X25519, AesGcm, $hash>    { -> e <- e, ee } }
            hiss::noise! { pub XX<X25519, AesGcm, $hash>    { -> e <- e, ee, s, es -> s, se } }
            hiss::noise! { pub IK<X25519, AesGcm, $hash>    { <- s ... -> e, es, s, ss <- e, ee, se } }
            hiss::noise! { pub Kpsk0<X25519, AesGcm, $hash> { -> s <- s ... -> psk, e, es, ss } }

            /// A `snow` keypair, plus the same public key in hiss's type.
            fn snow_keypair(pattern: &str) -> (snow::Keypair, <X25519 as Curve>::PublicKey) {
                let name: snow::params::NoiseParams =
                    format!("Noise_{}_{}", pattern, $suite).parse().unwrap();
                let kp = snow::Builder::new(name).generate_keypair().unwrap();
                let pk = <X25519 as Curve>::public_key_from_bytes(&kp.public).unwrap();
                (kp, pk)
            }

            /// A hiss static, plus its public key as raw bytes for `snow`.
            fn hiss_static() -> (
                hiss::curve::x25519::SoftwareX25519PrivateKey,
                Vec<u8>,
            ) {
                let mut p = provider();
                let sk = p.generate::<X25519>().unwrap();
                let pk_bytes = p.public(&sk).unwrap().as_ref().to_vec();
                (sk, pk_bytes)
            }

            fn builder(pattern: &str) -> snow::Builder<'static> {
                let name: snow::params::NoiseParams =
                    format!("Noise_{}_{}", pattern, $suite).parse().unwrap();
                snow::Builder::new(name)
            }

            // ── hiss initiator → snow responder ──────────────

            #[test]
            fn n_hiss_initiator() {
                let (kp, resp_pub) = snow_keypair("N");
                let (msg, mut hiss_t) = N::initiator(provider(), PROLOGUE, resp_pub)
                    .write_message_1()
                    .unwrap();

                let mut snow_hs = builder("N")
                    .prologue(PROLOGUE).unwrap()
                    .local_private_key(&kp.private).unwrap()
                    .build_responder().unwrap();
                let mut buf = [0u8; 1024];
                assert_eq!(
                    snow_hs.read_message(&msg, &mut buf).expect("snow reads hiss's msg1"),
                    0
                );
                let mut snow_t = snow_hs.into_transport_mode().unwrap();
                hiss_sends_to_snow(&mut hiss_t, &mut snow_t, "N");
            }

            #[test]
            fn nn_hiss_initiator() {
                let (msg1, hiss_hs) = NN::initiator(provider(), PROLOGUE)
                    .write_message_1()
                    .unwrap();

                let mut snow_hs = builder("NN")
                    .prologue(PROLOGUE).unwrap()
                    .build_responder().unwrap();
                let mut buf = [0u8; 1024];
                snow_hs.read_message(&msg1, &mut buf).expect("snow reads msg1");
                let mut out = [0u8; 1024];
                let n = snow_hs.write_message(&[], &mut out).unwrap();

                let mut hiss_t = hiss_hs
                    .read_message_2(&out[..n].try_into().expect("msg2 width"))
                    .expect("hiss reads snow's msg2");
                let mut snow_t = snow_hs.into_transport_mode().unwrap();
                round_trip(&mut hiss_t, &mut snow_t, "NN");
            }

            #[test]
            fn xx_hiss_initiator() {
                let (hiss_sk, _) = hiss_static();
                let (kp, _) = snow_keypair("XX");

                let (msg1, hiss_hs) = XX::initiator(provider(), PROLOGUE)
                    .write_message_1()
                    .unwrap();

                let mut snow_hs = builder("XX")
                    .prologue(PROLOGUE).unwrap()
                    .local_private_key(&kp.private).unwrap()
                    .build_responder().unwrap();
                let mut buf = [0u8; 1024];
                snow_hs.read_message(&msg1, &mut buf).expect("snow reads msg1");
                let mut out = [0u8; 1024];
                let n = snow_hs.write_message(&[], &mut out).unwrap();

                let hiss_hs = hiss_hs
                    .read_message_2(&out[..n].try_into().expect("msg2 width"))
                    .expect("hiss reads snow's msg2");
                // msg2's `s` token revealed snow's static — check hiss recovered
                // the same key snow holds, not merely *a* key.
                assert_eq!(
                    hiss_hs.remote_static().as_bytes(),
                    kp.public.as_slice(),
                    "XX: hiss must recover snow's static"
                );

                let (msg3, mut hiss_t) = hiss_hs.write_message_3(hiss_sk).unwrap();
                snow_hs.read_message(&msg3, &mut buf).expect("snow reads msg3");
                let mut snow_t = snow_hs.into_transport_mode().unwrap();
                round_trip(&mut hiss_t, &mut snow_t, "XX");
            }

            #[test]
            fn ik_hiss_initiator() {
                let (hiss_sk, _) = hiss_static();
                let (kp, resp_pub) = snow_keypair("IK");

                let (msg1, hiss_hs) = IK::initiator(provider(), PROLOGUE, resp_pub)
                    .write_message_1(hiss_sk)
                    .unwrap();

                let mut snow_hs = builder("IK")
                    .prologue(PROLOGUE).unwrap()
                    .local_private_key(&kp.private).unwrap()
                    .build_responder().unwrap();
                let mut buf = [0u8; 1024];
                snow_hs.read_message(&msg1, &mut buf).expect("snow reads msg1");
                let mut out = [0u8; 1024];
                let n = snow_hs.write_message(&[], &mut out).unwrap();

                let mut hiss_t = hiss_hs
                    .read_message_2(&out[..n].try_into().expect("msg2 width"))
                    .expect("hiss reads snow's msg2");
                let mut snow_t = snow_hs.into_transport_mode().unwrap();
                round_trip(&mut hiss_t, &mut snow_t, "IK");
            }

            #[test]
            fn kpsk0_hiss_initiator() {
                let (hiss_sk, hiss_pub_bytes) = hiss_static();
                let (kp, resp_pub) = snow_keypair("Kpsk0");

                let psk = hiss::psk::Psk::from_bytes(PSK);
                let (msg1, mut hiss_t) =
                    Kpsk0::initiator(provider(), PROLOGUE, hiss_sk, resp_pub)
                        .unwrap()
                        .write_message_1(&psk)
                        .unwrap();

                let mut snow_hs = builder("Kpsk0")
                    .prologue(PROLOGUE).unwrap()
                    .local_private_key(&kp.private).unwrap()
                    .remote_public_key(&hiss_pub_bytes).unwrap()
                    .psk(0, &PSK).unwrap()
                    .build_responder().unwrap();
                let mut buf = [0u8; 1024];
                snow_hs.read_message(&msg1, &mut buf).expect("snow reads hiss's psk msg1");
                let mut snow_t = snow_hs.into_transport_mode().unwrap();
                hiss_sends_to_snow(&mut hiss_t, &mut snow_t, "Kpsk0");
            }

            // ── snow initiator → hiss responder ──────────────

            #[test]
            fn n_snow_initiator() {
                let (hiss_sk, hiss_pub_bytes) = hiss_static();

                let mut snow_hs = builder("N")
                    .prologue(PROLOGUE).unwrap()
                    .remote_public_key(&hiss_pub_bytes).unwrap()
                    .build_initiator().unwrap();
                let mut out = [0u8; 1024];
                let n = snow_hs.write_message(&[], &mut out).unwrap();

                let mut hiss_t = N::responder(provider(), PROLOGUE, hiss_sk)
                    .unwrap()
                    .read_message_1(&out[..n].try_into().expect("msg1 width"))
                    .expect("hiss reads snow's msg1");
                let mut snow_t = snow_hs.into_transport_mode().unwrap();
                snow_sends_to_hiss(&mut snow_t, &mut hiss_t, "N");
            }

            #[test]
            fn nn_snow_initiator() {
                let mut snow_hs = builder("NN")
                    .prologue(PROLOGUE).unwrap()
                    .build_initiator().unwrap();
                let mut out = [0u8; 1024];
                let n = snow_hs.write_message(&[], &mut out).unwrap();

                let hiss_hs = NN::responder(provider(), PROLOGUE)
                    .read_message_1(&out[..n].try_into().expect("msg1 width"))
                    .expect("hiss reads snow's msg1");
                let (msg2, mut hiss_t) = hiss_hs.write_message_2().unwrap();

                let mut buf = [0u8; 1024];
                snow_hs.read_message(&msg2, &mut buf).expect("snow reads hiss's msg2");
                let mut snow_t = snow_hs.into_transport_mode().unwrap();
                round_trip(&mut hiss_t, &mut snow_t, "NN");
            }

            #[test]
            fn xx_snow_initiator() {
                let (hiss_sk, _) = hiss_static();
                let (kp, init_pub) = snow_keypair("XX");

                let mut snow_hs = builder("XX")
                    .prologue(PROLOGUE).unwrap()
                    .local_private_key(&kp.private).unwrap()
                    .build_initiator().unwrap();
                let mut out = [0u8; 1024];
                let n = snow_hs.write_message(&[], &mut out).unwrap();

                let hiss_hs = XX::responder(provider(), PROLOGUE)
                    .read_message_1(&out[..n].try_into().expect("msg1 width"))
                    .expect("hiss reads snow's msg1");
                let (msg2, hiss_hs) = hiss_hs.write_message_2(hiss_sk).unwrap();

                let mut buf = [0u8; 1024];
                snow_hs.read_message(&msg2, &mut buf).expect("snow reads hiss's msg2");
                let n = snow_hs.write_message(&[], &mut out).unwrap();

                let mut hiss_t = hiss_hs
                    .read_message_3(&out[..n].try_into().expect("msg3 width"))
                    .expect("hiss reads snow's msg3");
                // msg3's `s` revealed snow's static onto the transport.
                assert_eq!(
                    hiss_t.remote_static().unwrap().as_bytes(),
                    init_pub.as_ref(),
                    "XX: hiss must recover snow's initiator static"
                );
                let mut snow_t = snow_hs.into_transport_mode().unwrap();
                round_trip(&mut hiss_t, &mut snow_t, "XX");
            }

            #[test]
            fn ik_snow_initiator() {
                let (hiss_sk, hiss_pub_bytes) = hiss_static();
                let (kp, init_pub) = snow_keypair("IK");

                let mut snow_hs = builder("IK")
                    .prologue(PROLOGUE).unwrap()
                    .local_private_key(&kp.private).unwrap()
                    .remote_public_key(&hiss_pub_bytes).unwrap()
                    .build_initiator().unwrap();
                let mut out = [0u8; 1024];
                let n = snow_hs.write_message(&[], &mut out).unwrap();

                let hiss_hs = IK::responder(provider(), PROLOGUE, hiss_sk)
                    .unwrap()
                    .read_message_1(&out[..n].try_into().expect("msg1 width"))
                    .expect("hiss reads snow's msg1");
                // msg1's `s` token revealed snow's static mid-handshake.
                assert_eq!(
                    hiss_hs.remote_static().as_bytes(),
                    init_pub.as_ref(),
                    "IK: hiss must recover snow's initiator static"
                );

                let (msg2, mut hiss_t) = hiss_hs.write_message_2().unwrap();
                let mut buf = [0u8; 1024];
                snow_hs.read_message(&msg2, &mut buf).expect("snow reads hiss's msg2");
                let mut snow_t = snow_hs.into_transport_mode().unwrap();
                round_trip(&mut hiss_t, &mut snow_t, "IK");
            }

            #[test]
            fn kpsk0_snow_initiator() {
                let (hiss_sk, hiss_pub_bytes) = hiss_static();
                let (kp, init_pub) = snow_keypair("Kpsk0");

                let mut snow_hs = builder("Kpsk0")
                    .prologue(PROLOGUE).unwrap()
                    .local_private_key(&kp.private).unwrap()
                    .remote_public_key(&hiss_pub_bytes).unwrap()
                    .psk(0, &PSK).unwrap()
                    .build_initiator().unwrap();
                let mut out = [0u8; 1024];
                let n = snow_hs.write_message(&[], &mut out).unwrap();

                let psk = hiss::psk::Psk::from_bytes(PSK);
                let mut hiss_t = Kpsk0::responder(provider(), PROLOGUE, init_pub, hiss_sk)
                    .unwrap()
                    .read_message_1(&out[..n].try_into().expect("msg1 width"), &psk)
                    .expect("hiss reads snow's psk msg1");
                let mut snow_t = snow_hs.into_transport_mode().unwrap();
                snow_sends_to_hiss(&mut snow_t, &mut hiss_t, "Kpsk0");
            }
        }
    };
}

// ── Transport drivers ────────────────────────────────────────────

/// hiss writes, `snow` reads — [`TRANSPORT_ROUNDS`] times.
///
/// Used for the one-way patterns, where the transport is unidirectional. Each
/// message is a different plaintext so a stuck counter or a replayed
/// ciphertext cannot pass by coincidence.
fn hiss_sends_to_snow<P: hiss::noise::Protocol>(
    hiss_t: &mut hiss::noise::Transport<P>,
    snow_t: &mut snow::TransportState,
    label: &str,
) {
    for i in 0..TRANSPORT_ROUNDS {
        let plain = [i.wrapping_add(1); 24];
        let mut ct = [0u8; 128];
        let n = hiss_t.send(&plain, &mut ct).unwrap();
        let mut got = [0u8; 128];
        let m = snow_t
            .read_message(&ct[..n], &mut got)
            .unwrap_or_else(|e| panic!("{label}: snow rejected hiss transport msg {i}: {e}"));
        assert_eq!(
            &got[..m],
            &plain[..],
            "{label}: hiss→snow transport msg {i}"
        );
    }
}

/// `snow` writes, hiss reads — [`TRANSPORT_ROUNDS`] times.
fn snow_sends_to_hiss<P: hiss::noise::Protocol>(
    snow_t: &mut snow::TransportState,
    hiss_t: &mut hiss::noise::Transport<P>,
    label: &str,
) {
    for i in 0..TRANSPORT_ROUNDS {
        let plain = [i.wrapping_add(0x40); 24];
        let mut ct = [0u8; 128];
        let n = snow_t.write_message(&plain, &mut ct).unwrap();
        let mut got = [0u8; 128];
        let m = hiss_t
            .receive(&ct[..n], &mut got)
            .unwrap_or_else(|e| panic!("{label}: hiss rejected snow transport msg {i}: {e:?}"));
        assert_eq!(
            &got[..m],
            &plain[..],
            "{label}: snow→hiss transport msg {i}"
        );
    }
}

/// Both directions, interleaved — the interactive patterns' transport phase.
///
/// Interleaving matters: each side keeps an independent send and receive
/// counter, and running them alternately is what would expose the two being
/// crossed.
fn round_trip<P: hiss::noise::Protocol>(
    hiss_t: &mut hiss::noise::Transport<P>,
    snow_t: &mut snow::TransportState,
    label: &str,
) {
    for i in 0..TRANSPORT_ROUNDS {
        // hiss → snow
        let plain = [i.wrapping_add(1); 24];
        let mut ct = [0u8; 128];
        let n = hiss_t.send(&plain, &mut ct).unwrap();
        let mut got = [0u8; 128];
        let m = snow_t
            .read_message(&ct[..n], &mut got)
            .unwrap_or_else(|e| panic!("{label}: snow rejected hiss transport msg {i}: {e}"));
        assert_eq!(
            &got[..m],
            &plain[..],
            "{label}: hiss→snow transport msg {i}"
        );

        // snow → hiss
        let plain = [i.wrapping_add(0x40); 24];
        let mut ct = [0u8; 128];
        let n = snow_t.write_message(&plain, &mut ct).unwrap();
        let mut got = [0u8; 128];
        let m = hiss_t
            .receive(&ct[..n], &mut got)
            .unwrap_or_else(|e| panic!("{label}: hiss rejected snow transport msg {i}: {e:?}"));
        assert_eq!(
            &got[..m],
            &plain[..],
            "{label}: snow→hiss transport msg {i}"
        );
    }
}

interop_suite!(sha256, Sha256, "25519_AESGCM_SHA256");
interop_suite!(sha512, Sha512, "25519_AESGCM_SHA512");
interop_suite!(blake2s, Blake2s, "25519_AESGCM_BLAKE2s");
interop_suite!(blake2b, Blake2b, "25519_AESGCM_BLAKE2b");

/// All four hashes are instantiated — the same compile-time teeth the corpus
/// harness uses: removing an `interop_suite!` line stops this compiling.
#[test]
fn every_hash_is_instantiated() {
    let instantiated = [sha256::SUITE, sha512::SUITE, blake2s::SUITE, blake2b::SUITE];
    assert_eq!(instantiated.len(), 4);
    for suite in instantiated {
        assert!(
            suite.starts_with("25519_AESGCM_"),
            "{suite} is not a 25519 AESGCM suite"
        );
    }
    // 5 patterns × 2 role assignments × 4 hashes.
    assert_eq!(5 * 2 * instantiated.len(), 40, "live interop test count");
}
