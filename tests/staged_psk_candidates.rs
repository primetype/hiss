//! Acceptance coverage for choosing between two PSKs at a staged,
//! trailing-`psk` responder completion.
//!
//! A payload-bearing IKpsk1 shape makes the return-value contract explicit:
//! `complete_with_psk_candidates` adds the selected index around the ordinary
//! `(authenticated_payload, next_state)` output without flattening or changing
//! it. Deterministic providers also pin that candidate selection leaves no
//! trace in the handshake bytes, session binding, or transport keys.

use std::cell::Cell;
use std::rc::Rc;

use hiss::curve::{Curve, DhCurve};
use hiss::noise::{Blake2b, ChaChaPoly, HandshakeError, Transport, X25519};
use hiss::provider::{CryptoKeyProvider, DhProvider, EphemeralOnly, ProviderExt};
use hiss::psk::Psk;
use rand::SeedableRng;
use rand::rngs::StdRng;

hiss::noise! {
    pub IKpsk1Payload<X25519, ChaChaPoly, Blake2b> {
        <- s
        ...
        -> e, es, s, ss, psk [12]
        <- e, ee, se
    }
}

const PROLOGUE: &[u8] = b"hiss staged psk candidates";
const GOOD_PSK: [u8; 32] = [0x5A; 32];
const BAD_PSK_1: [u8; 32] = [0xA5; 32];
const BAD_PSK_2: [u8; 32] = [0x3C; 32];
const AUTHENTICATED_PAYLOAD: [u8; 12] = *b"candidate-ok";
const TRANSPORT_PAYLOAD: &[u8] = b"same transcript, same transport";

fn provider(seed: u64) -> EphemeralOnly<StdRng> {
    EphemeralOnly::new(StdRng::seed_from_u64(seed))
}

/// Wrap a provider and expose how many DH operations the responder paid.
struct CountingDh<P> {
    inner: P,
    dhs: Rc<Cell<usize>>,
}

impl<C: Curve, P: CryptoKeyProvider<C>> CryptoKeyProvider<C> for CountingDh<P> {
    type Error = P::Error;
    type PrivateKey = P::PrivateKey;

    fn public_key(&self, key: &Self::PrivateKey) -> Result<C::PublicKey, Self::Error> {
        self.inner.public_key(key)
    }

    fn generate_static_key(&mut self) -> Result<Self::PrivateKey, Self::Error> {
        self.inner.generate_static_key()
    }

    fn generate_ephemeral_key(&mut self) -> Result<Self::PrivateKey, Self::Error> {
        self.inner.generate_ephemeral_key()
    }
}

impl<C: DhCurve, P: DhProvider<C>> DhProvider<C> for CountingDh<P> {
    fn dh(
        &self,
        key: &Self::PrivateKey,
        peer: &C::PublicKey,
    ) -> Result<C::SharedSecret, Self::Error> {
        self.dhs.set(self.dhs.get() + 1);
        self.inner.dh(key, peer)
    }
}

enum Completion<'a> {
    Ordinary(&'a Psk),
    Candidates([&'a Psk; 2]),
}

struct SuccessfulRun {
    selected: Option<usize>,
    authenticated_payload: [u8; 12],
    message_1: Vec<u8>,
    message_2: Vec<u8>,
    session_id: Vec<u8>,
    transport_record: Vec<u8>,
    dhs_after_intro: usize,
    dhs_after_complete: usize,
}

fn successful_run(completion: Completion<'_>) -> SuccessfulRun {
    // Fixed seeds reproduce the whole handshake, including both ephemeral
    // keys, so ordinary and candidate completion can be compared bytewise.
    let mut initiator_provider = provider(101);
    let initiator_static = initiator_provider.generate::<X25519>().unwrap();
    let mut responder_provider = provider(202);
    let responder_static = responder_provider.generate::<X25519>().unwrap();
    let responder_public = responder_provider.public(&responder_static).unwrap();
    let good = Psk::from_bytes(GOOD_PSK);

    let (message_1, initiator) =
        IKpsk1Payload::initiator(initiator_provider, PROLOGUE, responder_public)
            .write_message_1(initiator_static, &good, &AUTHENTICATED_PAYLOAD)
            .unwrap();

    let dhs = Rc::new(Cell::new(0));
    let counting_provider = CountingDh {
        inner: responder_provider,
        dhs: dhs.clone(),
    };
    let (_, mid) = IKpsk1Payload::responder(counting_provider, PROLOGUE, responder_static)
        .unwrap()
        .read_message_1_intro(&message_1)
        .unwrap();
    let dhs_after_intro = dhs.get();

    let (selected, ordinary_output) = match completion {
        Completion::Ordinary(psk) => (None, mid.complete(psk).unwrap()),
        Completion::Candidates(candidates) => {
            let (selected, output) = mid.complete_with_psk_candidates(candidates).unwrap();
            (Some(selected), output)
        }
    };
    // Destructuring this as one second element is intentional: the candidate
    // API must preserve exactly the ordinary complete output.
    let (authenticated_payload, responder) = ordinary_output;
    let dhs_after_complete = dhs.get();

    let (message_2, mut responder_transport) = responder.write_message_2().unwrap();
    let mut initiator_transport = initiator.read_message_2(&message_2).unwrap();
    assert_eq!(
        initiator_transport.session_id(),
        responder_transport.session_id(),
        "both peers must derive the same session binding",
    );
    let session_id = responder_transport.session_id().as_ref().to_vec();

    let mut transport_record =
        vec![0u8; TRANSPORT_PAYLOAD.len() + Transport::<IKpsk1Payload>::OVERHEAD];
    let record_len = responder_transport
        .send(TRANSPORT_PAYLOAD, &mut transport_record)
        .unwrap();
    transport_record.truncate(record_len);
    let mut opened = vec![0u8; TRANSPORT_PAYLOAD.len()];
    let opened_len = initiator_transport
        .receive(&transport_record, &mut opened)
        .unwrap();
    assert_eq!(&opened[..opened_len], TRANSPORT_PAYLOAD);

    SuccessfulRun {
        selected,
        authenticated_payload,
        message_1: message_1.to_vec(),
        message_2: message_2.to_vec(),
        session_id,
        transport_record,
        dhs_after_intro,
        dhs_after_complete,
    }
}

#[test]
fn second_candidate_matches_ordinary_wire_state_and_pays_ss_once() {
    let good = Psk::from_bytes(GOOD_PSK);
    let bad = Psk::from_bytes(BAD_PSK_1);

    let ordinary = successful_run(Completion::Ordinary(&good));
    let candidates = successful_run(Completion::Candidates([&bad, &good]));

    assert_eq!(candidates.selected, Some(1));
    assert_eq!(candidates.authenticated_payload, AUTHENTICATED_PAYLOAD);
    assert_eq!(ordinary.authenticated_payload, AUTHENTICATED_PAYLOAD);
    assert_eq!(candidates.message_1, ordinary.message_1);
    assert_eq!(candidates.message_2, ordinary.message_2);
    assert_eq!(candidates.session_id, ordinary.session_id);
    assert_eq!(candidates.transport_record, ordinary.transport_record);

    assert_eq!(candidates.dhs_after_intro, 1, "intro pays only `es`");
    assert_eq!(
        candidates.dhs_after_complete - candidates.dhs_after_intro,
        1,
        "candidate completion must pay `ss` once, not once per candidate",
    );
}

#[test]
fn equal_candidates_select_the_first() {
    let good = Psk::from_bytes(GOOD_PSK);
    let run = successful_run(Completion::Candidates([&good, &good]));

    assert_eq!(run.selected, Some(0));
    assert_eq!(run.authenticated_payload, AUTHENTICATED_PAYLOAD);
    assert_eq!(run.dhs_after_intro, 1);
    assert_eq!(run.dhs_after_complete, 2);
}

fn failing_run(completion: Completion<'_>) -> (Result<(), HandshakeError>, usize, usize) {
    let mut initiator_provider = provider(303);
    let initiator_static = initiator_provider.generate::<X25519>().unwrap();
    let mut responder_provider = provider(404);
    let responder_static = responder_provider.generate::<X25519>().unwrap();
    let responder_public = responder_provider.public(&responder_static).unwrap();
    let good = Psk::from_bytes(GOOD_PSK);

    let (message_1, _) = IKpsk1Payload::initiator(initiator_provider, PROLOGUE, responder_public)
        .write_message_1(initiator_static, &good, &AUTHENTICATED_PAYLOAD)
        .unwrap();

    let dhs = Rc::new(Cell::new(0));
    let counting_provider = CountingDh {
        inner: responder_provider,
        dhs: dhs.clone(),
    };
    let (_, mid) = IKpsk1Payload::responder(counting_provider, PROLOGUE, responder_static)
        .unwrap()
        .read_message_1_intro(&message_1)
        .unwrap();
    let dhs_after_intro = dhs.get();

    // Mapping success to unit keeps the assertion focused on the Result:
    // an error carries neither the authenticated payload nor the next state.
    let result = match completion {
        Completion::Ordinary(psk) => mid.complete(psk).map(|_| ()),
        Completion::Candidates(candidates) => {
            mid.complete_with_psk_candidates(candidates).map(|_| ())
        }
    };
    let dhs_after_complete = dhs.get();

    (result, dhs_after_intro, dhs_after_complete)
}

#[test]
fn all_candidates_fail_like_ordinary_completion_without_output() {
    let bad_1 = Psk::from_bytes(BAD_PSK_1);
    let bad_2 = Psk::from_bytes(BAD_PSK_2);

    let (ordinary, ordinary_intro_dhs, ordinary_complete_dhs) =
        failing_run(Completion::Ordinary(&bad_1));
    let (candidates, candidate_intro_dhs, candidate_complete_dhs) =
        failing_run(Completion::Candidates([&bad_1, &bad_2]));

    let ordinary_error = match ordinary {
        Err(error @ HandshakeError::DecryptionFailed) => error,
        Err(other) => panic!("ordinary completion returned {other:?}"),
        Ok(()) => panic!("ordinary completion accepted a wrong PSK"),
    };
    let candidate_error = match candidates {
        Err(error @ HandshakeError::DecryptionFailed) => error,
        Err(other) => panic!("candidate completion returned {other:?}"),
        Ok(()) => panic!("candidate completion accepted two wrong PSKs"),
    };
    assert_eq!(candidate_error.to_string(), ordinary_error.to_string());

    assert_eq!(ordinary_intro_dhs, 1);
    assert_eq!(ordinary_complete_dhs, 2);
    assert_eq!(candidate_intro_dhs, 1);
    assert_eq!(
        candidate_complete_dhs, 2,
        "two failed candidates must still share one `ss` operation",
    );
}
