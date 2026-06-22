//! In-memory driver for the `hiss` crate's synchronous, type-level Noise
//! handshakes, built for a Leptos/wasm demo.
//!
//! [`establish`] drives **both** peers of one handshake on a single thread
//! over an in-memory duplex, snapshotting every handshake message's raw wire
//! bytes as it is produced, then hands back a live [`LiveSession`] holding
//! both peers' transports so the UI can keep chatting over the channel after
//! the handshake completes.
//!
//! The cipher+hash are fixed to **ChaCha20-Poly1305 + BLAKE2b**; the DH
//! curve is selectable across hiss's three Noise curves — X25519, P256, and
//! X448 (`Noise_<pattern>_<curve>_ChaChaPoly_BLAKE2b`). Every pattern is a
//! distinct compile-time type-state chain, generic over the curve, so it is
//! driven by its own small function below — the token order in each mirrors
//! the pattern's message sequence exactly.

use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::io::{Read, Write};
use std::rc::Rc;

use hiss::curve::p256::P256r1PrivateKey;
use hiss::curve::x25519::SoftwareX25519PrivateKey;
use hiss::curve::x448::SoftwareX448PrivateKey;
use hiss::curve::{Curve, DhCurve};
use hiss::noise::{
    Blake2b, ChaChaPoly, Initiator, Noise, Responder, SyncHandshake, Transport, WellFormed, P256,
    X25519, X448,
};
use hiss::provider::{CryptoKeyProvider, DhProvider, EphemeralOnly, ProviderExt};
use hiss::psk::Psk;

/// The concrete Noise suite the demo speaks, parameterised by pattern `P`
/// and DH curve `C`; cipher and hash are fixed.
type Channel<P, C> = Noise<P, C, ChaChaPoly, Blake2b>;

/// The software provider, seeded from a per-call ChaCha20 CSPRNG.
type Provider = EphemeralOnly<ChaCha20Rng>;

// ── RNG ──────────────────────────────────────────────────────────
//
// One helper that works on host *and* wasm: on the host `getrandom`
// needs no extra feature; under wasm the consuming crate enables
// getrandom's `wasm_js` backend. We seed a ChaCha20 CSPRNG once and hand
// it to the provider, which advances it for every key it mints.

/// Seed a ChaCha20 CSPRNG from the platform entropy source.
fn make_rng() -> ChaCha20Rng {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).expect("CSPRNG seeding failed");
    ChaCha20Rng::from_seed(seed)
}

/// A fresh software provider seeded from platform entropy.
fn make_provider() -> Provider {
    EphemeralOnly::new(make_rng())
}

// ═══════════════════════════════════════════════════════════════
//  Demo curve abstraction
// ═══════════════════════════════════════════════════════════════
//
// A sealed helper trait carrying everything the generic drivers and the
// persistent `Identity` need from a curve: the bound bundle for the sync
// driver, the runtime `CurveKind` tag, and the (non-generic-in-hiss)
// static-key byte round-trip. Implemented for the three Noise DH curves.

mod sealed {
    pub trait Sealed {}
    impl Sealed for hiss::noise::X25519 {}
    impl Sealed for hiss::noise::P256 {}
    impl Sealed for hiss::noise::X448 {}
}

/// The software static-key type for curve `C` — i.e. the provider's private
/// key. (X25519/X448's `SoftwareX…PrivateKey`, P256's `P256r1PrivateKey`.)
type Static<C> = <Provider as CryptoKeyProvider<C>>::PrivateKey;

/// A DH curve the demo can drive a handshake over.
///
/// Bundles the runtime [`CurveKind`] tag with the per-curve static-key byte
/// round-trip that `Identity` persistence needs (these are *not* generic in
/// hiss). The bound bundle the synchronous Noise driver imposes — `DhCurve`,
/// `Provider: DhProvider<Self>`, `PublicKey`/`SharedSecret` are `AsRef<[u8]>`
/// — is repeated as a `where` clause on every generic function rather than
/// folded in here, so the trait stays object-safe-shaped and dyn-free.
/// Sealed: only the three Noise curves below implement it.
trait DemoCurve: DhCurve + sealed::Sealed {
    /// The runtime tag identifying this curve.
    const KIND: CurveKind;

    /// Serialise a static secret to its raw scalar bytes.
    fn secret_to_bytes(secret: &Static<Self>) -> Vec<u8>
    where
        Self: Sized,
        Provider: CryptoKeyProvider<Self>;

    /// Reconstruct a static secret from its raw scalar bytes, validating it.
    fn secret_from_bytes(bytes: &[u8]) -> Result<Static<Self>, DemoError>
    where
        Self: Sized,
        Provider: CryptoKeyProvider<Self>;
}

impl DemoCurve for X25519 {
    const KIND: CurveKind = CurveKind::X25519;

    fn secret_to_bytes(secret: &SoftwareX25519PrivateKey) -> Vec<u8> {
        secret.as_bytes().to_vec()
    }
    fn secret_from_bytes(bytes: &[u8]) -> Result<SoftwareX25519PrivateKey, DemoError> {
        let scalar: [u8; 32] = bytes.try_into().map_err(|_| DemoError::Key)?;
        Ok(SoftwareX25519PrivateKey::from_bytes(scalar))
    }
}

impl DemoCurve for P256 {
    const KIND: CurveKind = CurveKind::P256;

    fn secret_to_bytes(secret: &P256r1PrivateKey) -> Vec<u8> {
        secret.to_bytes().to_vec()
    }
    fn secret_from_bytes(bytes: &[u8]) -> Result<P256r1PrivateKey, DemoError> {
        let scalar: [u8; 32] = bytes.try_into().map_err(|_| DemoError::Key)?;
        P256r1PrivateKey::from_bytes(scalar).map_err(|_| DemoError::Key)
    }
}

impl DemoCurve for X448 {
    const KIND: CurveKind = CurveKind::X448;

    fn secret_to_bytes(secret: &SoftwareX448PrivateKey) -> Vec<u8> {
        secret.as_bytes().to_vec()
    }
    fn secret_from_bytes(bytes: &[u8]) -> Result<SoftwareX448PrivateKey, DemoError> {
        let scalar: [u8; 56] = bytes.try_into().map_err(|_| DemoError::Key)?;
        Ok(SoftwareX448PrivateKey::from_bytes(scalar))
    }
}

/// Derive the public key of a freshly-minted static, as the curve's
/// `PublicKey` (for `set_rs`).
fn static_public<C>(secret: &Static<C>) -> Result<C::PublicKey, DemoError>
where
    C: DemoCurve,
    Provider: DhProvider<C>,
    C::PublicKey: AsRef<[u8]>,
    C::SharedSecret: AsRef<[u8]>,
{
    // Use the low-level `public_key` rather than `ProviderExt::public`: the
    // latter needs `Static<C>: SecretKey`, which is not provable for the
    // generic associated type, whereas `public_key` takes `&PrivateKey`.
    CryptoKeyProvider::<C>::public_key(&make_provider(), secret).map_err(|_| DemoError::Key)
}

// ═══════════════════════════════════════════════════════════════
//  Curve catalogue
// ═══════════════════════════════════════════════════════════════

/// The DH curves the demo can run. Cipher and hash are fixed; only the
/// curve (and therefore key sizes and the protocol-name token) changes.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CurveKind {
    X25519,
    P256,
    X448,
}

impl CurveKind {
    /// Every curve, in a sensible demo order.
    pub const ALL: [CurveKind; 3] = [CurveKind::X25519, CurveKind::P256, CurveKind::X448];

    /// The UI label (e.g. `"X25519"`).
    pub fn name(self) -> &'static str {
        match self {
            CurveKind::X25519 => "X25519",
            CurveKind::P256 => "P256",
            CurveKind::X448 => "X448",
        }
    }

    /// Parse a curve back from its [`name`](Self::name).
    pub fn from_name(s: &str) -> Option<CurveKind> {
        CurveKind::ALL.into_iter().find(|c| c.name() == s)
    }

    /// A one-line summary of the curve for the UI.
    pub fn description(self) -> &'static str {
        match self {
            CurveKind::X25519 => "Curve25519 ECDH · 32-byte keys · the Noise default.",
            CurveKind::P256 => "NIST P-256 ECDH · 32-byte scalars, 65-byte public keys.",
            CurveKind::X448 => "Curve448 ECDH · 56-byte keys · a higher security margin.",
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  Pattern catalogue
// ═══════════════════════════════════════════════════════════════

/// The handshake patterns the demo can run. The suite is fixed; only the
/// pattern (and therefore the authentication properties and key
/// prerequisites) changes.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PatternKind {
    N,
    K,
    Kpsk0,
    Nn,
    Nk,
    Xx,
    Ik,
    Ikpsk1,
    Ix,
    Xk,
}

impl PatternKind {
    /// Every pattern, in a sensible demo order (two-way first, then the
    /// one-way "seal" patterns).
    pub const ALL: [PatternKind; 10] = [
        PatternKind::Nn,
        PatternKind::Xx,
        PatternKind::Nk,
        PatternKind::Xk,
        PatternKind::Ik,
        PatternKind::Ikpsk1,
        PatternKind::Ix,
        PatternKind::N,
        PatternKind::K,
        PatternKind::Kpsk0,
    ];

    /// The canonical Noise pattern name (e.g. `"XX"`, `"IKpsk1"`).
    pub fn name(self) -> &'static str {
        match self {
            PatternKind::N => "N",
            PatternKind::K => "K",
            PatternKind::Kpsk0 => "Kpsk0",
            PatternKind::Nn => "NN",
            PatternKind::Nk => "NK",
            PatternKind::Xx => "XX",
            PatternKind::Ik => "IK",
            PatternKind::Ikpsk1 => "IKpsk1",
            PatternKind::Ix => "IX",
            PatternKind::Xk => "XK",
        }
    }

    /// Parse a pattern back from its [`name`](Self::name).
    pub fn from_name(s: &str) -> Option<PatternKind> {
        PatternKind::ALL.into_iter().find(|p| p.name() == s)
    }

    /// The per-message token lines (the pre-message line excluded), in order.
    ///
    /// `message_token_lines().len()` equals the number of wire messages the
    /// pattern produces, so the UI can annotate each captured message with
    /// its token line.
    pub fn message_token_lines(self) -> Vec<&'static str> {
        match self {
            PatternKind::N => vec!["-> e, es"],
            PatternKind::K => vec!["-> e, es, ss"],
            PatternKind::Kpsk0 => vec!["-> psk, e, es, ss"],
            PatternKind::Nn => vec!["-> e", "<- e, ee"],
            PatternKind::Nk => vec!["-> e, es", "<- e, ee"],
            PatternKind::Xx => vec!["-> e", "<- e, ee, s, es", "-> s, se"],
            PatternKind::Ik => vec!["-> e, es, s, ss", "<- e, ee, se"],
            PatternKind::Ikpsk1 => vec!["-> e, es, s, ss, psk", "<- e, ee, se"],
            PatternKind::Ix => vec!["-> e, s", "<- e, ee, se, s, es"],
            PatternKind::Xk => vec!["-> e, es", "<- e, ee", "-> s, se"],
        }
    }

    /// The token flow, newline-separated, `->` initiator→responder and
    /// `<-` responder→initiator. Pre-messages are shown on a leading
    /// `(pre: …)` line.
    pub fn tokens(self) -> &'static str {
        match self {
            PatternKind::N => "(pre: <- s)\n-> e, es",
            PatternKind::K => "(pre: -> s, <- s)\n-> e, es, ss",
            PatternKind::Kpsk0 => "(pre: -> s, <- s)\n-> psk, e, es, ss",
            PatternKind::Nn => "-> e\n<- e, ee",
            PatternKind::Nk => "(pre: <- s)\n-> e, es\n<- e, ee",
            PatternKind::Xx => "-> e\n<- e, ee, s, es\n-> s, se",
            PatternKind::Ik => "(pre: <- s)\n-> e, es, s, ss\n<- e, ee, se",
            PatternKind::Ikpsk1 => "(pre: <- s)\n-> e, es, s, ss, psk\n<- e, ee, se",
            PatternKind::Ix => "-> e, s\n<- e, ee, se, s, es",
            PatternKind::Xk => "(pre: <- s)\n-> e, es\n<- e, ee\n-> s, se",
        }
    }

    /// A one-sentence summary of the pattern's authentication properties.
    pub fn description(self) -> &'static str {
        match self {
            PatternKind::N => {
                "One-way seal to a known recipient: the sender is anonymous, the \
                 recipient is authenticated by its pre-shared static key."
            }
            PatternKind::K => {
                "One-way seal where both static keys are known in advance, so \
                 sender and recipient are both authenticated."
            }
            PatternKind::Kpsk0 => {
                "Like K, but a pre-shared symmetric key is mixed in first, adding \
                 PSK authentication on top of both known statics."
            }
            PatternKind::Nn => {
                "Anonymous, unauthenticated key agreement: neither party proves an \
                 identity, giving confidentiality only against passive eavesdroppers."
            }
            PatternKind::Nk => {
                "Anonymous initiator to a known responder: the responder is \
                 authenticated by its pre-shared static, the initiator stays anonymous."
            }
            PatternKind::Xx => {
                "Mutual authentication with statics exchanged (encrypted) on the \
                 wire — no pre-shared keys needed, both identities are verified."
            }
            PatternKind::Ik => {
                "Initiator knows the responder's static up front and transmits its \
                 own static immediately, giving mutual authentication in one round trip."
            }
            PatternKind::Ikpsk1 => {
                "Like IK, with a pre-shared key mixed in after the initiator's \
                 static for an extra PSK-authentication layer."
            }
            PatternKind::Ix => {
                "Mutual authentication where both statics are exchanged on the wire \
                 and no responder static needs to be known in advance."
            }
            PatternKind::Xk => {
                "Known responder with a deferred initiator static: the responder is \
                 authenticated first, the initiator reveals and proves its identity last."
            }
        }
    }

    /// Whether the responder's static public key must be known before the
    /// handshake (true for N, NK, IK, IKpsk1, XK, and the both-static K/Kpsk0).
    pub fn needs_responder_static(self) -> bool {
        matches!(
            self,
            PatternKind::N
                | PatternKind::Nk
                | PatternKind::Ik
                | PatternKind::Ikpsk1
                | PatternKind::Xk
                | PatternKind::K
                | PatternKind::Kpsk0
        )
    }

    /// Whether the initiator's static must be pre-shared with the responder
    /// (true only for the both-static K/Kpsk0 patterns).
    pub fn needs_initiator_static_preshared(self) -> bool {
        matches!(self, PatternKind::K | PatternKind::Kpsk0)
    }

    /// Whether a pre-shared symmetric key participates (Kpsk0, IKpsk1).
    pub fn needs_psk(self) -> bool {
        matches!(self, PatternKind::Kpsk0 | PatternKind::Ikpsk1)
    }

    /// Whether the pattern is one-way (a single handshake message, sealing
    /// data initiator→responder): N, K, Kpsk0.
    pub fn is_one_way(self) -> bool {
        matches!(self, PatternKind::N | PatternKind::K | PatternKind::Kpsk0)
    }

    /// Does the INITIATOR contribute a static key in this pattern?
    ///
    /// True for the patterns where the initiator authenticates with a static:
    /// XX, IX, IK, IKpsk1, K, Kpsk0, XK. False for NN, N, NK.
    pub fn initiator_has_static(self) -> bool {
        matches!(
            self,
            PatternKind::Xx
                | PatternKind::Ix
                | PatternKind::Ik
                | PatternKind::Ikpsk1
                | PatternKind::K
                | PatternKind::Kpsk0
                | PatternKind::Xk
        )
    }

    /// Does the RESPONDER contribute a static key in this pattern?
    ///
    /// True for every pattern except the fully-anonymous NN.
    pub fn responder_has_static(self) -> bool {
        !matches!(self, PatternKind::Nn)
    }
}

/// The full protocol name for a (pattern, curve) pair, identical to hiss's
/// own `Noise::<P, C, ChaChaPoly, Blake2b>::new().to_string()`
/// (e.g. `"Noise_XX_25519_ChaChaPoly_BLAKE2b"`).
pub fn protocol_name(pattern: PatternKind, curve: CurveKind) -> String {
    let curve_token = match curve {
        CurveKind::X25519 => <X25519 as Curve>::NAME,
        CurveKind::P256 => <P256 as Curve>::NAME,
        CurveKind::X448 => <X448 as Curve>::NAME,
    };
    format!(
        "Noise_{}_{}_{}_{}",
        pattern.name(),
        curve_token,
        <ChaChaPoly as hiss::noise::Cipher>::NAME,
        <Blake2b as hiss::noise::Hash>::NAME,
    )
}

// ═══════════════════════════════════════════════════════════════
//  Public result types
// ═══════════════════════════════════════════════════════════════

/// Which way a wire or application message travelled.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    InitiatorToResponder,
    ResponderToInitiator,
}

/// One captured handshake message: its position, direction, the token line
/// that produced it, and the exact bytes that crossed the wire.
#[derive(Clone)]
pub struct WireMessage {
    pub index: usize,
    pub direction: Direction,
    pub tokens: String,
    pub bytes: Vec<u8>,
}

/// Which peer is acting.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Peer {
    Initiator,
    Responder,
}

impl Peer {
    /// The UI label (`"Initiator"` / `"Responder"`).
    pub fn label(self) -> &'static str {
        match self {
            Peer::Initiator => "Initiator",
            Peer::Responder => "Responder",
        }
    }

    /// The other peer.
    pub fn other(self) -> Peer {
        match self {
            Peer::Initiator => Peer::Responder,
            Peer::Responder => Peer::Initiator,
        }
    }
}

/// One delivered chat message: encrypted by `from`, decrypted by the other peer.
#[derive(Clone)]
pub struct ChatLine {
    pub from: Peer,
    /// What the RECEIVER decrypted (equals the sent text when ok).
    pub plaintext: String,
    /// The exact bytes that crossed the wire.
    pub ciphertext: Vec<u8>,
    /// Did the receiver decrypt successfully.
    pub ok: bool,
}

/// A live, established session — both peers' transport state, type-erased over
/// the pattern and curve so the UI can hold it after the handshake.
pub trait LiveSession {
    /// Encrypt `plaintext` from `from` with that peer's transport, deliver it to
    /// the other peer's transport (both peers are local), and return the wire
    /// ciphertext plus what the receiver recovered.
    fn send(&mut self, from: Peer, plaintext: &str) -> Result<ChatLine, DemoError>;
}

/// The result of establishing a session: the handshake transcript plus the
/// live session for ongoing chat.
pub struct Established {
    pub protocol_name: String,
    pub wire: Vec<WireMessage>,
    pub session_id: String,
    pub session_ids_match: bool,
    pub session: Box<dyn LiveSession>,
}

/// Everything that can go wrong driving a demo handshake.
#[derive(thiserror::Error, Debug)]
pub enum DemoError {
    #[error("handshake failed: {0}")]
    Handshake(#[from] hiss::noise::HandshakeError),
    #[error("invalid key material")]
    Key,
    #[error("invalid hex: {0}")]
    Hex(String),
}

// ═══════════════════════════════════════════════════════════════
//  Persistent initiator identity
// ═══════════════════════════════════════════════════════════════

/// A persistent initiator identity — a long-term static key bound to a
/// specific [`CurveKind`], serialisable to/from hex for `localStorage`.
#[derive(Clone)]
pub struct Identity {
    curve: CurveKind,
    /// The raw secret scalar bytes of the static key (length is curve-specific).
    secret: Vec<u8>,
}

impl Identity {
    /// Mint a fresh random identity for `curve`.
    pub fn generate(curve: CurveKind) -> Self {
        let secret = match curve {
            CurveKind::X25519 => Self::generate_secret::<X25519>(),
            CurveKind::P256 => Self::generate_secret::<P256>(),
            CurveKind::X448 => Self::generate_secret::<X448>(),
        };
        Identity { curve, secret }
    }

    /// Mint a fresh static for `C` and return its raw scalar bytes.
    fn generate_secret<C>() -> Vec<u8>
    where
        C: DemoCurve,
        Provider: DhProvider<C>,
        C::PublicKey: AsRef<[u8]>,
        C::SharedSecret: AsRef<[u8]>,
    {
        let key = make_provider()
            .generate::<C>()
            .expect("software key generation cannot fail");
        C::secret_to_bytes(&key)
    }

    /// Rebuild an identity from its [`secret_hex`](Self::secret_hex), for `curve`.
    pub fn from_secret_hex(curve: CurveKind, hex: &str) -> Result<Self, DemoError> {
        let bytes = hex::decode(hex.trim()).map_err(|e| DemoError::Hex(e.to_string()))?;
        // Validate the scalar length and content by round-tripping through
        // the curve's key type.
        match curve {
            CurveKind::X25519 => Self::validate_secret::<X25519>(&bytes)?,
            CurveKind::P256 => Self::validate_secret::<P256>(&bytes)?,
            CurveKind::X448 => Self::validate_secret::<X448>(&bytes)?,
        }
        Ok(Identity {
            curve,
            secret: bytes,
        })
    }

    /// Validate that `bytes` is a well-formed `C` static scalar.
    fn validate_secret<C>(bytes: &[u8]) -> Result<(), DemoError>
    where
        C: DemoCurve,
        Provider: DhProvider<C>,
        C::PublicKey: AsRef<[u8]>,
        C::SharedSecret: AsRef<[u8]>,
    {
        C::secret_from_bytes(bytes).map(|_| ())
    }

    /// The curve this identity is bound to.
    pub fn curve(&self) -> CurveKind {
        self.curve
    }

    /// The raw secret scalar bytes as lowercase hex, for storage.
    pub fn secret_hex(&self) -> String {
        hex::encode(&self.secret)
    }

    /// The full hex of the identity's public key. The UI may truncate it
    /// for display.
    pub fn public_fingerprint(&self) -> Result<String, DemoError> {
        match self.curve {
            CurveKind::X25519 => self.fingerprint::<X25519>(),
            CurveKind::P256 => self.fingerprint::<P256>(),
            CurveKind::X448 => self.fingerprint::<X448>(),
        }
    }

    /// Reconstruct the live static and hex-encode its public key.
    fn fingerprint<C>(&self) -> Result<String, DemoError>
    where
        C: DemoCurve,
        Provider: DhProvider<C>,
        C::PublicKey: AsRef<[u8]>,
        C::SharedSecret: AsRef<[u8]>,
    {
        let secret = C::secret_from_bytes(&self.secret)?;
        let public = static_public::<C>(&secret)?;
        Ok(hex::encode(public.as_ref()))
    }

    /// Reconstruct the live static key for curve `C`.
    ///
    /// Returns [`DemoError::Key`] if the stored bytes do not match `C`
    /// (e.g. the caller passed a curve that disagrees with `self.curve`).
    fn static_key<C>(&self) -> Result<Static<C>, DemoError>
    where
        C: DemoCurve,
        Provider: DhProvider<C>,
        C::PublicKey: AsRef<[u8]>,
        C::SharedSecret: AsRef<[u8]>,
    {
        if self.curve != C::KIND {
            return Err(DemoError::Key);
        }
        C::secret_from_bytes(&self.secret)
    }
}

// ═══════════════════════════════════════════════════════════════
//  In-memory duplex with per-message wire capture
// ═══════════════════════════════════════════════════════════════

/// A byte queue shared between the two peers.
type Queue = Rc<RefCell<VecDeque<u8>>>;

/// One peer's view of the duplex: it writes to `out` and reads from `in_`.
/// Both peers live on the same thread; the queues are the only channel.
#[derive(Clone)]
struct DuplexEnd {
    out: Queue,
    in_: Queue,
}

impl Write for DuplexEnd {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.out.borrow_mut().extend(buf.iter().copied());
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Read for DuplexEnd {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut q = self.in_.borrow_mut();
        let n = buf.len().min(q.len());
        for slot in buf.iter_mut().take(n) {
            *slot = q.pop_front().expect("queue length checked above");
        }
        Ok(n)
    }
}

/// The captured-wire harness: holds both ends plus the running list of
/// captured handshake messages.
struct Wire {
    a2b: Queue,
    b2a: Queue,
    captured: Vec<WireMessage>,
    next_index: usize,
}

impl Wire {
    fn new() -> Self {
        Wire {
            a2b: Rc::new(RefCell::new(VecDeque::new())),
            b2a: Rc::new(RefCell::new(VecDeque::new())),
            captured: Vec::new(),
            next_index: 0,
        }
    }

    /// The initiator's IO end: writes to `a2b`, reads from `b2a`.
    fn initiator_end(&self) -> DuplexEnd {
        DuplexEnd {
            out: self.a2b.clone(),
            in_: self.b2a.clone(),
        }
    }

    /// The responder's IO end: writes to `b2a`, reads from `a2b`.
    fn responder_end(&self) -> DuplexEnd {
        DuplexEnd {
            out: self.b2a.clone(),
            in_: self.a2b.clone(),
        }
    }

    /// Snapshot the just-sent message on `direction`'s queue (non-destructive
    /// clone), record it, and return — the receiving peer drains it next.
    fn capture(&mut self, direction: Direction) {
        let queue = match direction {
            Direction::InitiatorToResponder => &self.a2b,
            Direction::ResponderToInitiator => &self.b2a,
        };
        let bytes: Vec<u8> = queue.borrow().iter().copied().collect();
        self.captured.push(WireMessage {
            index: self.next_index,
            direction,
            tokens: String::new(),
            bytes,
        });
        self.next_index += 1;
    }
}

// ═══════════════════════════════════════════════════════════════
//  Live, established session
// ═══════════════════════════════════════════════════════════════

/// A live session over a concrete (pattern, curve): both peers' transport
/// state, kept after the handshake so the UI can chat in either direction.
///
/// Erased to [`Box<dyn LiveSession>`] in [`establish`], where the concrete
/// `(P, C)` is known — the UI holds the trait object and never names `P`/`C`.
struct Live<P, C>
where
    P: WellFormed,
    C: DhCurve,
{
    init: Transport<Channel<P, C>>,
    resp: Transport<Channel<P, C>>,
}

impl<P, C> LiveSession for Live<P, C>
where
    P: WellFormed,
    C: DhCurve,
{
    fn send(&mut self, from: Peer, plaintext: &str) -> Result<ChatLine, DemoError> {
        let pt = plaintext.as_bytes();
        // Pick the sender / receiver transports for this direction. Each
        // direction has its own nonce counter; because every send here is
        // immediately paired with the matching receive, the counters stay in
        // lockstep regardless of send order or how many go each way.
        let (sender, receiver) = match from {
            Peer::Initiator => (&mut self.init, &mut self.resp),
            Peer::Responder => (&mut self.resp, &mut self.init),
        };

        let mut ciphertext = vec![0u8; pt.len() + Transport::<Channel<P, C>>::OVERHEAD];
        let n = sender.send(pt, &mut ciphertext)?;
        ciphertext.truncate(n);

        let mut opened = vec![0u8; n];
        let (plaintext_out, ok) = match receiver.receive(&ciphertext, &mut opened) {
            Ok(m) => match std::str::from_utf8(&opened[..m]) {
                Ok(s) => (s.to_string(), true),
                // Decryption succeeded but the bytes are not valid UTF-8;
                // surface the original send text and flag the mismatch.
                Err(_) => (plaintext.to_string(), false),
            },
            Err(_) => (String::new(), false),
        };

        Ok(ChatLine {
            from,
            plaintext: plaintext_out,
            ciphertext,
            ok,
        })
    }
}

// ═══════════════════════════════════════════════════════════════
//  Per-pattern drivers
//
//  Each fn drives both peers over one `Wire`, capturing each message as
//  it is sent, then returns the two transports. The token chains follow
//  the pattern's message sequence verbatim (see `tokens()` above). Each is
//  generic over the DH curve `C`; the cipher+hash are fixed.
// ═══════════════════════════════════════════════════════════════

/// Build the two transports plus the captured wire for a finished run.
struct Finished<P, C>
where
    P: WellFormed,
    C: DhCurve,
{
    init: Transport<Channel<P, C>>,
    resp: Transport<Channel<P, C>>,
    wire: Vec<WireMessage>,
}

/// NN: `-> e` / `<- e, ee`. Anonymous, no static keys.
fn drive_nn<C>() -> Result<Finished<hiss::noise::pattern::NN, C>, DemoError>
where
    C: DemoCurve,
    Provider: DhProvider<C>,
    C::PublicKey: AsRef<[u8]>,
    C::SharedSecret: AsRef<[u8]>,
{
    type Pat = hiss::noise::pattern::NN;
    let mut wire = Wire::new();
    let i = SyncHandshake::<Channel<Pat, C>, Initiator, _, _, _, _>::initiate(
        make_provider(),
        &[],
        wire.initiator_end(),
    );
    let r = SyncHandshake::<Channel<Pat, C>, Responder, _, _, _, _>::respond(
        make_provider(),
        &[],
        wire.responder_end(),
    );

    // msg1: -> e
    let i = i.e()?;
    wire.capture(Direction::InitiatorToResponder);
    let (_re, r) = r.recv().e()?;

    // msg2: <- e, ee
    let r = r.e()?;
    let (resp, _io) = r.ee()?.into_parts();
    wire.capture(Direction::ResponderToInitiator);
    let (_re, i) = i.recv().e()?;
    let (init, _io) = i.ee()?.into_parts();

    Ok(Finished {
        init,
        resp,
        wire: wire.captured,
    })
}

/// XX: `-> e` / `<- e, ee, s, es` / `-> s, se`. Mutual auth, statics on the wire.
fn drive_xx<C>(
    initiator_static: Static<C>,
    responder_static: Static<C>,
) -> Result<Finished<hiss::noise::pattern::XX, C>, DemoError>
where
    C: DemoCurve,
    Provider: DhProvider<C>,
    C::PublicKey: AsRef<[u8]>,
    C::SharedSecret: AsRef<[u8]>,
{
    type Pat = hiss::noise::pattern::XX;
    let mut wire = Wire::new();
    let i = SyncHandshake::<Channel<Pat, C>, Initiator, _, _, _, _>::initiate(
        make_provider(),
        &[],
        wire.initiator_end(),
    );
    let r = SyncHandshake::<Channel<Pat, C>, Responder, _, _, _, _>::respond(
        make_provider(),
        &[],
        wire.responder_end(),
    );

    // msg1: -> e
    let i = i.e()?;
    wire.capture(Direction::InitiatorToResponder);
    let (_re, r) = r.recv().e()?;

    // msg2: <- e, ee, s, es
    let r = r.e()?.ee()?.s(responder_static)?.es()?;
    wire.capture(Direction::ResponderToInitiator);
    let (_re, i) = i.recv().e()?;
    let i = i.ee()?;
    let (_rs, i) = i.s()?;
    let i = i.es()?;

    // msg3: -> s, se
    let (init, _io) = i.s(initiator_static)?.se()?.into_parts();
    wire.capture(Direction::InitiatorToResponder);
    let r = r.recv();
    let (_rs, r) = r.s()?;
    let (resp, _io) = r.se()?.into_parts();

    Ok(Finished {
        init,
        resp,
        wire: wire.captured,
    })
}

/// NK: `(pre: <- s)` / `-> e, es` / `<- e, ee`. Known responder, anon initiator.
fn drive_nk<C>(
    responder_static: Static<C>,
) -> Result<Finished<hiss::noise::pattern::NK, C>, DemoError>
where
    C: DemoCurve,
    Provider: DhProvider<C>,
    C::PublicKey: AsRef<[u8]>,
    C::SharedSecret: AsRef<[u8]>,
{
    type Pat = hiss::noise::pattern::NK;
    let mut wire = Wire::new();
    let responder_pub = static_public::<C>(&responder_static)?;

    let i = SyncHandshake::<Channel<Pat, C>, Initiator, _, _, _, _>::initiate(
        make_provider(),
        &[],
        wire.initiator_end(),
    )
    .set_rs(responder_pub);
    let r = SyncHandshake::<Channel<Pat, C>, Responder, _, _, _, _>::respond(
        make_provider(),
        &[],
        wire.responder_end(),
    )
    .set_s(responder_static)?;

    // msg1: -> e, es
    let i = i.e()?.es()?;
    wire.capture(Direction::InitiatorToResponder);
    let (_re, r) = r.recv().e()?;
    let r = r.es()?;

    // msg2: <- e, ee
    let r = r.e()?;
    let (resp, _io) = r.ee()?.into_parts();
    wire.capture(Direction::ResponderToInitiator);
    let (_re, i) = i.recv().e()?;
    let (init, _io) = i.ee()?.into_parts();

    Ok(Finished {
        init,
        resp,
        wire: wire.captured,
    })
}

/// XK: `(pre: <- s)` / `-> e, es` / `<- e, ee` / `-> s, se`. Known responder,
/// deferred initiator static.
fn drive_xk<C>(
    initiator_static: Static<C>,
    responder_static: Static<C>,
) -> Result<Finished<hiss::noise::pattern::XK, C>, DemoError>
where
    C: DemoCurve,
    Provider: DhProvider<C>,
    C::PublicKey: AsRef<[u8]>,
    C::SharedSecret: AsRef<[u8]>,
{
    type Pat = hiss::noise::pattern::XK;
    let mut wire = Wire::new();
    let responder_pub = static_public::<C>(&responder_static)?;

    let i = SyncHandshake::<Channel<Pat, C>, Initiator, _, _, _, _>::initiate(
        make_provider(),
        &[],
        wire.initiator_end(),
    )
    .set_rs(responder_pub);
    let r = SyncHandshake::<Channel<Pat, C>, Responder, _, _, _, _>::respond(
        make_provider(),
        &[],
        wire.responder_end(),
    )
    .set_s(responder_static)?;

    // msg1: -> e, es
    let i = i.e()?.es()?;
    wire.capture(Direction::InitiatorToResponder);
    let (_re, r) = r.recv().e()?;
    let r = r.es()?;

    // msg2: <- e, ee
    let r = r.e()?.ee()?;
    wire.capture(Direction::ResponderToInitiator);
    let (_re, i) = i.recv().e()?;
    let i = i.ee()?;

    // msg3: -> s, se
    let (init, _io) = i.s(initiator_static)?.se()?.into_parts();
    wire.capture(Direction::InitiatorToResponder);
    let r = r.recv();
    let (_rs, r) = r.s()?;
    let (resp, _io) = r.se()?.into_parts();

    Ok(Finished {
        init,
        resp,
        wire: wire.captured,
    })
}

/// IK: `(pre: <- s)` / `-> e, es, s, ss` / `<- e, ee, se`. Mutual auth, one RTT.
fn drive_ik<C>(
    initiator_static: Static<C>,
    responder_static: Static<C>,
) -> Result<Finished<hiss::noise::pattern::IK, C>, DemoError>
where
    C: DemoCurve,
    Provider: DhProvider<C>,
    C::PublicKey: AsRef<[u8]>,
    C::SharedSecret: AsRef<[u8]>,
{
    type Pat = hiss::noise::pattern::IK;
    let mut wire = Wire::new();
    let responder_pub = static_public::<C>(&responder_static)?;

    let i = SyncHandshake::<Channel<Pat, C>, Initiator, _, _, _, _>::initiate(
        make_provider(),
        &[],
        wire.initiator_end(),
    )
    .set_rs(responder_pub);
    let r = SyncHandshake::<Channel<Pat, C>, Responder, _, _, _, _>::respond(
        make_provider(),
        &[],
        wire.responder_end(),
    )
    .set_s(responder_static)?;

    // msg1: -> e, es, s, ss
    let i = i.e()?.es()?.s(initiator_static)?.ss()?;
    wire.capture(Direction::InitiatorToResponder);
    let (_re, r) = r.recv().e()?;
    let r = r.es()?;
    let (_rs, r) = r.s()?;
    let r = r.ss()?;

    // msg2: <- e, ee, se
    let r = r.e()?.ee()?;
    let (resp, _io) = r.se()?.into_parts();
    wire.capture(Direction::ResponderToInitiator);
    let (_re, i) = i.recv().e()?;
    let i = i.ee()?;
    let (init, _io) = i.se()?.into_parts();

    Ok(Finished {
        init,
        resp,
        wire: wire.captured,
    })
}

/// IKpsk1: `(pre: <- s)` / `-> e, es, s, ss, psk` / `<- e, ee, se`. IK + PSK.
fn drive_ikpsk1<C>(
    initiator_static: Static<C>,
    responder_static: Static<C>,
    psk: &Psk,
) -> Result<Finished<hiss::noise::pattern::IKpsk1, C>, DemoError>
where
    C: DemoCurve,
    Provider: DhProvider<C>,
    C::PublicKey: AsRef<[u8]>,
    C::SharedSecret: AsRef<[u8]>,
{
    type Pat = hiss::noise::pattern::IKpsk1;
    let mut wire = Wire::new();
    let responder_pub = static_public::<C>(&responder_static)?;

    let i = SyncHandshake::<Channel<Pat, C>, Initiator, _, _, _, _>::initiate(
        make_provider(),
        &[],
        wire.initiator_end(),
    )
    .set_rs(responder_pub);
    let r = SyncHandshake::<Channel<Pat, C>, Responder, _, _, _, _>::respond(
        make_provider(),
        &[],
        wire.responder_end(),
    )
    .set_s(responder_static)?;

    // msg1: -> e, es, s, ss, psk
    let i = i.e()?.es()?.s(initiator_static)?.ss()?.psk(psk)?;
    wire.capture(Direction::InitiatorToResponder);
    let (_re, r) = r.recv().e()?;
    let r = r.es()?;
    let (_rs, r) = r.s()?;
    let r = r.ss()?.psk(psk)?;

    // msg2: <- e, ee, se
    let r = r.e()?.ee()?;
    let (resp, _io) = r.se()?.into_parts();
    wire.capture(Direction::ResponderToInitiator);
    let (_re, i) = i.recv().e()?;
    let i = i.ee()?;
    let (init, _io) = i.se()?.into_parts();

    Ok(Finished {
        init,
        resp,
        wire: wire.captured,
    })
}

/// IX: `-> e, s` / `<- e, ee, se, s, es`. Mutual auth, statics on the wire,
/// no responder static known in advance.
fn drive_ix<C>(
    initiator_static: Static<C>,
    responder_static: Static<C>,
) -> Result<Finished<hiss::noise::pattern::IX, C>, DemoError>
where
    C: DemoCurve,
    Provider: DhProvider<C>,
    C::PublicKey: AsRef<[u8]>,
    C::SharedSecret: AsRef<[u8]>,
{
    type Pat = hiss::noise::pattern::IX;
    let mut wire = Wire::new();

    let i = SyncHandshake::<Channel<Pat, C>, Initiator, _, _, _, _>::initiate(
        make_provider(),
        &[],
        wire.initiator_end(),
    );
    let r = SyncHandshake::<Channel<Pat, C>, Responder, _, _, _, _>::respond(
        make_provider(),
        &[],
        wire.responder_end(),
    );

    // msg1: -> e, s
    let i = i.e()?.s(initiator_static)?;
    wire.capture(Direction::InitiatorToResponder);
    let (_re, r) = r.recv().e()?;
    let (_rs, r) = r.s()?;

    // msg2: <- e, ee, se, s, es
    let r = r.e()?.ee()?.se()?.s(responder_static)?.es()?;
    wire.capture(Direction::ResponderToInitiator);
    let (_re, i) = i.recv().e()?;
    let i = i.ee()?.se()?;
    let (_rs, i) = i.s()?;
    let (init, _io) = i.es()?.into_parts();
    let (resp, _io) = r.into_parts();

    Ok(Finished {
        init,
        resp,
        wire: wire.captured,
    })
}

/// N: `(pre: <- s)` / `-> e, es`. One-way seal to a known recipient.
fn drive_n<C>(
    responder_static: Static<C>,
) -> Result<Finished<hiss::noise::pattern::N, C>, DemoError>
where
    C: DemoCurve,
    Provider: DhProvider<C>,
    C::PublicKey: AsRef<[u8]>,
    C::SharedSecret: AsRef<[u8]>,
{
    type Pat = hiss::noise::pattern::N;
    let mut wire = Wire::new();
    let responder_pub = static_public::<C>(&responder_static)?;

    let i = SyncHandshake::<Channel<Pat, C>, Initiator, _, _, _, _>::initiate(
        make_provider(),
        &[],
        wire.initiator_end(),
    )
    .set_rs(responder_pub);
    let r = SyncHandshake::<Channel<Pat, C>, Responder, _, _, _, _>::respond(
        make_provider(),
        &[],
        wire.responder_end(),
    )
    .set_s(responder_static)?;

    // msg1: -> e, es  (final message → SyncTransport)
    let (init, _io) = i.e()?.es()?.into_parts();
    wire.capture(Direction::InitiatorToResponder);
    let (_re, r) = r.recv().e()?;
    let (resp, _io) = r.es()?.into_parts();

    Ok(Finished {
        init,
        resp,
        wire: wire.captured,
    })
}

/// K: `(pre: -> s, <- s)` / `-> e, es, ss`. One-way seal, both statics known.
fn drive_k<C>(
    initiator_static: Static<C>,
    responder_static: Static<C>,
) -> Result<Finished<hiss::noise::pattern::K, C>, DemoError>
where
    C: DemoCurve,
    Provider: DhProvider<C>,
    C::PublicKey: AsRef<[u8]>,
    C::SharedSecret: AsRef<[u8]>,
{
    type Pat = hiss::noise::pattern::K;
    let mut wire = Wire::new();
    let initiator_pub = static_public::<C>(&initiator_static)?;
    let responder_pub = static_public::<C>(&responder_static)?;

    // Initiator: -> s (own static), <- s (responder pub).
    let i = SyncHandshake::<Channel<Pat, C>, Initiator, _, _, _, _>::initiate(
        make_provider(),
        &[],
        wire.initiator_end(),
    )
    .set_s(initiator_static)?
    .set_rs(responder_pub);
    // Responder: -> s (initiator pub), <- s (own static).
    let r = SyncHandshake::<Channel<Pat, C>, Responder, _, _, _, _>::respond(
        make_provider(),
        &[],
        wire.responder_end(),
    )
    .set_rs(initiator_pub)
    .set_s(responder_static)?;

    // msg1: -> e, es, ss
    let (init, _io) = i.e()?.es()?.ss()?.into_parts();
    wire.capture(Direction::InitiatorToResponder);
    let (_re, r) = r.recv().e()?;
    let (resp, _io) = r.es()?.ss()?.into_parts();

    Ok(Finished {
        init,
        resp,
        wire: wire.captured,
    })
}

/// Kpsk0: `(pre: -> s, <- s)` / `-> psk, e, es, ss`. K + leading PSK.
fn drive_kpsk0<C>(
    initiator_static: Static<C>,
    responder_static: Static<C>,
    psk: &Psk,
) -> Result<Finished<hiss::noise::pattern::Kpsk0, C>, DemoError>
where
    C: DemoCurve,
    Provider: DhProvider<C>,
    C::PublicKey: AsRef<[u8]>,
    C::SharedSecret: AsRef<[u8]>,
{
    type Pat = hiss::noise::pattern::Kpsk0;
    let mut wire = Wire::new();
    let initiator_pub = static_public::<C>(&initiator_static)?;
    let responder_pub = static_public::<C>(&responder_static)?;

    let i = SyncHandshake::<Channel<Pat, C>, Initiator, _, _, _, _>::initiate(
        make_provider(),
        &[],
        wire.initiator_end(),
    )
    .set_s(initiator_static)?
    .set_rs(responder_pub);
    let r = SyncHandshake::<Channel<Pat, C>, Responder, _, _, _, _>::respond(
        make_provider(),
        &[],
        wire.responder_end(),
    )
    .set_rs(initiator_pub)
    .set_s(responder_static)?;

    // msg1: -> psk, e, es, ss
    let (init, _io) = i.psk(psk)?.e()?.es()?.ss()?.into_parts();
    wire.capture(Direction::InitiatorToResponder);
    let r = r.recv().psk(psk)?;
    let (_re, r) = r.e()?;
    let (resp, _io) = r.es()?.ss()?.into_parts();

    Ok(Finished {
        init,
        resp,
        wire: wire.captured,
    })
}

// ═══════════════════════════════════════════════════════════════
//  Public entry point
// ═══════════════════════════════════════════════════════════════

/// Assemble an [`Established`] from a finished pair of transports, erasing the
/// concrete `(P, C)` types into a `Box<dyn LiveSession>` for the UI to hold.
///
/// Each captured wire message is annotated with its token line, index-aligned.
fn finish<P, C>(mut finished: Finished<P, C>, pattern: PatternKind) -> Established
where
    P: WellFormed + 'static,
    C: DhCurve + 'static,
{
    let protocol_name = Channel::<P, C>::new().to_string();

    let session_id = finished.init.session_id().to_string();
    let session_ids_match = finished.init.session_id() == finished.resp.session_id();

    // Annotate each captured wire message with its token line, index-aligned.
    let token_lines = pattern.message_token_lines();
    for (msg, line) in finished.wire.iter_mut().zip(token_lines.iter()) {
        msg.tokens = (*line).to_string();
    }

    let session: Box<dyn LiveSession> = Box::new(Live {
        init: finished.init,
        resp: finished.resp,
    });

    Established {
        protocol_name,
        wire: finished.wire,
        session_id,
        session_ids_match,
        session,
    }
}

/// Run the handshake for `pattern`/`curve` between two persistent identities,
/// returning the handshake transcript and a live session to chat over.
///
/// `initiator` and `responder` supply each peer's long-term static key (each
/// used by the patterns that authenticate that peer). Ephemeral keys and any
/// PSK are still generated fresh per run. Both identities must be bound to
/// `curve`; if either disagrees, this returns [`DemoError::Key`].
///
/// For the patterns where the responder's static is pre-known to the initiator
/// (N, NK, IK, IKpsk1, XK, K, Kpsk0), the initiator's `set_rs` and the
/// responder's `set_s` are both derived from this single `responder` identity,
/// so they agree — that is what makes the handshake succeed.
pub fn establish(
    pattern: PatternKind,
    curve: CurveKind,
    initiator: &Identity,
    responder: &Identity,
) -> Result<Established, DemoError> {
    if initiator.curve() != curve || responder.curve() != curve {
        return Err(DemoError::Key);
    }
    match curve {
        CurveKind::X25519 => establish_on::<X25519>(pattern, initiator, responder),
        CurveKind::P256 => establish_on::<P256>(pattern, initiator, responder),
        CurveKind::X448 => establish_on::<X448>(pattern, initiator, responder),
    }
}

/// Curve-monomorphised half of [`establish`]: dispatch on the pattern, drive
/// it (threading each peer's static from its identity), and assemble the
/// [`Established`] (boxing the live session).
///
/// Each arm extracts only the statics its pattern actually uses — NN extracts
/// neither, the responder-static patterns extract the responder's, and the
/// mutual / both-static patterns extract both. The unused identity is simply
/// never read, so there are no unused-key warnings.
fn establish_on<C>(
    pattern: PatternKind,
    initiator: &Identity,
    responder: &Identity,
) -> Result<Established, DemoError>
where
    C: DemoCurve + 'static,
    Provider: DhProvider<C>,
    C::PublicKey: AsRef<[u8]>,
    C::SharedSecret: AsRef<[u8]>,
{
    // The PSK is shared by both peers; generate one per run.
    let psk = Psk::generate(make_rng());

    Ok(match pattern {
        // NN: neither static used.
        PatternKind::Nn => finish(drive_nn::<C>()?, pattern),
        // XX, IX: both statics, exchanged on the wire.
        PatternKind::Xx => finish(
            drive_xx::<C>(initiator.static_key::<C>()?, responder.static_key::<C>()?)?,
            pattern,
        ),
        PatternKind::Ix => finish(
            drive_ix::<C>(initiator.static_key::<C>()?, responder.static_key::<C>()?)?,
            pattern,
        ),
        // NK, N: responder static only.
        PatternKind::Nk => finish(drive_nk::<C>(responder.static_key::<C>()?)?, pattern),
        PatternKind::N => finish(drive_n::<C>(responder.static_key::<C>()?)?, pattern),
        // XK, IK, IKpsk1: both statics (responder pre-known to the initiator).
        PatternKind::Xk => finish(
            drive_xk::<C>(initiator.static_key::<C>()?, responder.static_key::<C>()?)?,
            pattern,
        ),
        PatternKind::Ik => finish(
            drive_ik::<C>(initiator.static_key::<C>()?, responder.static_key::<C>()?)?,
            pattern,
        ),
        PatternKind::Ikpsk1 => finish(
            drive_ikpsk1::<C>(
                initiator.static_key::<C>()?,
                responder.static_key::<C>()?,
                &psk,
            )?,
            pattern,
        ),
        // K, Kpsk0: both statics (both pre-shared).
        PatternKind::K => finish(
            drive_k::<C>(initiator.static_key::<C>()?, responder.static_key::<C>()?)?,
            pattern,
        ),
        PatternKind::Kpsk0 => finish(
            drive_kpsk0::<C>(
                initiator.static_key::<C>()?,
                responder.static_key::<C>()?,
                &psk,
            )?,
            pattern,
        ),
    })
}
