//! Frozen handshake traces and per-pattern UI metadata for the device.
//!
//! The trace table (`fixtures_data.in`) is **generated** by
//! `tests/fixtures.rs`: every byte was produced by hiss itself, over the six
//! patterns the device offers, with fixed RNG seeds so regeneration is
//! deterministic. The pinning test (`fixtures_match_hiss`) re-runs hiss and
//! fails if the committed table drifts — the deploy workflow runs it before
//! every build, so nothing on the page can silently stop being true.

/// Who sends a handshake message, from the visitor's ("you") perspective.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Dir {
    ToPeer,
    FromPeer,
}

/// One handshake message: its tokens, real wire size, and a preview of the
/// actual bytes hiss produced.
pub struct Msg {
    pub dir: Dir,
    pub tokens: &'static str,
    pub size: usize,
    pub preview: &'static str,
}

/// One pattern's frozen trace.
pub struct Fixture {
    pub name: &'static str,
    /// The pre-message line (`<- s`), if the pattern has one.
    pub pre: Option<&'static str>,
    pub msgs: &'static [Msg],
    /// Preview of the session id both transports derived (asserted equal).
    pub session: &'static str,
    /// Ciphertext previews of a real transport exchange ("ping" / "pong").
    pub ping_ct: &'static str,
    pub pong_ct: &'static str,
    /// `Transport::OVERHEAD` — the per-record authentication-tag cost.
    pub overhead: usize,
}

include!("fixtures_data.in");

/// Per-pattern editorial metadata (hand-written; the *claims* here mirror the
/// README's pattern tables, and every *number* rendered next to them comes
/// from the pinned fixture).
pub struct Info {
    pub name: &'static str,
    /// The `noise!` body, rendered after a highlighted `hiss::noise!`.
    pub decl: &'static str,
    /// One-line "who is proven" summary, per README / Noise spec §7.7.
    pub blurb: &'static str,
    /// True when the blurb is a security caveat (NN) — rendered in the
    /// reserved warning color.
    pub caveat: bool,
    pub explorer: &'static str,
}

pub static INFO: &[Info] = &[
    Info {
        name: "NN",
        decl: r#" {
    pub NN<X25519, ChaChaPoly, Blake2b> {
        -> e
        <- e, ee
    }
}"#,
        blurb: "no one is proven — an active machine-in-the-middle defeats it outright",
        caveat: true,
        explorer: "https://noiseexplorer.com/patterns/NN/",
    },
    Info {
        name: "NK",
        decl: r#" {
    pub NK<X25519, ChaChaPoly, Blake2b> {
        <- s
        ...
        -> e, es
        <- e, ee
    }
}"#,
        blurb: "peer proven via the key you already hold · you stay anonymous",
        caveat: false,
        explorer: "https://noiseexplorer.com/patterns/NK/",
    },
    Info {
        name: "NX",
        decl: r#" {
    pub NX<X25519, ChaChaPoly, Blake2b> {
        -> e
        <- e, ee, s, es
    }
}"#,
        blurb: "peer proven — their key arrives during the handshake · you stay anonymous",
        caveat: false,
        explorer: "https://noiseexplorer.com/patterns/NX/",
    },
    Info {
        name: "XN",
        decl: r#" {
    pub XN<X25519, ChaChaPoly, Blake2b> {
        -> e
        <- e, ee
        -> s, se
    }
}"#,
        blurb: "you are proven · the peer is not",
        caveat: false,
        explorer: "https://noiseexplorer.com/patterns/XN/",
    },
    Info {
        name: "XX",
        decl: r#" {
    pub XX<X25519, ChaChaPoly, Blake2b> {
        -> e
        <- e, ee, s, es
        -> s, se
    }
}"#,
        blurb: "both proven · identities hidden from the wire · nothing arranged in advance",
        caveat: false,
        explorer: "https://noiseexplorer.com/patterns/XX/",
    },
    Info {
        name: "IK",
        decl: r#" {
    pub IK<X25519, ChaChaPoly, Blake2b> {
        <- s
        ...
        -> e, es, s, ss
        <- e, ee, se
    }
}"#,
        blurb: "both proven in two messages — you ship the peer's key in advance",
        caveat: false,
        explorer: "https://noiseexplorer.com/patterns/IK/",
    },
];

pub fn fixture(name: &str) -> &'static Fixture {
    FIXTURES
        .iter()
        .find(|f| f.name == name)
        .expect("every device pattern has a fixture")
}

pub fn info(name: &str) -> &'static Info {
    INFO.iter()
        .find(|i| i.name == name)
        .expect("every device pattern has metadata")
}

/// The device's whole state space: three choices resolve to a pattern.
/// "peer key known" only means something while the peer authenticates at
/// all (pre-knowing a key *is* how a 2-message pattern authenticates), so
/// the UI coerces it off when `peer` is off — the `_` arms mirror that.
pub fn pick(you: bool, peer: bool, known: bool) -> &'static str {
    match (you, peer, known) {
        (false, false, _) => "NN",
        (false, true, true) => "NK",
        (false, true, false) => "NX",
        (true, false, _) => "XN",
        (true, true, false) => "XX",
        (true, true, true) => "IK",
    }
}
