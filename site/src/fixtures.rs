//! Frozen handshake traces and per-pattern UI metadata for the wizard.
//!
//! The trace table (`fixtures_data.in`) is **generated** by
//! `tests/fixtures.rs`: every byte was produced by hiss itself, over the six
//! patterns the wizard can recommend, with fixed RNG seeds so regeneration is
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

/// A pattern that also satisfies the visitor's answers, with the trade-off
/// that would make someone prefer it. Wording follows the README's tables.
pub struct Alt {
    pub name: &'static str,
    pub note: &'static str,
    pub explorer: &'static str,
}

/// Per-pattern editorial metadata (hand-written; the *claims* here mirror the
/// README's pattern tables and the Noise spec's §7.7 property tables, and
/// every *number* rendered next to them comes from the pinned fixture).
pub struct Info {
    pub name: &'static str,
    /// The `noise!` body, rendered after a highlighted `hiss::noise!`.
    pub decl: &'static str,
    /// "What you get" bullets for the result card.
    pub why: &'static [&'static str],
    /// A security caveat shown in the reserved warning color, when the
    /// honest answer to the visitor's choices deserves one.
    pub warn_note: Option<&'static str>,
    pub alternates: &'static [Alt],
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
        why: &[
            "an encrypted channel — to an unverified stranger",
            "forward secrecy from the ephemeral exchange",
            "nothing arranged in advance, two messages",
        ],
        warn_note: Some(
            "NN authenticates no one: an active machine-in-the-middle defeats it \
             outright. Use it only with authentication layered on top — or answer \
             again; XX needs nothing arranged in advance either.",
        ),
        alternates: &[Alt {
            name: "XX",
            note: "mutual authentication with the same \"nothing pre-shared\" start",
            explorer: "https://noiseexplorer.com/patterns/XX/",
        }],
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
        why: &[
            "the peer is proven against the key you already hold",
            "you stay anonymous — nothing identifies you",
            "two messages; the peer's key never rides the wire",
        ],
        warn_note: None,
        alternates: &[
            Alt {
                name: "NX",
                note: "no pre-shared key — the peer's key arrives during the handshake",
                explorer: "https://noiseexplorer.com/patterns/NX/",
            },
            Alt {
                name: "XX",
                note: "upgrade to mutual authentication",
                explorer: "https://noiseexplorer.com/patterns/XX/",
            },
        ],
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
        why: &[
            "the peer proves possession of a key — which arrives during the handshake",
            "you stay anonymous — nothing identifies you",
            "check the received key against something you trust before relying on it",
        ],
        warn_note: None,
        alternates: &[
            Alt {
                name: "NK",
                note: "pre-share the peer's key instead — it then never rides the wire",
                explorer: "https://noiseexplorer.com/patterns/NK/",
            },
            Alt {
                name: "XX",
                note: "upgrade to mutual authentication",
                explorer: "https://noiseexplorer.com/patterns/XX/",
            },
        ],
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
        why: &[
            "you are proven to the peer",
            "the peer stays unproven — be sure that is really what you want",
            "three messages",
        ],
        warn_note: None,
        alternates: &[Alt {
            name: "XX",
            note: "almost always the better call — the peer is proven too",
            explorer: "https://noiseexplorer.com/patterns/XX/",
        }],
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
        why: &[
            "both sides proven during the handshake",
            "identities hidden from a passive eavesdropper",
            "nothing needs arranging in advance",
            "forward secrecy from the ephemeral exchange",
        ],
        warn_note: None,
        alternates: &[
            Alt {
                name: "IX",
                note: "two messages instead of three — your identity travels in the clear",
                explorer: "https://noiseexplorer.com/patterns/IX/",
            },
            Alt {
                name: "IK",
                note: "two messages — if you can ship the peer's key in advance",
                explorer: "https://noiseexplorer.com/patterns/IK/",
            },
        ],
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
        why: &[
            "both sides proven",
            "two messages — the fewest for mutual authentication",
            "requires the peer's public key shipped in advance",
        ],
        warn_note: None,
        alternates: &[
            Alt {
                name: "XK",
                note: "hides your identity from an eavesdropper — costs an extra round trip",
                explorer: "https://noiseexplorer.com/patterns/XK/",
            },
            Alt {
                name: "XX",
                note: "nothing pre-arranged — three messages",
                explorer: "https://noiseexplorer.com/patterns/XX/",
            },
        ],
        explorer: "https://noiseexplorer.com/patterns/IK/",
    },
];

pub fn fixture(name: &str) -> &'static Fixture {
    FIXTURES
        .iter()
        .find(|f| f.name == name)
        .expect("every wizard pattern has a fixture")
}

pub fn info(name: &str) -> &'static Info {
    INFO.iter()
        .find(|i| i.name == name)
        .expect("every wizard pattern has metadata")
}

/// The wizard's whole state space: three answers resolve to a pattern.
/// "peer key known" only means something while the peer authenticates at
/// all (pre-knowing a key *is* how a 2-message pattern authenticates), so
/// the wizard never asks it when `peer` is off — the `_` arms mirror that.
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
