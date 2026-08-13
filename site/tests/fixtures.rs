//! The fixture generator and its pinning test.
//!
//! `src/fixtures_data.in` is a frozen table of real handshake traces: every
//! byte was produced by hiss itself over the eight patterns the wizard can
//! show, deterministically (ChaCha20 RNG, fixed seeds, empty prologue). The shipped
//! WASM never links hiss — this file is where the page's numbers meet the
//! crate:
//!
//! * `fixtures_match_hiss` regenerates the table in memory and fails if the
//!   committed file differs. The deploy workflow runs it before every build.
//! * `regenerate` (ignored) rewrites the file:
//!   `cargo test --test fixtures -- --ignored regenerate`
//!
//! The declarations below are byte-for-byte the ones `tests/noise_kat.rs`
//! and `tests/noise_macro.rs` compile in the hiss repo (over X25519).

use std::fmt::Write as _;

use hiss::noise::{Blake2b, ChaChaPoly, Transport, X25519};
use hiss::provider::{EphemeralOnly, ProviderExt};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

hiss::noise! { pub NN<X25519, ChaChaPoly, Blake2b> { -> e <- e, ee } }
hiss::noise! { pub NK<X25519, ChaChaPoly, Blake2b> { <- s ... -> e, es <- e, ee } }
hiss::noise! { pub NX<X25519, ChaChaPoly, Blake2b> { -> e <- e, ee, s, es } }
hiss::noise! { pub XN<X25519, ChaChaPoly, Blake2b> { -> e <- e, ee -> s, se } }
hiss::noise! { pub XX<X25519, ChaChaPoly, Blake2b> { -> e <- e, ee, s, es -> s, se } }
hiss::noise! { pub IK<X25519, ChaChaPoly, Blake2b> { <- s ... -> e, es, s, ss <- e, ee, se } }
hiss::noise! { pub XK<X25519, ChaChaPoly, Blake2b> { <- s ... -> e, es <- e, ee -> s, se } }
hiss::noise! { pub IX<X25519, ChaChaPoly, Blake2b> { -> e, s <- e, ee, se, s, es } }

/// The device shows the simplest honest run: no prologue.
const PROLOGUE: &[u8] = &[];

fn provider(seed: u64) -> EphemeralOnly<ChaCha20Rng> {
    EphemeralOnly::new(ChaCha20Rng::seed_from_u64(seed))
}

/// One captured message: sent by the initiator ("you")?, its tokens, bytes.
struct TMsg {
    to_peer: bool,
    tokens: &'static str,
    bytes: Vec<u8>,
}

struct Trace {
    name: &'static str,
    pre: Option<&'static str>,
    msgs: Vec<TMsg>,
    session: Vec<u8>,
    ping: Vec<u8>,
    pong: Vec<u8>,
    overhead: usize,
}

/// Run the transport exchange the device replays — "ping" from you, "pong"
/// back — proving both directions decrypt, and capture the ciphertexts.
/// A macro rather than a function: each pattern's `Transport<P>` is its own
/// concrete type, and going generic over patterns is what sank the retired
/// demo crate (see the 0.2.0 changelog).
macro_rules! transport_exchange {
    ($i_t:ident, $r_t:ident, $pat:ty) => {{
        let overhead = Transport::<$pat>::OVERHEAD;
        let mut ping = vec![0u8; 4 + overhead];
        let n = $i_t.send(b"ping", &mut ping).unwrap();
        assert_eq!(n, ping.len());
        let mut opened = [0u8; 4];
        let m = $r_t.receive(&ping, &mut opened).unwrap();
        assert_eq!(&opened[..m], b"ping");

        let mut pong = vec![0u8; 4 + overhead];
        let n = $r_t.send(b"pong", &mut pong).unwrap();
        assert_eq!(n, pong.len());
        let m = $i_t.receive(&pong, &mut opened).unwrap();
        assert_eq!(&opened[..m], b"pong");

        assert_eq!($i_t.session_id().as_ref(), $r_t.session_id().as_ref());
        ($i_t.session_id().as_ref().to_vec(), ping, pong, overhead)
    }};
}

fn trace_nn() -> Trace {
    let ip = provider(0xA1);
    let rp = provider(0xB1);

    let (msg1, i_hs) = NN::initiator(ip, PROLOGUE).write_message_1().unwrap();
    let r_hs = NN::responder(rp, PROLOGUE).read_message_1(&msg1).unwrap();
    let (msg2, mut r_t) = r_hs.write_message_2().unwrap();
    let mut i_t = i_hs.read_message_2(&msg2).unwrap();

    assert_eq!(msg1.len(), NN::MSG1_SIZE);
    assert_eq!(msg2.len(), NN::MSG2_SIZE);
    let (session, ping, pong, overhead) = transport_exchange!(i_t, r_t, NN);
    Trace {
        name: "NN",
        pre: None,
        msgs: vec![
            TMsg {
                to_peer: true,
                tokens: "e",
                bytes: msg1.to_vec(),
            },
            TMsg {
                to_peer: false,
                tokens: "e, ee",
                bytes: msg2.to_vec(),
            },
        ],
        session,
        ping,
        pong,
        overhead,
    }
}

fn trace_nk() -> Trace {
    let ip = provider(0xA2);
    let mut rp = provider(0xB2);
    let r_static = rp.generate::<X25519>().unwrap();
    let r_pub = rp.public(&r_static).unwrap();

    let (msg1, i_hs) = NK::initiator(ip, PROLOGUE, r_pub)
        .write_message_1()
        .unwrap();
    let r_hs = NK::responder(rp, PROLOGUE, r_static)
        .unwrap()
        .read_message_1(&msg1)
        .unwrap();
    let (msg2, mut r_t) = r_hs.write_message_2().unwrap();
    let mut i_t = i_hs.read_message_2(&msg2).unwrap();

    assert_eq!(msg1.len(), NK::MSG1_SIZE);
    assert_eq!(msg2.len(), NK::MSG2_SIZE);
    let (session, ping, pong, overhead) = transport_exchange!(i_t, r_t, NK);
    Trace {
        name: "NK",
        pre: Some("<- s"),
        msgs: vec![
            TMsg {
                to_peer: true,
                tokens: "e, es",
                bytes: msg1.to_vec(),
            },
            TMsg {
                to_peer: false,
                tokens: "e, ee",
                bytes: msg2.to_vec(),
            },
        ],
        session,
        ping,
        pong,
        overhead,
    }
}

fn trace_nx() -> Trace {
    let ip = provider(0xA3);
    let mut rp = provider(0xB3);
    let r_static = rp.generate::<X25519>().unwrap();

    let (msg1, i_hs) = NX::initiator(ip, PROLOGUE).write_message_1().unwrap();
    let r_hs = NX::responder(rp, PROLOGUE).read_message_1(&msg1).unwrap();
    let (msg2, mut r_t) = r_hs.write_message_2(r_static).unwrap();
    let mut i_t = i_hs.read_message_2(&msg2).unwrap();

    assert_eq!(msg1.len(), NX::MSG1_SIZE);
    assert_eq!(msg2.len(), NX::MSG2_SIZE);
    let (session, ping, pong, overhead) = transport_exchange!(i_t, r_t, NX);
    Trace {
        name: "NX",
        pre: None,
        msgs: vec![
            TMsg {
                to_peer: true,
                tokens: "e",
                bytes: msg1.to_vec(),
            },
            TMsg {
                to_peer: false,
                tokens: "e, ee, s, es",
                bytes: msg2.to_vec(),
            },
        ],
        session,
        ping,
        pong,
        overhead,
    }
}

fn trace_xn() -> Trace {
    let mut ip = provider(0xA4);
    let i_static = ip.generate::<X25519>().unwrap();
    let rp = provider(0xB4);

    let (msg1, i_hs) = XN::initiator(ip, PROLOGUE).write_message_1().unwrap();
    let r_hs = XN::responder(rp, PROLOGUE).read_message_1(&msg1).unwrap();
    let (msg2, r_hs) = r_hs.write_message_2().unwrap();
    let i_hs = i_hs.read_message_2(&msg2).unwrap();
    let (msg3, mut i_t) = i_hs.write_message_3(i_static).unwrap();
    let mut r_t = r_hs.read_message_3(&msg3).unwrap();

    assert_eq!(msg1.len(), XN::MSG1_SIZE);
    assert_eq!(msg2.len(), XN::MSG2_SIZE);
    assert_eq!(msg3.len(), XN::MSG3_SIZE);
    let (session, ping, pong, overhead) = transport_exchange!(i_t, r_t, XN);
    Trace {
        name: "XN",
        pre: None,
        msgs: vec![
            TMsg {
                to_peer: true,
                tokens: "e",
                bytes: msg1.to_vec(),
            },
            TMsg {
                to_peer: false,
                tokens: "e, ee",
                bytes: msg2.to_vec(),
            },
            TMsg {
                to_peer: true,
                tokens: "s, se",
                bytes: msg3.to_vec(),
            },
        ],
        session,
        ping,
        pong,
        overhead,
    }
}

fn trace_xx() -> Trace {
    let mut ip = provider(0xA5);
    let i_static = ip.generate::<X25519>().unwrap();
    let mut rp = provider(0xB5);
    let r_static = rp.generate::<X25519>().unwrap();

    let (msg1, i_hs) = XX::initiator(ip, PROLOGUE).write_message_1().unwrap();
    let r_hs = XX::responder(rp, PROLOGUE).read_message_1(&msg1).unwrap();
    let (msg2, r_hs) = r_hs.write_message_2(r_static).unwrap();
    let i_hs = i_hs.read_message_2(&msg2).unwrap();
    let (msg3, mut i_t) = i_hs.write_message_3(i_static).unwrap();
    let mut r_t = r_hs.read_message_3(&msg3).unwrap();

    assert_eq!(msg1.len(), XX::MSG1_SIZE);
    assert_eq!(msg2.len(), XX::MSG2_SIZE);
    assert_eq!(msg3.len(), XX::MSG3_SIZE);
    let (session, ping, pong, overhead) = transport_exchange!(i_t, r_t, XX);
    Trace {
        name: "XX",
        pre: None,
        msgs: vec![
            TMsg {
                to_peer: true,
                tokens: "e",
                bytes: msg1.to_vec(),
            },
            TMsg {
                to_peer: false,
                tokens: "e, ee, s, es",
                bytes: msg2.to_vec(),
            },
            TMsg {
                to_peer: true,
                tokens: "s, se",
                bytes: msg3.to_vec(),
            },
        ],
        session,
        ping,
        pong,
        overhead,
    }
}

fn trace_ik() -> Trace {
    let mut ip = provider(0xA6);
    let i_static = ip.generate::<X25519>().unwrap();
    let mut rp = provider(0xB6);
    let r_static = rp.generate::<X25519>().unwrap();
    let r_pub = rp.public(&r_static).unwrap();

    let (msg1, i_hs) = IK::initiator(ip, PROLOGUE, r_pub)
        .write_message_1(i_static)
        .unwrap();
    let r_hs = IK::responder(rp, PROLOGUE, r_static)
        .unwrap()
        .read_message_1(&msg1)
        .unwrap();
    let (msg2, mut r_t) = r_hs.write_message_2().unwrap();
    let mut i_t = i_hs.read_message_2(&msg2).unwrap();

    assert_eq!(msg1.len(), IK::MSG1_SIZE);
    assert_eq!(msg2.len(), IK::MSG2_SIZE);
    let (session, ping, pong, overhead) = transport_exchange!(i_t, r_t, IK);
    Trace {
        name: "IK",
        pre: Some("<- s"),
        msgs: vec![
            TMsg {
                to_peer: true,
                tokens: "e, es, s, ss",
                bytes: msg1.to_vec(),
            },
            TMsg {
                to_peer: false,
                tokens: "e, ee, se",
                bytes: msg2.to_vec(),
            },
        ],
        session,
        ping,
        pong,
        overhead,
    }
}

fn trace_xk() -> Trace {
    let mut ip = provider(0xA7);
    let i_static = ip.generate::<X25519>().unwrap();
    let mut rp = provider(0xB7);
    let r_static = rp.generate::<X25519>().unwrap();
    let r_pub = rp.public(&r_static).unwrap();

    let (msg1, i_hs) = XK::initiator(ip, PROLOGUE, r_pub)
        .write_message_1()
        .unwrap();
    let r_hs = XK::responder(rp, PROLOGUE, r_static)
        .unwrap()
        .read_message_1(&msg1)
        .unwrap();
    let (msg2, r_hs) = r_hs.write_message_2().unwrap();
    let i_hs = i_hs.read_message_2(&msg2).unwrap();
    let (msg3, mut i_t) = i_hs.write_message_3(i_static).unwrap();
    let mut r_t = r_hs.read_message_3(&msg3).unwrap();

    assert_eq!(msg1.len(), XK::MSG1_SIZE);
    assert_eq!(msg2.len(), XK::MSG2_SIZE);
    assert_eq!(msg3.len(), XK::MSG3_SIZE);
    let (session, ping, pong, overhead) = transport_exchange!(i_t, r_t, XK);
    Trace {
        name: "XK",
        pre: Some("<- s"),
        msgs: vec![
            TMsg {
                to_peer: true,
                tokens: "e, es",
                bytes: msg1.to_vec(),
            },
            TMsg {
                to_peer: false,
                tokens: "e, ee",
                bytes: msg2.to_vec(),
            },
            TMsg {
                to_peer: true,
                tokens: "s, se",
                bytes: msg3.to_vec(),
            },
        ],
        session,
        ping,
        pong,
        overhead,
    }
}

fn trace_ix() -> Trace {
    let mut ip = provider(0xA8);
    let i_static = ip.generate::<X25519>().unwrap();
    let mut rp = provider(0xB8);
    let r_static = rp.generate::<X25519>().unwrap();

    let (msg1, i_hs) = IX::initiator(ip, PROLOGUE)
        .write_message_1(i_static)
        .unwrap();
    let r_hs = IX::responder(rp, PROLOGUE).read_message_1(&msg1).unwrap();
    let (msg2, mut r_t) = r_hs.write_message_2(r_static).unwrap();
    let mut i_t = i_hs.read_message_2(&msg2).unwrap();

    assert_eq!(msg1.len(), IX::MSG1_SIZE);
    assert_eq!(msg2.len(), IX::MSG2_SIZE);
    let (session, ping, pong, overhead) = transport_exchange!(i_t, r_t, IX);
    Trace {
        name: "IX",
        pre: None,
        msgs: vec![
            TMsg {
                to_peer: true,
                tokens: "e, s",
                bytes: msg1.to_vec(),
            },
            TMsg {
                to_peer: false,
                tokens: "e, ee, se, s, es",
                bytes: msg2.to_vec(),
            },
        ],
        session,
        ping,
        pong,
        overhead,
    }
}

fn traces() -> Vec<Trace> {
    vec![
        trace_nn(),
        trace_nk(),
        trace_nx(),
        trace_xn(),
        trace_xx(),
        trace_ik(),
        trace_xk(),
        trace_ix(),
    ]
}

/// First eight bytes as spaced hex, with an ellipsis when truncated.
fn preview(bytes: &[u8]) -> String {
    let shown = bytes.len().min(8);
    let mut s = String::new();
    for (i, b) in bytes[..shown].iter().enumerate() {
        if i > 0 {
            s.push(' ');
        }
        let _ = write!(s, "{b:02x}");
    }
    if bytes.len() > shown {
        s.push_str(" …");
    }
    s
}

fn render(traces: &[Trace]) -> String {
    let mut out = String::new();
    out.push_str(
        "// @generated by tests/fixtures.rs — do not edit by hand.\n\
         //   regenerate: cargo test --test fixtures -- --ignored regenerate\n\
         //\n\
         // Every byte below was produced by hiss itself (X25519 · ChaChaPoly ·\n\
         // Blake2b, ChaCha20 RNG with fixed seeds, empty prologue) and is pinned\n\
         // against the crate by the `fixtures_match_hiss` test on every deploy.\n\
         \n\
         pub static FIXTURES: &[Fixture] = &[\n",
    );
    for t in traces {
        let _ = writeln!(out, "    Fixture {{");
        let _ = writeln!(out, "        name: \"{}\",", t.name);
        match t.pre {
            Some(p) => {
                let _ = writeln!(out, "        pre: Some(\"{p}\"),");
            }
            None => {
                let _ = writeln!(out, "        pre: None,");
            }
        }
        let _ = writeln!(out, "        msgs: &[");
        for m in &t.msgs {
            let dir = if m.to_peer { "ToPeer" } else { "FromPeer" };
            let _ = writeln!(
                out,
                "            Msg {{ dir: Dir::{dir}, tokens: \"{}\", size: {}, preview: \"{}\" }},",
                m.tokens,
                m.bytes.len(),
                preview(&m.bytes),
            );
        }
        let _ = writeln!(out, "        ],");
        let _ = writeln!(out, "        session: \"{}\",", preview(&t.session));
        let _ = writeln!(out, "        ping_ct: \"{}\",", preview(&t.ping));
        let _ = writeln!(out, "        pong_ct: \"{}\",", preview(&t.pong));
        let _ = writeln!(out, "        overhead: {},", t.overhead);
        let _ = writeln!(out, "    }},");
    }
    out.push_str("];\n");
    out
}

fn data_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/fixtures_data.in")
}

/// The pin: the committed table is exactly what hiss produces today.
#[test]
fn fixtures_match_hiss() {
    let expected = render(&traces());
    let committed = std::fs::read_to_string(data_path()).expect(
        "src/fixtures_data.in is missing — generate it with \
         `cargo test --test fixtures -- --ignored regenerate`",
    );
    assert_eq!(
        committed, expected,
        "src/fixtures_data.in no longer matches what hiss produces; \
         regenerate with `cargo test --test fixtures -- --ignored regenerate` \
         and review the page against the new numbers",
    );
}

/// Rewrite the table. Ignored so it only runs on demand.
#[test]
#[ignore = "writes src/fixtures_data.in; run explicitly to regenerate"]
fn regenerate() {
    std::fs::write(data_path(), render(&traces())).unwrap();
}
