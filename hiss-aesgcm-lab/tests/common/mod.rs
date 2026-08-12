//! Shared helpers for the lab's integration tests.
//!
//! Two things live here, and both are shared by more than one test binary:
//! [`ScriptedRng`] (the replays and the live interop) and the cacophony vector
//! schema (the replays and the extractor). The main repo keeps its schema
//! inside `tests/noise_cacophony.rs` because its extractor is a module in that
//! same file; here the extractor is its own binary, so the schema has to be
//! reachable from both — and sharing it is what keeps the extractor's
//! `check_invariants` and the replays' the *same* check rather than two
//! drifting copies.

#![allow(dead_code)] // each test binary uses a different subset

use serde::{Deserialize, Serialize};
use std::convert::Infallible;

// ── Deterministic RNG ────────────────────────────────────────────

/// A deterministic RNG that replays a fixed, pre-scripted byte stream.
///
/// Copied from the main repo's `tests/common/mod.rs`, minus the P-256 helpers
/// this crate has no use for. Drop it into [`hiss::provider::EphemeralOnly`]
/// in place of a real CSPRNG to make ephemeral-key generation deterministic:
/// every `fill_bytes` request is served from the scripted bytes in order,
/// which is what lets a known-answer vector pin the ephemeral exactly so the
/// on-wire bytes can be asserted byte-for-byte.
///
/// Test-only: panics if the script is exhausted, so a miswired test fails
/// loudly instead of silently drawing zeros.
pub struct ScriptedRng {
    bytes: Vec<u8>,
    pos: usize,
}

impl ScriptedRng {
    /// Build from one or more byte blocks, concatenated in draw order.
    pub fn new(blocks: &[&[u8]]) -> Self {
        Self {
            bytes: blocks.concat(),
            pos: 0,
        }
    }

    fn take(&mut self, n: usize) -> &[u8] {
        let end = self.pos + n;
        assert!(
            end <= self.bytes.len(),
            "ScriptedRng exhausted: requested {n} bytes at offset {} of {}",
            self.pos,
            self.bytes.len()
        );
        let out = &self.bytes[self.pos..end];
        self.pos = end;
        out
    }
}

// rand_core 0.10 inverts the hierarchy: `TryRng` is the base trait and the
// infallible `Rng` / `CryptoRng` arrive through blanket impls over
// `Error = Infallible`. So this is the whole implementation.
//
// Infallible is the *type-level* claim; exhausting the script still panics
// inside `take`, which is deliberate — a scripted draw that runs off the end
// of its vector is a miswired test, not a runtime error a caller could handle.
impl rand::TryRng for ScriptedRng {
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

// Marker only (no methods): the scripted stream stands in for a CSPRNG in
// deterministic tests, never in production.
impl rand::TryCryptoRng for ScriptedRng {}

// ── Vector schema (cacophony's own) ──────────────────────────────

/// The payload byte-length of each of a vector's six messages.
///
/// Fixed by message *index* across the whole corpus — the AESGCM half no less
/// than the ChaChaPoly half — which is what lets the `noise!` declarations
/// spell `[16]`, `[15]` and `[11]` uniformly across all seventeen patterns.
pub const PAYLOAD_LENS: [usize; 6] = [16, 15, 11, 11, 17, 21];

/// Upstream's top level is an object, not a bare array.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VectorFile {
    pub vectors: Vec<Vector>,
}

/// The thirteen keys the corpus actually uses.
///
/// `deny_unknown_fields` is deliberate and is stricter than `snow`'s own
/// deserializer: a refresh that introduces a new key fails here loudly rather
/// than quietly replaying less than it claims to.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Vector {
    pub protocol_name: String,
    pub init_prologue: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub init_psks: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub init_static: Option<String>,
    pub init_ephemeral: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub init_remote_static: Option<String>,
    pub resp_prologue: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resp_psks: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resp_static: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resp_ephemeral: Option<String>,
    /// Unused by an initiator replay; retained so the vendored entries stay
    /// byte-comparable to upstream.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resp_remote_static: Option<String>,
    pub handshake_hash: String,
    /// Six per vector: the pattern's handshake messages followed by transport
    /// messages, split positionally.
    pub messages: Vec<Message>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Message {
    pub payload: String,
    pub ciphertext: String,
}

pub fn decode(hex_str: &str) -> Vec<u8> {
    hex::decode(hex_str).expect("hex")
}

/// Assert the properties of the *vendored data* that every replay relies on,
/// so a bad refresh fails here rather than as a misleading crypto failure two
/// hundred lines later.
///
/// Run by both the extractor (before writing) and the replays (on load), which
/// is the reason this lives in `common` rather than beside either one.
pub fn check_invariants(v: &Vector) {
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

// ── The filter, as a single source of truth ──────────────────────

/// The seventeen patterns hiss implements.
pub const PATTERNS: [&str; 17] = [
    "N", "K", "Kpsk0", "IKpsk1", "IK", "NK", "IX", "XK", "NN", "XX", "X", "NX", "XN", "KN", "KK",
    "KX", "IN",
];

/// The eight **AESGCM** suites the corpus provides over the two curves hiss
/// shares with it. The exact mirror of the main repo's ChaChaPoly eight.
pub const SUITES: [&str; 8] = [
    "25519_AESGCM_BLAKE2b",
    "25519_AESGCM_BLAKE2s",
    "25519_AESGCM_SHA256",
    "25519_AESGCM_SHA512",
    "448_AESGCM_BLAKE2b",
    "448_AESGCM_BLAKE2s",
    "448_AESGCM_SHA256",
    "448_AESGCM_SHA512",
];

/// Where the vendored subset lives, and where the extractor writes it.
pub const VECTORS_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/vectors/cacophony-aesgcm/cacophony-aesgcm.json"
);

/// Every `Noise_<pattern>_<suite>` name the filter selects — 17 × 8 = 136.
pub fn wanted_protocol_names() -> Vec<String> {
    PATTERNS
        .iter()
        .flat_map(|p| SUITES.iter().map(move |s| format!("Noise_{p}_{s}")))
        .collect()
}

pub fn load_vectors() -> VectorFile {
    let raw = std::fs::read_to_string(VECTORS_PATH).unwrap_or_else(|e| {
        panic!(
            "missing {VECTORS_PATH}: run `CACOPHONY_SRC=… cargo test --test extract \
             extract_cacophony_aesgcm_subset -- --ignored` first ({e})"
        )
    });
    serde_json::from_str(&raw).expect("valid cacophony json")
}
