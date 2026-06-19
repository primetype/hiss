//! Shared helpers for the integration test suite.

#![allow(dead_code)] // each test binary uses a different subset

use rand::{CryptoRng, RngCore};

/// A deterministic RNG that replays a fixed, pre-scripted byte stream.
///
/// Drop it into [`hiss::provider::EphemeralOnly`] in place of a real
/// CSPRNG to make a handshake's ephemeral-key generation fully
/// deterministic: every `fill_bytes` request is served from the scripted
/// bytes in order. That is what lets a Noise known-answer vector pin the
/// initiator/responder ephemeral exactly, so the on-wire bytes are
/// reproducible and can be asserted byte-for-byte.
///
/// A P-256 ephemeral consumes one 32-byte block: `P256r1PrivateKey::
/// generate` rejection-samples a scalar in `[1, n-1]`, and a valid vector
/// scalar is accepted on the first draw, so exactly the scripted 32 bytes
/// become the ephemeral private scalar.
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

impl RngCore for ScriptedRng {
    fn next_u32(&mut self) -> u32 {
        u32::from_le_bytes(self.take(4).try_into().unwrap())
    }

    fn next_u64(&mut self) -> u64 {
        u64::from_le_bytes(self.take(8).try_into().unwrap())
    }

    fn fill_bytes(&mut self, dst: &mut [u8]) {
        let n = dst.len();
        dst.copy_from_slice(self.take(n));
    }
}

// Marker only (no methods): the scripted stream stands in for a CSPRNG in
// deterministic tests, never in production.
impl CryptoRng for ScriptedRng {}
