//! Shared helpers for the integration test suite.

#![allow(dead_code)] // each test binary uses a different subset

use rand::{TryCryptoRng, TryRng};
use std::convert::Infallible;

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

// rand_core 0.10 inverts the hierarchy: `TryRng` is the base trait and the
// infallible `Rng` / `CryptoRng` arrive through blanket impls over
// `Error = Infallible`. So this is the whole implementation — `ScriptedRng`
// is a `CryptoRng` (and satisfies hiss's public bounds) without naming
// either trait.
//
// Infallible is the *type-level* claim; exhausting the script still panics
// inside `take`, which is deliberate — a scripted draw that runs off the end
// of its vector is a miswired test, not a runtime error a caller could
// handle.
impl TryRng for ScriptedRng {
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
impl TryCryptoRng for ScriptedRng {}

// ── Fixed-key minting (P-256) ────────────────────────────────────

use hiss::noise::{Curve, P256};
use hiss::provider::{CryptoKeyProvider, EphemeralOnly, ProviderExt};

/// Mint a P-256 private key from fixed scalar bytes via the public
/// provider API (the scripted block is a valid scalar, accepted on the
/// first rejection-sampling draw).
pub fn private_key(
    seed: &[u8; 32],
) -> <EphemeralOnly<ScriptedRng> as CryptoKeyProvider<P256>>::PrivateKey {
    let mut p = EphemeralOnly::new(ScriptedRng::new(&[seed]));
    p.generate::<P256>().unwrap()
}

/// The public key for a fixed private scalar.
pub fn public_key(seed: &[u8; 32]) -> <P256 as Curve>::PublicKey {
    let mut p = EphemeralOnly::new(ScriptedRng::new(&[seed]));
    let sk = p.generate::<P256>().unwrap();
    p.public(&sk).unwrap()
}

// ── In-memory peer stream for the blocking driver ────────────────

use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

/// A single in-memory `Read + Write` endpoint, retained for any test that
/// needs to stream bytes against an out-of-band peer by hand.
///
/// Writes accumulate into a capture buffer drained per outgoing message
/// by [`take_written`](PeerStream::take_written); reads pull from an
/// inbound queue that the test refills mid-handshake via
/// [`feed`](PeerStream::feed) as the peer produces each message. This is
/// what lets a synchronous, executor-free handshake interleave with a
/// peer that only yields its next message after seeing ours.
#[derive(Clone, Default)]
pub struct PeerStream {
    written: Rc<RefCell<Vec<u8>>>,
    inbound: Rc<RefCell<VecDeque<u8>>>,
}

impl PeerStream {
    /// A fresh stream with empty capture and inbound buffers.
    pub fn new() -> Self {
        Self::default()
    }

    /// Push bytes the peer produced onto the read side.
    pub fn feed(&self, bytes: &[u8]) {
        self.inbound.borrow_mut().extend(bytes.iter().copied());
    }

    /// Drain and return the bytes written since the last call — exactly
    /// one completed outgoing handshake message.
    pub fn take_written(&self) -> Vec<u8> {
        std::mem::take(&mut *self.written.borrow_mut())
    }

    /// Number of fed-but-unread bytes still queued on the read side.
    ///
    /// After a handshake completes, a nonzero value means the peer sent
    /// more bytes than the framing consumed — i.e. an over-long /
    /// trailing-garbage message that left the stream desynchronised.
    pub fn remaining(&self) -> usize {
        self.inbound.borrow().len()
    }
}

impl std::io::Read for PeerStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut q = self.inbound.borrow_mut();
        let n = q.len().min(buf.len());
        for slot in buf.iter_mut().take(n) {
            *slot = q.pop_front().unwrap();
        }
        Ok(n)
    }
}

impl std::io::Write for PeerStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.written.borrow_mut().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
