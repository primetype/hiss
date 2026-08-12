# Cacophony Noise **AESGCM** test vectors (vendored subset)

`cacophony-aesgcm.json` is a filtered subset of a community Noise
known-answer-test corpus that neither hiss nor `snow` produced. It is what
gives this lab's AESGCM handshakes **third-party** agreement: it is the only
one of the three validation legs that spans the full suite matrix, and for
X448 it is the only cross-implementation check that exists at all.

This directory is the lab's **own** copy. The main repo's
`tests/vectors/cacophony/` is frozen and was not touched: its 136 ChaChaPoly
vectors, its filter, its `PROVENANCE.md` and its generator are all exactly as
they were. That file's sentence *"The remaining 808 are `AESGCM` suites (hiss
ships no AES-GCM) … an unreplayed vector in a KAT directory is a claim with
nothing behind it"* is not contradicted here — the 136 vendored below **are**
replayed, 272 times, by `tests/cacophony_aesgcm.rs`. (At exit, when AESGCM
becomes hiss surface, these merge into the frozen corpus and that sentence
gets rewritten. See `../../README.md`.)

## Source and pins

- **Acquired from:** `tests/vectors/cacophony.txt` inside the **snow 0.10.0**
  crate package (`~/.cargo/registry/src/*/snow-0.10.0/`).
  Upstream repository <https://github.com/mcginty/snow>, package
  `.cargo_vcs_info.json` sha1 `4bb43f50370bdb3e8b1b57814ac662864db2704f`.
- **Corpus file sha256:**
  `3bde7c09a6f349ee11c825c50fcc02649f8f02a47c857a459206b357f9386cae`
  (944 vectors, 1,709,817 bytes). JSON despite the `.txt` name.
- **Originating project (checked, see below):**
  <https://github.com/haskell-cryptography/cacophony> (formerly
  `centromere/cacophony`), file `vectors/cacophony.txt`, last touched by commit
  `18b7348c54fd61fcd0c220298883de0d09c8364d`.
- **This directory's `cacophony-aesgcm.json` sha256:**
  `14d10e66b398ac4a8108c06d49ec88a1ba1b1692435537bae4ad9831695fbc5c`
  (136 vectors, 275,418 bytes)

These are the same source file and the same pins the main repo's
`tests/vectors/cacophony/PROVENANCE.md` records — deliberately, because it *is*
the same file. The two directories differ only in which half of it they select.

## Filter

The seventeen patterns hiss implements × the eight `AESGCM` suites the corpus
provides over the two curves hiss shares with it — 136 of 944:

```
patterns  N K Kpsk0 IKpsk1 IK NK IX XK NN XX X NX XN KN KK KX IN  (17)
suites    {25519,448}_AESGCM_{BLAKE2b,BLAKE2s,SHA256,SHA512}      (8)
```

Upstream carries **472** AESGCM vectors in total; the other 336 are patterns
hiss does not implement, and are not vendored for the same reason the main
repo gives — an unreplayed vector in a KAT directory is a claim with nothing
behind it.

Every one of the 136 cells exists upstream (verified: 17 per suite, all eight
suites, zero gaps). The extractor asserts it selected exactly 136 before
writing, and `PATTERNS`/`SUITES` in `tests/common/mod.rs` are the single source
of truth for the filter. A second, non-`#[ignore]`d test
(`vendored_subset_matches_the_declared_filter`) re-checks the vendored file
against that same filter on every `cargo test`, including that every entry is
in fact an `_AESGCM_` one — vendoring the ChaChaPoly half by mistake is the
single error that would leave all 272 replays green while proving nothing
about AES-GCM.

Sixteen vectors carry a pre-shared key (`Kpsk0` and `IKpsk1` × 8 suites);
every vector has exactly six messages, with payload lengths fixed by message
index at (16, 15, 11, 11, 17, 21) — the same shape as the ChaChaPoly half, which
is what lets the replay harness be a structural clone of
`tests/noise_cacophony.rs`.

Upstream order is preserved and every value is re-emitted verbatim; only
whitespace, key order and the elision of absent optional keys differ, so the
entries stay `jq`-comparable to the source entry for entry. All 136 are
replayed by `tests/cacophony_aesgcm.rs`, in **both roles** — 136 initiator and
136 responder replays, 272 tests.

## Refresh

```
CACOPHONY_SRC=~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/\
  snow-0.10.0/tests/vectors/cacophony.txt \
  cargo test --test extract extract_cacophony_aesgcm_subset -- --ignored
```

Then update the `cacophony-aesgcm.json` hash above.

## Licence

**Upstream-bytes check — performed independently for this directory, not
inherited.** Before writing this file the originating repository's
`vectors/cacophony.txt` was fetched fresh at commit `18b7348c…` and compared
against `snow`'s copy: the two are **byte-identical** (same 1,709,817 bytes,
same sha256 as pinned above). The 136 vendored entries were then compared
entry-for-entry against that fresh upstream download with `jq` — sorted keys,
absent-optional elisions normalised — and are **identical, in upstream order**.

Upstream is released under **The Unlicense** (a public-domain dedication),
which is no more restrictive than `snow`'s grant. So the primary grant cited
here is upstream's, with `snow` named as the acquisition path — the vendored
bytes physically come from `snow`'s package, and both projects' licence texts
are kept in this directory:

| File | Grant | Applies to |
|------|-------|-----------|
| `LICENSE-UNLICENSE` | The Unlicense | the Cacophony project, the vectors' origin — the primary grant |
| `LICENSE-MIT` | MIT, `Copyright (c) 2021 Jake McGinty` | `snow` 0.10.0, the package these bytes were copied out of |
| `LICENSE-APACHE` | Apache-2.0 (stock; copyright appendix absent) | as above |

`snow` is `license = "Apache-2.0 OR MIT"` (`snow-0.10.0/Cargo.toml`). The three
files are byte-identical copies of the main repo's
`tests/vectors/cacophony/` set — same bytes, same grants. They are duplicated
rather than referenced because this is a separate crate and must carry its own.

## What these vectors prove, and what they do not

They prove byte-for-byte agreement between this lab's AESGCM
[`Cipher`](../../src/lib.rs) — cryptoxide's unreleased AES-GCM, driving hiss's
Noise state machine — and an implementation that is **not** `snow` and not
cryptoxide, on a corpus neither project generated: handshake ciphertexts,
recovered handshake payloads, revealed remote statics, the final handshake
hash, and all three to five transport messages in the direction the corpus
records them.

Because every vector has six messages, the replays reach transport nonces well
past 0 — which is what makes them able to catch a little-endian nonce. Noise
**§12.4** specifies the AESGCM nonce as 32 zero bits followed by the **big**-
endian counter, and counter 0 is byte-identical in either encoding, so an
LE-nonce bug is invisible until n = 1. Measured: an LE mutant matches the
corpus through the handshake message *and* the first transport message, and
first diverges at message 2.

For X448 these are the **only** cross-implementation check that exists: `snow`'s
default resolver returns `None` for `DHChoice::Curve448`, so the live-interop
leg covers 25519 only and `snow`'s own harness skips all of its `448` vectors
at runtime.

They do **not** make hiss standards-validated at the handshake level. hiss did
not audit the Cacophony implementation, and cacophony's generation was not
reviewed here. This is agreement with a second, independent implementation —
not vectors from a standards body.
