# Cacophony Noise test vectors (vendored subset)

`cacophony.json` is a filtered subset of a community Noise known-answer-test
corpus that neither hiss nor `snow` produced. It is what gives hiss's
handshakes **third-party** agreement: everything else frozen in this tree is
agreement-with-`snow`.

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
- **This directory's `cacophony.json` sha256:**
  `245dac6c55a70c6278732a89211a8f00ebffa6d37649209710faa9398b485b5d`

## Filter

The seventeen patterns hiss implements × the eight `ChaChaPoly` suites the
corpus provides over the two curves hiss shares with it — 136 of 944:

```
patterns  N K Kpsk0 IKpsk1 IK NK IX XK NN XX X NX XN KN KK KX IN  (17)
suites    {25519,448}_ChaChaPoly_{BLAKE2b,BLAKE2s,SHA256,SHA512}   (8)
```

Every one of the 136 cells exists upstream; the extractor asserts it selected
exactly 136 before writing, and its `PATTERNS` array is the single source of
truth for the filter. The remaining 808 are `AESGCM` suites (hiss ships no
AES-GCM) or patterns hiss does not implement — an unreplayed vector in a KAT
directory is a claim with nothing behind it, so they are not vendored.

Upstream order is preserved and every value is re-emitted verbatim; only
whitespace, key order and the elision of absent optional keys differ, so the
entries stay `jq`-comparable to the source entry for entry. All 136 are
replayed by `tests/noise_cacophony.rs`, in **both roles** — 136 initiator and
136 responder replays, 272 tests.

## Refresh

```
CACOPHONY_SRC=~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/\
  snow-0.10.0/tests/vectors/cacophony.txt \
  cargo test --all-features --test noise_cacophony \
  extract_cacophony_subset -- --ignored
```

Then update both hashes above.

## Licence

**Upstream-bytes check — performed, and it changed the answer.** Before
writing this file the originating repository was fetched and its
`vectors/cacophony.txt` compared against `snow`'s copy: the two are
**byte-identical** (same 1,709,817 bytes, same sha256 as pinned above).
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

`snow` is `license = "Apache-2.0 OR MIT"` (`snow-0.10.0/Cargo.toml`).

**What `snow` itself documents about the file: nothing.** The vector file
carries no per-file licence header, no attribution comment, and no
`LICENSE`/`NOTICE` anywhere under `tests/` — it is pure JSON from byte 0. A
case-insensitive recursive grep for `cacophony|centromere` over the whole
package returns exactly two hits, both the filename and the test-function name.
Had the upstream check above not been done, the attribution to the Cacophony
implementation would have been an *inference* from the filename and the payload
style (Austrian-economist names, a `"John Galt"` prologue) rather than a
statement anyone in the chain makes. The byte comparison is what turns it into
a verified fact.

## What these vectors prove, and what they do not

They prove byte-for-byte agreement with an implementation that is **not**
`snow`, on a corpus neither project generated: handshake ciphertexts, recovered
handshake payloads, revealed remote statics, the final handshake hash, and all
three to five transport messages in the direction the corpus records them.

For X448 they are the **only** cross-implementation check that exists: `snow`'s
default resolver returns `None` for `DHChoice::Curve448`, so `snow`'s own
harness skips all 472 of its `448` vectors at runtime.

They do **not** make hiss standards-validated at the handshake level. hiss did
not audit the Cacophony implementation, and cacophony's generation was not
reviewed here. This is agreement with a second, independent implementation —
not vectors from a standards body.
