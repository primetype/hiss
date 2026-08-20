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
  `aeca61ba0b93c6da8db1b9b37274d98ef78009aa8e09b1b56bbef6b9332ad58f`
  (320 vectors, 651,286 bytes)

## Filter

The seventeen patterns hiss implements, plus three psk-placement variants,
× the sixteen suites the corpus provides over the two curves and the two
ciphers hiss shares with it — 320 of 944:

```
patterns  N K Kpsk0 IKpsk1 IK NK IX XK NN XX X NX XN KN KK KX IN
          NNpsk0 NNpsk2 XXpsk3                                              (20)
suites    {25519,448}_{ChaChaPoly,AESGCM}_{BLAKE2b,BLAKE2s,SHA256,SHA512}   (16)
```

The second pattern row exists to pin *psk positions*: with `Kpsk0` (psk
first) and `IKpsk1` (psk ends message 1), every placement a `pskN` modifier
can name — psk0 through psk3 — has a third-party-pinned representative.
There is no psk4 row because no fundamental pattern has a fourth message.

The two ciphers are exact mirrors in the corpus: every one of the 320 cells
exists upstream (twenty patterns per suite, sixteen suites, zero gaps), and
the extractor asserts it selected exactly 320 before writing. `PATTERNS` and
`SUITES` in `tests/noise_cacophony.rs` are the single source of truth for the
filter — shared by the extractor and by the coverage test
(`every_vendored_suite_is_instantiated`) that checks the vendored file against
them on every run: every vendored vector must be a cell of the instantiated
matrix, and every cell must have a vector. The remaining 624 upstream vectors
are patterns hiss does not implement — an unreplayed vector in a KAT directory
is a claim with nothing behind it, so they are not vendored.

Upstream order is preserved and every value is re-emitted verbatim; only
whitespace, key order and the elision of absent optional keys differ, so the
entries stay `jq`-comparable to the source entry for entry. All 320 are
replayed by `tests/noise_cacophony.rs`, in **both roles** — 320 initiator and
320 responder replays, plus the staged `IK` responder read on each suite:
656 tests.

## Refresh

```
CACOPHONY_SRC=~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/\
  snow-0.10.0/tests/vectors/cacophony.txt \
  cargo test --all-features --test noise_cacophony \
  extract_cacophony_subset -- --ignored
```

Then update both hashes above. A refresh from the same upstream commit is a
no-op; the 2026-08-20 widening from the 160 `ChaChaPoly` vectors to all 320
was checked additions-only — each previously vendored entry byte-identical and
in the same relative order, the `AESGCM` entries interleaved where upstream
has them.

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

For `AESGCM` they are also what pins the cipher's Noise framing against a
foreign implementation: the 16-byte tag width, through every compile-time
message size, and the §12.4 nonce — 32 zero bits then the counter
**big**-endian. Counter 0 is byte-identical in either byte order, so a
little-endian nonce agrees with the corpus through the handshake message and
the first transport message and first diverges at transport message 2 for
one-way patterns and 4 for interactive ones, whose senders alternate
(measured); every vector carries six messages, so every replay reaches it.

They do **not** make hiss standards-validated at the handshake level. hiss did
not audit the Cacophony implementation, and cacophony's generation was not
reviewed here. This is agreement with a second, independent implementation —
not vectors from a standards body.
