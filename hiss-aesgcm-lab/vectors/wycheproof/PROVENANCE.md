# Wycheproof AES-GCM test vectors (vendored)

`aes_gcm_test.json` is a verbatim copy from Google's **Project Wycheproof**,
vendored so this lab's test suite is hermetic and offline-reproducible.

It is the **primitive-level** leg of the AES-GCM validation: it never touches
hiss, and it says nothing about the Noise framing. What it pins is that
cryptoxide's `AesGcm256` is AES-256-GCM, against a corpus written by neither
cryptoxide nor hiss nor `snow`.

## Source and pins

- **Source:** <https://github.com/C2SP/wycheproof>
- **Pinned commit:** `6d7cccd0fcb1917368579adeeac10fe802f1b521`
- **Path in upstream:** `testvectors_v1/aes_gcm_test.json`
- **This file's sha256:**
  `985e5ecc172e181eaf49e89508b9470dcf478002eb7e8559c707eb42dc97dfe7`
  (213,177 bytes, 316 tests)
- **Licence:** Apache-2.0 (see `LICENSE` in this directory).

The commit is **deliberately the same pin the main repo already uses**
(`tests/vectors/wycheproof/PROVENANCE.md`, which vendors the P-256 ECDSA and
ECDH files at that revision). The lab does not introduce a second Wycheproof
revision into the tree, so at exit the file can move across without a pin
reconciliation.

To refresh, re-fetch the same path at a newer commit and update the pin and
the hash above:

```
curl -sSL -o aes_gcm_test.json \
  https://raw.githubusercontent.com/C2SP/wycheproof/<commit>/testvectors_v1/aes_gcm_test.json
```

## What the file contains, and what the lab runs

`algorithm: AES-GCM`, `schema: aead_test_schema_v1.json`, `numberOfTests: 316`
(229 `valid`, 87 `invalid`). Noise **§12.4** AESGCM is AES-**256** with a
**96**-bit nonce and a **128**-bit tag, so most of the file is out of scope:

| Dimension | File contains | Noise §12.4 needs | Filter |
|---|---|---|---|
| `keySize` | 128 → 108, **256 → 105**, 192 → 103 | 256 | keep 256 |
| `ivSize` | **96 → 197**, plus 0, 8, 16, 32, 48, 64, 80, 120, 128, 160, 256, 512, 1024, 2056 | 96 | keep 96 |
| `tagSize` | **128 — all 316 tests** | 128 | no-op |

**Applicable subset: 66 tests — 39 `valid`, 27 `invalid`** (measured, and
asserted by the test, which fails if the count moves).

### The gap this corpus does not close

Note the `tagSize` row: at this pin **every** vector in `aes_gcm_test.json` has
a 128-bit tag. There are **no truncated-tag vectors at all**, so tag truncation
— accepting a short tag, or comparing only a prefix — is *not* covered here.
That risk is carried by bespoke negative tests in `src/lib.rs`
(`truncated_tags_rejected`, `every_flipped_tag_bit_rejected`), which is why
they exist rather than being redundant with this file.

The out-of-scope rows are dropped rather than run-and-ignored on purpose: an
unreplayed vector in a KAT directory is a claim with nothing behind it. The
same rule governs the cacophony subset next door.

## What the test asserts

For each `valid` vector: encryption reproduces the recorded ciphertext **and**
tag exactly, and decryption then verifies and recovers the plaintext. Pinning
the tag matters — a round-trip alone would pass under a wrong-but-consistent
GHASH.

For each `invalid` vector: decryption returns `MisMatch`.
