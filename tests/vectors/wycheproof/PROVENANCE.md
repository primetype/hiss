# Wycheproof test vectors (vendored)

These JSON files are verbatim copies from Google's **Project Wycheproof**,
vendored so the test suite is hermetic and offline-reproducible.

- **Source:** <https://github.com/C2SP/wycheproof>
- **Pinned commit:** `6d7cccd0fcb1917368579adeeac10fe802f1b521`
- **Path in upstream:** `testvectors_v1/`
- **License:** Apache-2.0 (see `LICENSE` in this directory).

## Files

| File | Upstream path | Tests |
|------|---------------|-------|
| `ecdsa_secp256r1_sha256_test.json` | `testvectors_v1/ecdsa_secp256r1_sha256_test.json` | 484 (DER/ASN.1-encoded signatures) |
| `ecdh_secp256r1_ecpoint_test.json` | `testvectors_v1/ecdh_secp256r1_ecpoint_test.json` | 355 (raw SEC1 EC-point public keys) |
| `aes_gcm_test.json` | `testvectors_v1/aes_gcm_test.json` | 316 in the file (229 `valid`, 87 `invalid`); **66 run** — see below |

All three files are at the **same** pinned commit. To refresh, re-fetch the same
paths at a newer commit and update the pin above.

## AES-GCM: the applicable subset

`aes_gcm_test.json` (sha256
`985e5ecc172e181eaf49e89508b9470dcf478002eb7e8559c707eb42dc97dfe7`, 213,177
bytes) is the primitive-level leg of the `AesGcm` validation: it never touches
a handshake. What it pins is that `cryptoxide::aes_gcm::AesGcm256` is
AES-256-GCM, against a corpus written by neither cryptoxide nor hiss nor
`snow`. It runs as `src/noise/cipher/wycheproof.rs`.

Noise **§12.4** AESGCM is AES-**256** with a **96**-bit nonce and a **128**-bit
tag, so most of the file is out of scope:

| Dimension | File contains | Noise §12.4 needs | Filter |
|---|---|---|---|
| `keySize` | 128 → 108, **256 → 105**, 192 → 103 | 256 | keep 256 |
| `ivSize` | **96 → 197**, plus 0, 8, 16, 32, 48, 64, 80, 120, 128, 160, 256, 512, 1024, 2056 | 96 | keep 96 |
| `tagSize` | **128 — all 316 tests** | 128 | no-op |

**Applicable subset: 66 tests — 39 `valid`, 27 `invalid`** (measured, and
asserted by the test, which fails if the count moves). For each `valid`
vector, encryption must reproduce the recorded ciphertext **and** tag exactly
— pinning the tag matters, because a round-trip alone would pass under a
wrong-but-self-consistent GHASH — and decryption must verify and recover the
plaintext. For each `invalid` vector, decryption must report a mismatch.

The out-of-scope groups are dropped rather than run-and-ignored on purpose: an
unreplayed vector in a KAT directory is a claim with nothing behind it. The
same rule governs the `cacophony` subset next door.

**The gap this corpus does not close.** At this pin **every** vector in the
file has a 128-bit tag — there are no truncated-tag vectors at all — so
accepting a short tag, or comparing only a prefix, is *not* covered here. That
risk is carried by bespoke negative tests in `src/noise/cipher.rs`
(`truncated_tags_rejected`, `every_flipped_tag_bit_rejected`), which is why
they exist rather than being redundant with this file.
