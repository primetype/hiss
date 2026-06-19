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

To refresh, re-fetch the same paths at a newer commit and update the pin above.
