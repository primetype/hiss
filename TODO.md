# TODO

Short-term direction, one line each. Nothing here is a commitment or a date, and
nothing here is needed to use what `hiss` ships today — see the
[README](README.md) for that.

## Providers

Beyond the software and Apple Secure Enclave backends that ship today. A backend
can carry the Noise channel only if it will hand back a raw Diffie–Hellman shared
secret; one that can only sign fits an identity layer around the channel instead.

- **Android Keystore / StrongBox** — can do DH.
- **Linux TPM2** — can do DH, policy permitting.
- **AWS KMS** — can do DH, via `DeriveSharedSecret`.
- **Windows CNG, Azure Key Vault, GCP KMS** — no raw ECDH, so identity role only.
- **PKCS#11 HSMs, YubiKey, Ledger** — no raw ECDH export; out of scope.

## Not planned

- **The `fallback` modifier**, and the compound protocols it enables (Noise Pipes,
  0-RTT-with-retry). Optional in the Noise spec, which presents it only as an
  illustrative building block, and unnecessary for the use cases `hiss` targets.
  `snow` omits it for the same reason.
- **Hashes beyond the specification's four.** BLAKE2b, BLAKE2s, SHA-256 and SHA-512
  all ship; SHA-3/SHAKE, KangarooTwelve, MarsupilamiFourteen and BLAKE3 are not
  planned. No Noise-level vectors exist for any of them, nothing deploys them, and
  the Noise wiki's unofficial list disclaims its own contents.
