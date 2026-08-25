v0 development TA signing key. Not a product ROT.

- `v0-dev.pem` — RSA-2048 private key for the TA signer (not in the TCB).
- `v0-dev.spki.der` — SPKI public key compiled into rustee-os as `V0_DEV_PUBKEY`.
- Envelope: SHA-256(uuid || ta_version_le || ELF), RSASSA-PKCS1-v1_5. Kernel verifies via CryptoProvider; it does not implement RSA.
