Public fixtures for the v0 development key compiled into rustee-os (#6).

- `v0-dev.spki.der` — RSA-2048 SPKI (same bytes as `crates/rustee-os/dev-keys/v0-dev.spki.der`)
- `v0-dev-digest.sig` — RSASSA-PKCS1-v1_5 SHA-256 over the UTF-8 bytes `digest`

The matching private key stays in rustee-os and is not TCB.
