# cert_gen – key and certificate tools

| Script | Purpose |
|---|---|
| `gen_ed_keys.py` | Ed25519 key pairs (`<name>_priv.pem`, `<name>_pub.pem`); never overwrites existing keys without `--force`; encrypts private keys if `SQR_KEY_PASSPHRASE` is set |
| `create_cose_cert.py` | lightweight CBOR certificate for an App key, signed by the Root (`--iss`, `--sub`, `--pub`, `--not-after` required) |

Both are run from the repository root. The complete, paper-aligned command sequence is in
the main [README](../README.md#step-by-step-the-two-scenarios-of-the-paper).
