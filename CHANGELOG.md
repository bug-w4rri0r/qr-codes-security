# Changelog

## v2.0 (2026-11-04)

Aligned with the paper "Secure QR Codes: Authenticity Verification via EdDSA Signatures and CBOR
Certificates"; closes gaps between its threat model and the v1 code. The QR container keeps the
v1 structure and sizes (Scenario 1: QR v8, CBOR 128 B; Scenario 2: QR v13, CBOR 314 B).

### Security
- Domain-separated Ed25519 signatures for Root payloads, App payloads and certificates
  (prevents signature reuse across roles and the certificate-stripping downgrade).
- Certificates signed over deterministic CBOR (RFC 8949 §4.2).
- Fail-closed validity window: mandatory, parseable `exp`; `nbf` optional; `alg` must be Ed25519.
- Strict schema validation before cryptography; validated Base64; bounded ZLIB decompression.
- Trust store loads only `*.pem` files; `--require-chain` option.
- Unverified payloads are not shown unless `--show-untrusted`; exit codes 0 / 2 / 1.
- Optional private-key encryption (`SQR_KEY_PASSPHRASE`); keys are not overwritten without `--force`;
  `qr-create.py` checks that the App key matches the certificate.

### Behaviour
- Separate size report: CBOR, after ZLIB, Base64 length (v1 printed the CBOR size as
  "Raw Data Size (before Base64)").
- `--min-ecc`, `--compress {always,auto,never}`, `--max-version`; defaults unchanged.
- `segno.make_qr` instead of `segno.make` (never a Micro QR).
- OpenCV Aruco QR detector as fallback.
- Output directories are created automatically.
- `--legacy-v1` in `qr-read.py` verifies codes made by v1 tools.

### Reproducibility
- `reproduce_paper.py`: runs both scenarios of the paper and compares the results.
- `benchmarks/`: raw Ed25519 and full-pipeline benchmarks (perf_counter, environment report,
  JSON output), end-to-end CLI run; original paper scripts archived in `benchmarks/paper_v1/`.
- `tests/`: 32 unittest cases (standard library only).
- `requirements.txt` with pinned versions; `.gitignore` no longer hides it.
- README commands, payloads and dates match the paper; corrected file names and expected output.

### Incompatible
- v2 readers reject v1 codes unless `--legacy-v1`; v1 certificates must be re-issued.
- `create_cose_cert.py` now requires `--iss` and `--not-after`.
