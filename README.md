# Secure QR Codes with Ed25519 Signatures and CBOR Certificates (v2)

Reference implementation for the paper
**"Secure QR Codes: Authenticity Verification via EdDSA Signatures and CBOR Certificates"**
(W. Jonderko, W. Wodo, Wrocław University of Science and Technology).

QR codes carry no proof of who created them, which enables QR phishing ("quishing") and
stickers placed over genuine codes on parking meters or charging stations. This toolkit signs
the QR content with **Ed25519**, packs it with an optional lightweight **CBOR** certificate,
compresses it with **ZLIB** and stores it as **Base64** text, so that any phone camera can still
read the code while a verifying reader can check the issuer offline.

Two trust models (the paper's "Dual-Mode PKI"):

| Mode | Who signs the payload | What the QR code contains | Paper |
|---|---|---|---|
| A – Root-Only (Direct Trust) | Root CA | `{payload, payload_sig}` | Scenario 1, QR version 8 |
| B – Root + App (Certificate Chain) | App (department / device) | `{payload, payload_sig, cert, cert_sig}`; the certificate is signed by the Root | Scenario 2, QR version 13 |

The reader only needs the **Root public key**.

---

## Quick start: reproduce the paper in one command

```bash
python -m venv .venv
```
```bash
.venv\Scripts\activate          # Windows   (Linux/macOS: source .venv/bin/activate)
```
```bash
pip install -r requirements.txt
```
```bash
python reproduce_paper.py
```

`reproduce_paper.py` creates fresh keys in a temporary directory, runs the real command-line
tools with the payloads, names and dates used in the paper and compares the results:

```
 Scenario                 Value                  Paper    This run   Result
 Scenario 1 (Root-Only)   QR Version                 8           8   match
 Scenario 1 (Root-Only)   Error Correction           L           L   match
 Scenario 1 (Root-Only)   Payload Size              39          39   match
 Scenario 1 (Root-Only)   CBOR Size                128         128   match
 Scenario 1 (Root-Only)   Encoded Size             135         134   match
 Scenario 1 (Root-Only)   Verification         SUCCESS     SUCCESS   match
 Scenario 2 (Root + App)  QR Version                13          13   match
 Scenario 2 (Root + App)  Error Correction           L           L   match
 Scenario 2 (Root + App)  Payload Size              37          37   match
 Scenario 2 (Root + App)  CBOR Size                314         314   match
 Scenario 2 (Root + App)  Encoded Size             314         313   match
 Scenario 2 (Root + App)  Verification         SUCCESS     SUCCESS   match
RESULT: ALL VALUES MATCH THE PAPER
```

Keys and signatures are random, so the size after ZLIB can differ by a byte or two between runs;
all other values are deterministic. Use `--workdir paper_run` to keep the keys and images.

On Windows `py` can be used instead of `python`.

---

## Step by step: the two scenarios of the paper

All commands are run from the repository root. Output folders (`certs_vault/`,
`test_qr_images/`) are created automatically; `trusted_roots/` is part of the repository.

### Scenario 1 – Root-Only (Direct Trust)

1. Root CA keys (creates `certs_vault/PWr-Campus_priv.pem` and `certs_vault/PWr-Campus_pub.pem`):
   ```bash
   python cert_gen/gen_ed_keys.py --root-name "PWr-Campus" --root-only --out-dir ./certs_vault/
   ```
2. Trust the Root public key (the reader trusts only Root keys):
   ```bash
   cp ./certs_vault/PWr-Campus_pub.pem ./trusted_roots/
   ```
   (Windows PowerShell: `Copy-Item .\certs_vault\PWr-Campus_pub.pem .\trusted_roots\`)
3. Create the QR code:
   ```bash
   python qr-create.py --payload "Welcome to the PWrcampus (Direct Mode)!" --root-priv ./certs_vault/PWr-Campus_priv.pem --out ./test_qr_images/qr_pwr_campus_direct
   ```
   ```
    PKI Mode:          Root-Only (Direct Trust)
    QR Version:        8 (Max limit: 26)
    Error Correction:  L
    Compression:       YES (ZLIB)
    CBOR Size:         128 bytes (before compression)
    Encoded Size:      134 bytes (after compression, before Base64)
    QR Text Length:    180 chars (Base64)
   ```
4. Read and verify:
   ```bash
   python qr-read.py --image ./test_qr_images/qr_pwr_campus_direct.png --trusted-dir ./trusted_roots/
   ```
   ```
   1. Payload signature (Root)
      [OK]
   SUCCESS: DATA VERIFIED AND SECURE
   Welcome to the PWrcampus (Direct Mode)!
   ```

### Scenario 2 – Root + App (Certificate Chain)

Requires the Root keys from Scenario 1.

1. App keys (creates `certs_vault/app_priv.pem` and `certs_vault/app_pub.pem`):
   ```bash
   python cert_gen/gen_ed_keys.py --app-only --out-dir ./certs_vault/
   ```
2. The Root issues a certificate to the App:
   ```bash
   python cert_gen/create_cose_cert.py --root-priv ./certs_vault/PWr-Campus_priv.pem --iss "PWr-Campus" --sub "W4N-K34" --pub ./certs_vault/app_pub.pem --not-before "2025-10-01" --not-after "2030-12-31" --out ./certs_vault/cert_W4N_K34.cbor
   ```
3. Create the QR code (signed by the App, certificate embedded):
   ```bash
   python qr-create.py --payload "Access to laboratory W4N-K34 granted." --app-priv ./certs_vault/app_priv.pem --cert-cbor ./certs_vault/cert_W4N_K34.cbor --out ./test_qr_images/qr_w4n_k34_chain
   ```
   ```
    PKI Mode:          Root + App (Certificate Chain)
    QR Version:        13 (Max limit: 26)
    Error Correction:  L
    CBOR Size:         314 bytes (before compression)
    QR Text Length:    420 chars (Base64)
   ```
4. Read and verify the whole chain (`--require-chain` rejects Root-Only codes):
   ```bash
   python qr-read.py --image ./test_qr_images/qr_w4n_k34_chain.png --trusted-dir ./trusted_roots/ --require-chain
   ```
   ```
   1. Certificate signature (Root)
      [OK]
   2. Algorithm is Ed25519
      [OK]
   3. Validity window (nbf/exp)
      [OK]
   4. Payload signature (App key from certificate)
      [OK]
   SUCCESS: DATA VERIFIED AND SECURE
   Access to laboratory W4N-K34 granted.
   ```

Add `--debug` to either tool to see the CBOR, ZLIB and Base64 data byte by byte.

### Useful options

| Tool | Option | Effect |
|---|---|---|
| `qr-create.py` | `--min-ecc Q` / `--min-ecc H` | force a higher error correction level (larger code, more robust); default `L` = smallest code, as in the paper |
| `qr-create.py` | `--compress auto` | use ZLIB only if it makes the data smaller (default `always`, as in the paper) |
| `qr-create.py` | `--max-version N` | largest QR version allowed (default 26) |
| `qr-read.py` | `--require-chain` | accept only Root + App codes |
| `qr-read.py` | `--legacy-v1` | verify codes made by the v1 tools (e.g. the figures in the paper) |
| `qr-read.py` | `--show-untrusted` | print the payload even if verification failed (marked UNTRUSTED) |

`qr-read.py` exit codes: `0` verified, `2` verification failed, `1` input or usage error.

---

## Benchmarks (paper, Table "System performance benchmark")

```bash
python benchmarks/benchmark_crypto.py --iterations 1000 --repeats 5
```
```bash
python benchmarks/benchmark_pipeline.py --iterations 1000
```
```bash
python benchmarks/benchmark_pipeline.py --iterations 1000 --mode chain
```

Every run prints the Python and library versions; `--json results.json` saves them.
`benchmark_pipeline.py` uses the same functions as the CLI tools (in-process, without interpreter
start-up). Defaults follow the paper run: Root-Only, ECC level H, 3 px per module.

| Stage | Paper | v2 run (Windows 11, Python 3.14.0, consumer laptop) |
|---|---|---|
| Raw Ed25519 signing | 0.06 ms, 16,463 ops/s | 0.057 ms, 17,407 ops/s |
| Raw Ed25519 verification | 0.17 ms, 5,994 ops/s | 0.163 ms, 6,144 ops/s |
| Full QR generation (sign + CBOR + ZLIB + Base64 + QR + PNG) | 42.46 ms | 42.18 ms |
| Full QR verification (OpenCV + Base64 + ZLIB + CBOR + signature) | 24.07 ms | 25.98 ms |

`benchmarks/e2e_cli_pipeline.py --count 10` is an end-to-end functional run of the Root + App chain
through the CLI tools with realistic ~150-byte ticket URLs.

The scripts that produced the numbers in the paper are archived unchanged in
[`benchmarks/paper_v1/`](benchmarks/paper_v1/README.md).

---

## Tests

```bash
python -m unittest discover -s tests -v
```

32 tests, standard library only: valid codes in both modes, tampered payloads and certificates,
expired and not-yet-valid certificates, missing or malformed dates, wrong algorithm, downgrade
attempts, signature reuse across contexts, malformed CBOR, invalid Base64, a ZLIB decompression
bomb, deterministic certificate encoding, the container sizes from the paper, v1 compatibility,
and end-to-end CLI runs with real PNG files.

---

## What changed in v2

The QR content keeps the structure and the sizes reported in the paper. The changes close gaps
between the paper's threat model and the v1 code:

| Concern | v1 behaviour | v2 |
|---|---|---|
| Signature reuse / downgrade | the Root key signed certificates and Root-Only payloads the same way; an App key placed in `trusted_roots/` could validate a code with its certificate stripped | every signature covers a context string (`SecureQR/v2/root-payload`, `…/app-payload`, `…/cert`); a signature is valid only in its own role; `--require-chain`; only `*.pem` files are loaded from the trust store |
| Validity window | unparseable `nbf`/`exp` were silently accepted; certificates without `exp` never expired | fail-closed: `exp` is mandatory, dates must parse; a date-only `exp` is valid through the end of that day (UTC) |
| Metadata check | "Dates, Issuer" printed but issuer and algorithm not checked | `alg` must be `Ed25519`; `iss`/`sub` must be present |
| Certificate encoding | signature over re-encoded CBOR in insertion order | signature over deterministic CBOR (RFC 8949 §4.2), so any implementation recomputes the same bytes |
| Schema / DoS | no type checks; unbounded ZLIB decompression | strict schema validation before any cryptography; Base64 validated; decompression limited to 64 KiB |
| Untrusted data | interactive prompt could show an unverified payload | hidden by default; `--show-untrusted`; exit codes for scripting |
| Size report | "Raw Data Size … (before Base64)" actually showed CBOR before compression | CBOR size, size after ZLIB and Base64 length reported separately |
| ECC level | always the smallest code (level L) | unchanged by default (paper), `--min-ecc` for Q/H |
| Compression | always on, even when it grows the data (128 → 135 B in Scenario 1) | unchanged by default (paper), `--compress auto` |
| Micro QR | `segno.make` could produce a Micro QR for tiny inputs | `segno.make_qr` (always a regular QR code) |
| Reading | classic OpenCV detector misses some dense codes (≈7% of version 13–14 codes in our tests) | falls back to `cv2.QRCodeDetectorAruco` |
| Keys | unencrypted, could be overwritten silently | optional encryption via `SQR_KEY_PASSPHRASE`; no overwrite without `--force`; App key must match the certificate |
| Reproducibility | no requirements file (ignored by `.gitignore`), output folder not created, README commands differed from the paper, no benchmark code | pinned `requirements.txt`, folders created automatically, paper-aligned commands, `reproduce_paper.py`, benchmarks, tests |

**Compatibility:** v1 codes (including the figures in the paper) fail under v2 rules by design.
They can still be verified with `qr-read.py --legacy-v1`. Certificates issued by the v1
`create_cose_cert.py` must be re-issued for v2.

---

## Data format (v2)

QR text = `Base64( ZLIB( CBOR(container) ) )`

```
container = {
  "payload":     bstr,                       ; the user data (UTF-8 text or binary)
  "payload_sig": bstr .size 64,              ; Ed25519 over context || payload
  ? "cert": {                                ; Mode B only
      "iss": tstr, "sub": tstr, "alg": "Ed25519",
      "pub": bstr .size 32,                  ; App public key
      ? "nbf": tstr / int,                   ; "YYYY-MM-DD", ISO 8601 or Unix time
      "exp": tstr / int
    },
  ? "cert_sig":  bstr .size 64               ; Root Ed25519 over "SecureQR/v2/cert\0" || deterministic CBOR(cert)
}
context = "SecureQR/v2/root-payload\0" (Mode A) or "SecureQR/v2/app-payload\0" (Mode B)
```

The design follows the EU Digital COVID Certificate pipeline (CBOR, EdDSA, ZLIB, Base64-style
text) and is **COSE-inspired**, but the container is not a COSE_Sign1 message.

---

## Limitations

- **Revocation:** offline codes cannot be revoked before `exp`; the Hybrid Web PKI described in the
  paper (JWKS endpoints) is a proposal and is not implemented here.
- **Binary Mode:** the PoC stores Base64 text (about 33% overhead) for compatibility with camera
  apps and OpenCV; raw binary QR encoding is not implemented.
- **Keys:** private keys are plain PEM files unless `SQR_KEY_PASSPHRASE` is set; a real Root key
  belongs offline or in an HSM.
- **Image size:** OpenCV decoding is unreliable below about 4 px per module for QR versions ≥ 14;
  `qr-create.py` writes 8 px per module.
- **Semantic checks:** a valid signature proves who issued the code, not that the content is
  harmless (see the typosquatting discussion in the paper).

---

## Repository structure

```text
.
├── qr-create.py              # generator (Root-Only / Root + App)
├── qr-read.py                # reader and verifier
├── sqr_core.py               # shared format, signing and verification code
├── reproduce_paper.py        # one-command reproduction of the paper's scenarios
├── requirements.txt          # pinned dependencies
├── cert_gen/
│   ├── gen_ed_keys.py        # Ed25519 key pairs
│   └── create_cose_cert.py   # lightweight CBOR certificates
├── benchmarks/
│   ├── benchmark_crypto.py   # raw Ed25519 sign / verify
│   ├── benchmark_pipeline.py # full generation / verification pipeline
│   ├── e2e_cli_pipeline.py   # end-to-end CLI run of the certificate chain
│   └── paper_v1/             # scripts used for the paper, unchanged
├── tests/test_secure_qr.py   # unittest suite
├── scanner/                  # minimal plain QR generator / OpenCV scanner (no cryptography)
├── trusted_roots/            # reader trust store: Root public keys only
└── certs_vault/              # keys and certificates (created locally, never committed)
```

---

## License and disclaimer

Released under the MIT License (see `LICENSE`). The software is a research proof of concept
provided "as is", without warranties; it should not be the sole security component of a
critical or safety-related system.
