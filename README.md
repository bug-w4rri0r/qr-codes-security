# Secure QR Codes with Ed25519 Signatures and CBOR Certificates (v2)

Reference implementation for the paper
**"Secure QR Codes: Authenticity Verification via EdDSA Signatures and CBOR Certificates"**
(W. Jonderko, W. Wodo, Wrocław University of Science and Technology).

QR codes carry no proof of who created them, which enables QR phishing ("quishing") and
stickers placed over genuine codes on parking meters or charging stations. This toolkit signs
the QR content with **Ed25519**, packs it with an optional lightweight **CBOR** certificate,
compresses it with **ZLIB** and stores it as **Base64** text. Any phone camera can still read the
code, while a verifying reader checks the issuer offline.

Two trust models (the paper's "Dual-Mode PKI"):

| Mode | Who signs the payload | What the QR code contains | Paper |
|---|---|---|---|
| A – Root-Only (Direct Trust) | Root CA | `{payload, payload_sig}` | Scenario 1, QR version 8 |
| B – Root + App (Certificate Chain) | App (department / device) | `{payload, payload_sig, cert, cert_sig}`; the certificate is signed by the Root | Scenario 2, QR version 13 |

The reader only needs the **Root public key**.

## Contents

1. [Requirements](#1-requirements)
2. [Get the code](#2-get-the-code)
3. [Set up the Python environment](#3-set-up-the-python-environment)
4. [Check that everything works (5 minutes)](#4-check-that-everything-works-5-minutes)
5. [How the PKI files fit together](#5-how-the-pki-files-fit-together)
6. [Scenario 1 – Root-Only, step by step](#6-scenario-1--root-only-step-by-step)
7. [Scenario 2 – Root + App certificate chain, step by step](#7-scenario-2--root--app-certificate-chain-step-by-step)
8. [Examples: your own codes and options](#8-examples-your-own-codes-and-options)
9. [Debug mode](#9-debug-mode)
10. [End-to-end pipeline: X codes with a full report](#10-end-to-end-pipeline-x-codes-with-a-full-report)
11. [Benchmarks](#11-benchmarks)
12. [Tests](#12-tests)
13. [Troubleshooting](#13-troubleshooting)
14. [Command cheat sheet](#14-command-cheat-sheet)
15. [What changed in v2](#15-what-changed-in-v2)
16. [Data format](#16-data-format-v2)
17. [Limitations](#17-limitations)
18. [Repository structure](#18-repository-structure)

---

## 1. Requirements

| Item | Version / note |
|---|---|
| Python | **3.11 or newer** (tested with 3.14.0) |
| Git | any recent version (or download the branch as a ZIP from GitHub) |
| Python packages | `cbor2`, `cryptography`, `segno`, `opencv-python`, `numpy` – installed from `requirements.txt`, ready-made wheels, no compiler needed |
| OS | tested on Windows 11 (PowerShell); the Linux/macOS commands below are the standard equivalents |

Check Python:

```powershell
py --version          # Windows (Python launcher)
```
```bash
python3 --version     # Linux / macOS
```

---

## 2. Get the code

```bash
git clone https://github.com/bug-w4rri0r/qr-codes-security.git
```
```bash
cd qr-codes-security
```
```bash
git switch v2.0.0
```

All later commands are run from this repository folder.

| Branch | Content |
|---|---|
| `v2.0.0` | this version: paper-aligned toolchain, tests, benchmarks, reproduction script |
| `v1.0.0` | the original v1 code (snapshot of `main` before v2), used for the figures in the paper |

---

## 3. Set up the Python environment

A virtual environment keeps the pinned package versions separate from the rest of your system.

### Windows – PowerShell

```powershell
py -m venv .venv
```
```powershell
.\.venv\Scripts\Activate.ps1
```
If PowerShell answers *"running scripts is disabled on this system"*, allow scripts for the current
window only and activate again:
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```
```powershell
.\.venv\Scripts\Activate.ps1
```

### Windows – Command Prompt (cmd)

```bat
py -m venv .venv
```
```bat
.venv\Scripts\activate.bat
```

### Linux / macOS

```bash
python3 -m venv .venv
```
```bash
source .venv/bin/activate
```

### Install the packages (all systems, environment activated)

The prompt now starts with `(.venv)`, and `python` points to the environment on every system.

```bash
python -m pip install -r requirements.txt
```

Check the installation:

```bash
python -c "import cbor2, cryptography, segno, cv2, numpy; print('Environment OK:', cryptography.__version__, segno.__version__, cv2.__version__, numpy.__version__)"
```
```
Environment OK: 46.0.3 1.6.6 4.14.0 2.3.5
```

On a headless Linux server `import cv2` may fail with `libGL.so.1: cannot open shared object file`;
install the system library (`sudo apt install libgl1 libglib2.0-0` on Debian/Ubuntu).

To leave the environment later: `deactivate`. To use it again, run only the activation command.

### Optional: install as a package

The scripts in the repository work without installation. To get the tools as commands available
from any folder, install the package into the environment:

```bash
python -m pip install .
```

| Script in the repository | Installed command |
|---|---|
| `python qr-create.py` | `secureqr-create` |
| `python qr-read.py` | `secureqr-read` |
| `python cert_gen/gen_ed_keys.py` | `secureqr-keygen` |
| `python cert_gen/create_cose_cert.py` | `secureqr-issue-cert` |
| `python cert_gen/show_cert.py` | `secureqr-show-cert` |

Both forms take the same options. This README uses the script form, as in the paper.

---

## 4. Check that everything works (5 minutes)

Three commands verify the whole toolchain. Each must end with the line shown.

**1. Unit and command-line tests** (35 tests, about 20 s):
```bash
python -m unittest discover -s tests
```
```
Ran 35 tests in 18.991s
OK
```

**2. Reproduce the two scenarios of the paper** (fresh keys in a temporary folder):
```bash
python reproduce_paper.py
```
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
 Scenario 2 (Root + App)  Encoded Size             314         314   match
 Scenario 2 (Root + App)  Verification         SUCCESS     SUCCESS   match

RESULT: ALL VALUES MATCH THE PAPER
```
Keys and signatures are random, so the size after ZLIB ("Encoded Size") can differ by a byte or
two between runs; everything else is deterministic. `--workdir paper_run` keeps the keys and images.

**3. End-to-end run with attack cases**:
```bash
python scripts/e2e_pipeline.py --count 10 --negative
```
```
 Positive cases: 10/10 verified and matched
 Negative cases: 5/5 rejected as expected
```

If all three pass, the installation is correct. Sections 6–7 walk through the same steps manually.

---

## 5. How the PKI files fit together

```
 Root CA key pair                       App key pair (Scenario 2 only)
 certs_vault/PWr-Campus_priv.pem  ──┐   certs_vault/app_priv.pem ──────────┐
 (SECRET, signs certificates and    │   (SECRET, signs the QR payloads)    │
  Root-Only QR codes)               │                                      │
                                    ├─ create_cose_cert.py ──> certs_vault/cert_W4N_K34.cbor
 certs_vault/PWr-Campus_pub.pem     │   (public: iss, sub, alg, App public key, nbf, exp + Root signature)
   └─ copy to trusted_roots/ ───────┘                                      │
      (the reader trusts only this)            qr-create.py ──> test_qr_images/*.png
```

| File | Secret? | Created by | Used by |
|---|---|---|---|
| `certs_vault/<Root>_priv.pem` | **yes** – keep offline; whoever has it can issue certificates | `gen_ed_keys.py --root-only` | `create_cose_cert.py`, `qr-create.py --root-priv` |
| `certs_vault/<Root>_pub.pem` | no | `gen_ed_keys.py` | copied to `trusted_roots/` |
| `trusted_roots/<Root>_pub.pem` | no | you (copy) | `qr-read.py --trusted-dir`, `show_cert.py --root-pub` |
| `certs_vault/<App>_priv.pem` | **yes** – the signing key of one device / department | `gen_ed_keys.py --app-only` | `qr-create.py --app-priv` |
| `certs_vault/<App>_pub.pem` | no | `gen_ed_keys.py` | `create_cose_cert.py --pub` |
| `certs_vault/cert_*.cbor` | no (it is embedded in every QR code) | `create_cose_cert.py` | `qr-create.py --cert-cbor` |
| `test_qr_images/*.png` | no | `qr-create.py` | `qr-read.py --image` |

Rules:
- `trusted_roots/` holds **only Root public keys**. App keys never go there; they are trusted only
  through a certificate signed by a Root.
- `certs_vault/`, `*.pem`, `*.cbor` and `*.png` are excluded by `.gitignore` – keys are never committed.
- Certificate dates: `YYYY-MM-DD` (UTC). `--not-after 2030-12-31` is valid through the end of that day.
  `--not-after` is mandatory, `--not-before` optional.
- Generating a new Root key invalidates all certificates and Root-Only codes issued with the old one:
  re-issue the certificates and copy the new public key to `trusted_roots/`.
- Existing keys are never overwritten; add `--force` only if you really want to replace them.

---

## 6. Scenario 1 – Root-Only, step by step

The Root CA (e.g. the campus) signs the QR code directly.

**Step 1 – Root CA key pair**
```bash
python cert_gen/gen_ed_keys.py --root-name "PWr-Campus" --root-only --out-dir ./certs_vault/
```
```
Generating Root CA key pair (PWr-Campus)...
Saved PWr-Campus_priv.pem (unencrypted) and PWr-Campus_pub.pem
Key generation completed successfully!
```

**Step 2 – trust the Root public key**
```powershell
Copy-Item .\certs_vault\PWr-Campus_pub.pem .\trusted_roots\        # Windows PowerShell
```
```bash
cp ./certs_vault/PWr-Campus_pub.pem ./trusted_roots/               # Linux / macOS / Git Bash
```

**Step 3 – create the QR code**
```bash
python qr-create.py --payload "Welcome to the PWrcampus (Direct Mode)!" --root-priv ./certs_vault/PWr-Campus_priv.pem --out ./test_qr_images/qr_pwr_campus_direct
```
```
=================================================================
 SUCCESS - QR CODE GENERATED
=================================================================
 PKI Mode:          Root-Only (Direct Trust)
 Output File:       test_qr_images/qr_pwr_campus_direct.png
 Payload:           "Welcome to the PWrcampus (Direct Mode)!" (39 bytes, UTF-8 text)
-----------------------------------------------------------------
 QR Version:        8 (Max limit: 26)
 Error Correction:  L
 Encoding:          Base64 (Safe for Cameras)
 Compression:       YES (ZLIB)
 CBOR Size:         128 bytes (before compression)
 Encoded Size:      135 bytes (after compression, before Base64)
 QR Text Length:    180 chars (Base64)
 QR Size:           49x49 modules
=================================================================
```

**Step 4 – read and verify**
```bash
python qr-read.py --image ./test_qr_images/qr_pwr_campus_direct.png --trusted-dir ./trusted_roots/
```
```
[Direct Trust Details - Mode: Root-Only (Direct Trust)]
   Payload Size:          39 bytes
   Payload Signature:     64 bytes (Ed25519)

1. Payload signature (Root)
   [OK]
--------------------------------------------------
SUCCESS: DATA VERIFIED AND SECURE

==============================
      PAYLOAD CONTENT
==============================
Welcome to the PWrcampus (Direct Mode)!
==============================

 READING SUMMARY
 PKI Mode:          Root-Only (Direct Trust)
 Verification:      VERIFIED
 Payload:           "Welcome to the PWrcampus (Direct Mode)!" (39 bytes, UTF-8 text)
 QR Version:        8 (Estimated)
 CBOR Size:         128 bytes (decompressed container)
```

---

## 7. Scenario 2 – Root + App certificate chain, step by step

The Root CA issues a certificate to a department or device (e.g. laboratory W4N-K34), which then
signs its own QR codes. Requires the Root keys from Scenario 1.

**Step 1 – App key pair**
```bash
python cert_gen/gen_ed_keys.py --app-only --out-dir ./certs_vault/
```
```
Generating application key pair (app)...
Saved app_priv.pem (unencrypted) and app_pub.pem
```
(`--app-name "Parking-Meter-01"` gives the files a different name.)

**Step 2 – the Root issues the certificate**
```bash
python cert_gen/create_cose_cert.py --root-priv ./certs_vault/PWr-Campus_priv.pem --iss "PWr-Campus" --sub "W4N-K34" --pub ./certs_vault/app_pub.pem --not-before "2025-10-01" --not-after "2030-12-31" --out ./certs_vault/cert_W4N_K34.cbor
```
```
Certificate generated successfully!
  File: certs_vault/cert_W4N_K34.cbor (189 bytes)
  Issuer: PWr-Campus
  Subject: W4N-K34
  Valid From (nbf): 2025-10-01
  Expires (exp): 2030-12-31
```

**Step 3 – inspect the certificate (optional)**
```bash
python cert_gen/show_cert.py --cert ./certs_vault/cert_W4N_K34.cbor --root-pub ./trusted_roots/
```
```
Certificate file:  certs_vault/cert_W4N_K34.cbor (189 bytes)
  iss              PWr-Campus
  sub              W4N-K34
  alg              Ed25519
  nbf              2025-10-01
  exp              2030-12-31
  pub              413037f7e6b179cd885d2f023ed00bfc718ac10ec7c6dbcbb762f148caf97b2f (32 bytes)
  cert_sig         b6cb6b197bd4f2b9c2597ad5259e2b05... (64 bytes)

Root signature:    VALID
Validity window:   valid now
```

**Step 4 – create the QR code (signed by the App, certificate embedded)**
```bash
python qr-create.py --payload "Access to laboratory W4N-K34 granted." --app-priv ./certs_vault/app_priv.pem --cert-cbor ./certs_vault/cert_W4N_K34.cbor --out ./test_qr_images/qr_w4n_k34_chain
```
```
 PKI Mode:          Root + App (Certificate Chain)
 Output File:       test_qr_images/qr_w4n_k34_chain.png
 Payload:           "Access to laboratory W4N-K34 granted." (37 bytes, UTF-8 text)
 Certificate:       iss=PWr-Campus sub=W4N-K34 nbf=2025-10-01 exp=2030-12-31
-----------------------------------------------------------------
 QR Version:        13 (Max limit: 26)
 Error Correction:  L
 CBOR Size:         314 bytes (before compression)
 Encoded Size:      314 bytes (after compression, before Base64)
 QR Text Length:    420 chars (Base64)
 QR Size:           69x69 modules
```

**Step 5 – read and verify the whole chain** (`--require-chain` rejects Root-Only codes)
```bash
python qr-read.py --image ./test_qr_images/qr_w4n_k34_chain.png --trusted-dir ./trusted_roots/ --require-chain
```
```
[Certificate & Authorization Details - Mode: Root + App (Certificate Chain)]
   Issuer (iss):          PWr-Campus
   Subject (sub):         W4N-K34
   Valid From (nbf):      2025-10-01
   Expires (exp):         2030-12-31

1. Certificate signature (Root)
   [OK]
2. Algorithm is Ed25519
   [OK]
3. Validity window (nbf/exp)
   [OK]
4. Payload signature (App key from certificate)
   [OK]
--------------------------------------------------
SUCCESS: DATA VERIFIED AND SECURE

Access to laboratory W4N-K34 granted.
Issued to (Subject): W4N-K34
```

---

## 8. Examples: your own codes and options

All examples assume the keys from sections 6–7.

**Your own text or URL**
```bash
python qr-create.py --payload "https://wroclaw.pl/parking/strefa-A/12" --root-priv ./certs_vault/PWr-Campus_priv.pem --out ./test_qr_images/parking
```
```bash
python qr-read.py --image ./test_qr_images/parking.png --trusted-dir ./trusted_roots/
```

**Payload from a file** (any bytes; text is shown as text, binary as hex)
```bash
python qr-create.py --payload ./examples/payload.txt --file --root-priv ./certs_vault/PWr-Campus_priv.pem --out ./test_qr_images/from_file
```

**More robust code** (error correction at least Q; larger code, survives more damage)
```bash
python qr-create.py --payload "https://wroclaw.pl/parking/strefa-A/12" --root-priv ./certs_vault/PWr-Campus_priv.pem --out ./test_qr_images/parking_q --min-ecc Q
```
```
 QR Version:        12 (Max limit: 26)
 Error Correction:  Q
```

**Compression only when it helps** (default `always`, as in the paper)
```bash
python qr-create.py --payload "Short" --root-priv ./certs_vault/PWr-Campus_priv.pem --out ./test_qr_images/short --compress auto
```

**Several Roots** – put each Root public key into `trusted_roots/`; the reader accepts a code
signed by any of them (`Loaded 2 trusted root key(s).`).

**Encrypted private keys** – set a passphrase before generating the keys and keep it set when
using them:
```powershell
$env:SQR_KEY_PASSPHRASE = "your-passphrase"        # Windows PowerShell
```
```bash
export SQR_KEY_PASSPHRASE="your-passphrase"        # Linux / macOS
```
```bash
python cert_gen/gen_ed_keys.py --root-name "Enc-Root" --root-only --out-dir ./certs_vault/
```
```
Saved Enc-Root_priv.pem (encrypted) and Enc-Root_pub.pem
```

**Use the result in a script** – `qr-read.py` returns `0` = verified, `2` = verification failed,
`1` = input or usage error:
```powershell
python qr-read.py --image ./test_qr_images/parking.png --trusted-dir ./trusted_roots/ > $null; echo $LASTEXITCODE
```
```bash
python qr-read.py --image ./test_qr_images/parking.png --trusted-dir ./trusted_roots/ > /dev/null; echo $?
```

**Look at a rejected payload anyway** (printed with an UNTRUSTED label)
```bash
python qr-read.py --image ./test_qr_images/parking.png --trusted-dir ./trusted_roots/ --require-chain --show-untrusted
```

**Codes made with the v1 tools** (e.g. the figures in the paper) – v2 rejects them by design;
verify them with v1 rules:
```bash
python qr-read.py --image <v1_image.png> --trusted-dir ./trusted_roots/ --legacy-v1
```

### All options

| Tool | Option | Effect |
|---|---|---|
| `qr-create.py` | `--payload TEXT` / `--file` | payload text, or a file path with `--file` |
| | `--root-priv KEY` / `--app-priv KEY --cert-cbor CERT` | Root-Only or Root + App mode |
| | `--out BASE` | output file name without `.png` (folders are created) |
| | `--min-ecc L\|M\|Q\|H` | lowest error correction level (default L = smallest code, as in the paper) |
| | `--compress always\|auto\|never`, `--no-compress` | ZLIB use (default always, as in the paper) |
| | `--max-version N` | largest QR version allowed (default 26) |
| | `--debug` | full byte dumps of every stage |
| `qr-read.py` | `--image PNG`, `--trusted-dir DIR_or_PEM` | image and trust store |
| | `--require-chain` | accept only Root + App codes |
| | `--legacy-v1` | verify codes made by the v1 tools |
| | `--show-untrusted` | print the payload even if verification failed |
| | `--debug` | full byte dumps of every stage |
| `gen_ed_keys.py` | `--root-name`, `--app-name`, `--root-only`, `--app-only`, `--out-dir`, `--force` | key pairs |
| `create_cose_cert.py` | `--root-priv`, `--iss`, `--sub`, `--pub`, `--not-before`, `--not-after`, `--out` | certificate |
| `show_cert.py` | `--cert`, `--root-pub` | show and check a certificate |

---

## 9. Debug mode

Add `--debug` to `qr-create.py` or `qr-read.py` to see every stage in full, without truncation:

| `qr-create.py --debug` | `qr-read.py --debug` |
|---|---|
| Step 0 input payload (hex) | Step 1 raw QR text (Base64) |
| certificate: signed bytes and `cert_sig` (Root+App) | Step 2 decoded Base64 (hex) |
| Step 1 signed bytes (context ‖ payload) and `payload_sig` | Step 3 ZLIB-decompressed CBOR (hex) and compression ratio |
| CBOR container field by field | CBOR container field by field (payload marked *not verified yet*) |
| Step 2 raw CBOR (hex) | bytes checked against `cert_sig` and `payload_sig` |
| Step 3 ZLIB output (hex) and compression ratio | trusted Root key fingerprints |
| Step 4 Base64 text stored in the QR code | |

```bash
python qr-create.py --payload "Welcome to the PWrcampus (Direct Mode)!" --root-priv ./certs_vault/PWr-Campus_priv.pem --out ./test_qr_images/qr_pwr_campus_direct --debug
```
```bash
python qr-read.py --image ./test_qr_images/qr_w4n_k34_chain.png --trusted-dir ./trusted_roots/ --debug
```
```
[DEBUG] --- Step 2: Decoded Base64 (binary) ---
 Size: 314 bytes
 Hex: 78 da ...
[DEBUG] --- CBOR container structure ---
 payload      bstr[37]  "Access to laboratory W4N-K34 granted." (37 bytes, UTF-8 text)
 payload_sig  bstr[64]  ...
 cert         map
   iss        'PWr-Campus'
   sub        'W4N-K34'
   alg        'Ed25519'
   pub        bstr[32]  ...
   nbf        '2025-10-01'
   exp        '2030-12-31'
 cert_sig     bstr[64]  ...
 (payload above is NOT verified yet)
[DEBUG] --- Certificate: bytes checked against cert_sig (context || deterministic CBOR(cert)) ---
[DEBUG] --- Payload: bytes checked against payload_sig (context || payload) ---
```

Without `--debug` both tools still print the payload (text and size), the certificate (issuer,
subject, validity) and all sizes in their summary.

---

## 10. End-to-end pipeline: X codes with a full report

`scripts/e2e_pipeline.py` builds a fresh PKI, generates the codes with `qr-create.py`, reads
every image with `qr-read.py` and reports for each code what was **created** (payload, image file,
QR version and size, ECC level, CBOR → ZLIB → Base64 sizes) and what was **read** (PKI mode,
certificate, each verification step, decoded payload, match, exit code), then a summary table.

**10 random ticket URLs, keep images and report:**
```bash
python scripts/e2e_pipeline.py --count 10 --workdir e2e_run
```

**Your own payloads** – a text file with one payload per line, e.g. the provided
[`examples/payloads.txt`](examples/payloads.txt):
```
https://wroclaw.pl/parking/strefa-A/12
Bilet nr 2026-000123
Access to laboratory W4N-K34 granted.
...
```
```bash
python scripts/e2e_pipeline.py --payloads examples/payloads.txt --negative --workdir e2e_run
```
```
[CREATE 01] OK  test_qr_images/case_01.png
            payload: "https://wroclaw.pl/parking/strefa-A/12" (38 B)
            QR v15 (77x77 modules), ECC L, CBOR 339 B -> ZLIB 344 B -> Base64 460 chars
[READ   01] VERIFIED (exit 0, 2146 ms)  mode: Root + App (Certificate Chain)
            certificate: iss=Global_Mobility_Root sub=PL_WRO_Transit_API nbf=2025-10-01 exp=2030-12-31
            check  Certificate signature (Root): OK
            check  Algorithm is Ed25519: OK
            check  Validity window (nbf/exp): OK
            check  Payload signature (App key from certificate): OK
            decoded: "https://wroclaw.pl/parking/strefa-A/12"
            payload match: YES
[NEG 3] REJECTED as expected  (exit 2)
        Expired certificate (valid 2020-01-01 .. 2021-12-31)
        reason: Certificate has EXPIRED (exp 2021-12-31)
 SUMMARY
  #  payload                                     B   QR ECC  CBOR   B64  read      match
  1  https://wroclaw.pl/parking/strefa-A/12      38  v15   L   339   460  VERIFIED  YES
  2  Bilet nr 2026-000123                        20  v14   L   317   428  VERIFIED  YES
  3  Access to laboratory W4N-K34 granted.       37  v14   L   335   452  VERIFIED  YES
 Positive cases: 3/3 verified and matched
 Negative cases: 5/5 rejected as expected
 Images:  e2e_run/test_qr_images
 Report:  e2e_run/report.json
```

| Option | Effect |
|---|---|
| `--count N` | N random ~150-byte ticket URLs (default 10) |
| `--payloads FILE` | your own payloads, one per line (UTF-8, a BOM is ignored) |
| `--mode root` / `--mode chain` | Root-Only or Root + App (default chain) |
| `--min-ecc Q` | higher error correction level |
| `--negative` | five attack cases that must be rejected: untrusted Root, forged certificate, expired certificate, Root-Only code where a chain is required, wrong trust store |
| `--workdir DIR` | keep keys, images (`DIR/test_qr_images/case_NN.png`) and `DIR/report.json` |
| `--debug` | print the full output of every tool call, including the `--debug` byte dumps |

---

## 11. Benchmarks

Paper table "System performance benchmark":

```bash
python benchmarks/benchmark_crypto.py --iterations 1000 --repeats 5
```
```bash
python benchmarks/benchmark_pipeline.py --iterations 1000
```
```bash
python benchmarks/benchmark_pipeline.py --iterations 1000 --mode chain
```

Each run prints the Python and library versions and the CPU; `--json results.json` saves the
results. `benchmark_pipeline.py` uses the same functions as the CLI tools, in-process (without
interpreter start-up). Defaults follow the paper run: Root-Only, ECC level H, 3 px per module.

| Stage | Paper | v2 run (Windows 11, Python 3.14.0, AMD laptop CPU, OpenCV 4.12) |
|---|---|---|
| Raw Ed25519 signing | 0.06 ms, 16,463 ops/s | 0.057 ms, 17,407 ops/s |
| Raw Ed25519 verification | 0.17 ms, 5,994 ops/s | 0.163 ms, 6,144 ops/s |
| Full QR generation (sign + CBOR + ZLIB + Base64 + QR + PNG) | 42.46 ms | 42.18 ms |
| Full QR verification (OpenCV + Base64 + ZLIB + CBOR + signature) | 24.07 ms | 25.98 ms |

Timings depend on the machine and its load; run each benchmark a few times and compare medians.
The scripts that produced the numbers in the paper are archived unchanged in
[`benchmarks/paper_v1/`](benchmarks/paper_v1/README.md).

---

## 12. Tests

```bash
python -m unittest discover -s tests -v
```

35 tests, standard library only: valid codes in both modes; tampered payloads and certificates;
expired and not-yet-valid certificates; missing or malformed dates; wrong algorithm; downgrade
attempts and signature reuse across contexts; malformed CBOR, invalid Base64 and a ZLIB
decompression bomb; deterministic certificate encoding; the container sizes from the paper; v1
compatibility; end-to-end command-line runs with real PNG files and exit codes.

---

## 13. Troubleshooting

| Message | Cause | Fix |
|---|---|---|
| `'python' is not recognized` / `command not found` | environment not activated, or Python not on PATH | activate `.venv` (section 3); on Windows `py` works without activation |
| `running scripts is disabled on this system` | PowerShell execution policy | `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`, then activate again |
| `ModuleNotFoundError: No module named 'cbor2'` (or `cv2`) | packages installed outside the environment | activate `.venv` and run `python -m pip install -r requirements.txt` |
| `[ERROR] PWr-Campus_priv.pem or PWr-Campus_pub.pem already exists (use --force to overwrite).` | keys with this name exist | keep using them, choose another `--root-name`, or `--force` (old certificates become invalid) |
| `qr-create.py: error: --cert-cbor is required with --app-priv (Root+App mode)` | App mode without certificate | add `--cert-cbor ./certs_vault/<cert>.cbor` |
| `The App private key does not match the public key in the certificate` | wrong key or wrong certificate | use the `*_priv.pem` whose `*_pub.pem` was passed to `create_cose_cert.py --pub` |
| `Certificate signature INVALID (does not match any trusted root)` | `trusted_roots/` does not contain the Root that issued the certificate (e.g. Root keys regenerated) | copy the current `<Root>_pub.pem` to `trusted_roots/` or re-issue the certificate; check with `show_cert.py --root-pub` |
| `Payload signature INVALID (does not match any trusted root)` | Root-Only code from another Root, or a **v1** code | trust the right Root; for v1 codes use `--legacy-v1` |
| `Certificate has EXPIRED (exp …)` / `NOT YET valid (nbf …)` | outside the validity window | issue a new certificate with suitable `--not-before` / `--not-after` |
| `Certificate chain required (--require-chain), but the code is Root-Only` | Root-Only code with `--require-chain` | drop `--require-chain` if Root-Only codes are acceptable |
| `[ERROR] Invalid time value: '31/12/2030'` | wrong date format | use `YYYY-MM-DD` |
| `… is encrypted; set SQR_KEY_PASSPHRASE` | encrypted private key | set `SQR_KEY_PASSPHRASE` (section 8) |
| `[ERROR] Cannot read image` / `No QR code detected` | not an image, or the code is too small / damaged | use the PNG written by `qr-create.py` (8 px per module); OpenCV is unreliable below ~4 px per module for QR version ≥ 14 |
| `Data does not fit into a QR code of version <= 26` | payload too large | shorten the payload, lower `--min-ecc`, or raise `--max-version` |

---

## 14. Command cheat sheet

| Goal | Command |
|---|---|
| Install | `python -m pip install -r requirements.txt` |
| Check installation | `python -m unittest discover -s tests` |
| Reproduce the paper | `python reproduce_paper.py` |
| Root keys | `python cert_gen/gen_ed_keys.py --root-name "PWr-Campus" --root-only --out-dir ./certs_vault/` |
| App keys | `python cert_gen/gen_ed_keys.py --app-only --out-dir ./certs_vault/` |
| Certificate | `python cert_gen/create_cose_cert.py --root-priv ./certs_vault/PWr-Campus_priv.pem --iss "PWr-Campus" --sub "W4N-K34" --pub ./certs_vault/app_pub.pem --not-before "2025-10-01" --not-after "2030-12-31" --out ./certs_vault/cert_W4N_K34.cbor` |
| Show certificate | `python cert_gen/show_cert.py --cert ./certs_vault/cert_W4N_K34.cbor --root-pub ./trusted_roots/` |
| Root-Only QR | `python qr-create.py --payload "TEXT" --root-priv ./certs_vault/PWr-Campus_priv.pem --out ./test_qr_images/NAME` |
| Root + App QR | `python qr-create.py --payload "TEXT" --app-priv ./certs_vault/app_priv.pem --cert-cbor ./certs_vault/cert_W4N_K34.cbor --out ./test_qr_images/NAME` |
| Read QR | `python qr-read.py --image ./test_qr_images/NAME.png --trusted-dir ./trusted_roots/` |
| Debug | add `--debug` to `qr-create.py` / `qr-read.py` |
| X codes with report | `python scripts/e2e_pipeline.py --count 10 --negative --workdir e2e_run` |
| Benchmarks | `python benchmarks/benchmark_crypto.py`, `python benchmarks/benchmark_pipeline.py` |

---

## 15. What changed in v2

The QR content keeps the structure and the sizes reported in the paper. The changes close gaps
between the paper's threat model and the v1 code (details in [CHANGELOG.md](CHANGELOG.md)):

| Concern | v1 behaviour | v2 |
|---|---|---|
| Signature reuse / downgrade | the Root key signed certificates and Root-Only payloads the same way; an App key placed in `trusted_roots/` could validate a code with its certificate stripped | every signature covers a context string (`SecureQR/v2/root-payload`, `…/app-payload`, `…/cert`); a signature is valid only in its own role; `--require-chain`; only `*.pem` files are loaded from the trust store |
| Validity window | unparseable `nbf`/`exp` were silently accepted; certificates without `exp` never expired | fail-closed: `exp` is mandatory, dates must parse; a date-only `exp` is valid through the end of that day (UTC) |
| Metadata check | "Dates, Issuer" printed but issuer and algorithm not checked | `alg` must be `Ed25519`; `iss`/`sub` must be present |
| Certificate encoding | signature over re-encoded CBOR in insertion order | signature over deterministic CBOR (RFC 8949 §4.2), so any implementation recomputes the same bytes |
| Schema / DoS | no type checks; unbounded ZLIB decompression | strict schema validation before any cryptography; Base64 validated; decompression limited to 64 KiB |
| Untrusted data | interactive prompt could show an unverified payload | hidden by default; `--show-untrusted`; exit codes 0 / 2 / 1 |
| Size report | "Raw Data Size … (before Base64)" actually showed CBOR before compression | CBOR size, size after ZLIB and Base64 length reported separately |
| ECC level | always the smallest code (level L) | unchanged by default (paper), `--min-ecc` for Q/H |
| Compression | always on, even when it grows the data (128 → 135 B in Scenario 1) | unchanged by default (paper), `--compress auto` |
| Micro QR | `segno.make` could produce a Micro QR for tiny inputs | `segno.make_qr` (always a regular QR code) |
| Reading | classic OpenCV detector misses some dense codes (≈7% of version 13–14 codes in our tests) | falls back to `cv2.QRCodeDetectorAruco` |
| Keys | unencrypted, could be overwritten silently | optional encryption via `SQR_KEY_PASSPHRASE`; no overwrite without `--force`; App key must match the certificate |
| Debug / reporting | byte dumps only | full dumps incl. the exact signed bytes; payload and certificate in every summary; `show_cert.py`; per-code pipeline report |
| Reproducibility | no requirements file (ignored by `.gitignore`), output folder not created, README commands differed from the paper, no benchmark code | pinned `requirements.txt` (verified in a fresh environment), folders created automatically, paper-aligned commands, `reproduce_paper.py`, benchmarks, tests, CI on Linux and Windows |
| Project structure | flat scripts with copied helpers and `sys.path` changes | `secureqr` package with thin entry scripts (same commands as in the paper), `pyproject.toml` with console commands, `CITATION.cff` |

**Compatibility:** v1 codes (including the figures in the paper) fail under v2 rules by design.
They can still be verified with `qr-read.py --legacy-v1`. Certificates issued by the v1
`create_cose_cert.py` must be re-issued for v2.

---

## 16. Data format (v2)

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

## 17. Limitations

- **Revocation:** offline codes cannot be revoked before `exp`; the Hybrid Web PKI described in the
  paper (JWKS endpoints) is a proposal and is not implemented here.
- **Binary Mode:** the PoC stores Base64 text (about 33% overhead) for compatibility with camera
  apps and OpenCV; raw binary QR encoding is not implemented.
- **Compression:** ZLIB rarely helps here – signatures, keys and random tokens do not compress.
- **Keys:** private keys are plain PEM files unless `SQR_KEY_PASSPHRASE` is set; a real Root key
  belongs offline or in an HSM.
- **Image size:** OpenCV decoding is unreliable below about 4 px per module for QR versions ≥ 14;
  `qr-create.py` writes 8 px per module.
- **Semantic checks:** a valid signature proves who issued the code, not that the content is
  harmless (see the typosquatting discussion in the paper).

---

## 18. Repository structure

```text
.
├── secureqr/                    # the package: all logic lives here
│   ├── __init__.py              # version
│   ├── core.py                  # format, signing, decoding, verification
│   ├── debug.py                 # --debug output
│   └── cli/                     # command-line tools (each module has main())
│       ├── create.py  read.py   # QR generator / reader
│       ├── keygen.py            # Ed25519 key pairs
│       ├── issue_cert.py        # lightweight CBOR certificates
│       └── show_cert.py         # show and check a certificate
├── qr-create.py, qr-read.py     # entry scripts used in the paper (call secureqr.cli)
├── cert_gen/                    # entry scripts: gen_ed_keys.py, create_cose_cert.py, show_cert.py
├── reproduce_paper.py           # one-command reproduction of the paper's scenarios
├── scripts/e2e_pipeline.py      # X codes through the CLI with a full report
├── benchmarks/
│   ├── benchmark_crypto.py      # raw Ed25519 sign / verify
│   ├── benchmark_pipeline.py    # full generation / verification pipeline
│   ├── env_info.py              # environment report
│   └── paper_v1/                # scripts used for the paper, archived unchanged
├── tests/test_secure_qr.py      # unittest suite (35 tests)
├── examples/                    # sample payloads, unsigned plain-QR baseline (plain_qr/)
├── trusted_roots/               # reader trust store: Root public keys only
├── certs_vault/                 # keys and certificates (created locally, never committed)
├── pyproject.toml               # package metadata, dependencies, console commands
├── requirements.txt             # exact versions for reproduction
├── .github/workflows/tests.yml  # CI: tests, reproduction, pipeline on Linux and Windows
├── CHANGELOG.md, CITATION.cff, LICENSE
```

Design rules: logic only in `secureqr/`; entry scripts contain no logic; tools, benchmarks and tests
use the same `secureqr.core` functions; keys and generated files never enter the repository.

---

## License and disclaimer

Released under the MIT License (see `LICENSE`). The software is a research proof of concept
provided "as is", without warranties; it should not be the sole security component of a
critical or safety-related system.
