# qr-codes-security
Secure CBOR QR codes with Ed25519 signatures. Tools for generating, signing, scanning, and verifying compressed CBOR-based QR payloads with certificate validation against trusted roots. Suitable for secure documents, tickets, and offline verifiable credentials.


# Secure CBOR QR Codes with Ed25519 Signatures

This repository contains a complete toolkit for generating, signing, encoding, scanning, and verifying secure QR codes based on CBOR data structures and Ed25519 cryptography.

It provides:

- 🔐 **Ed25519 digital signatures** for payload integrity  
- 🧾 **CBOR** (Concise Binary Object Representation) for compact structured data  
- 🗜️ Optional **zlib compression** for smaller QR codes  
- 📦 COSE-like **certificate structure** with `nbf` (not before) and `exp` (expiry)  
- 📤 **QR generation** (PNG + byte-perfect `.bin` output)  
- 📥 **QR scanning** with pyzbar and byte-accurate extraction  
- ✔️ **Certificate validation** against trusted root keys  
- ✔️ **Payload signature verification**  

The project supports secure digital documents, access passes, academic certificates, tickets, and any application requiring verifiable QR-encoded data.

---

## Features

### ✔️ Signed Payloads
All payloads are signed using Ed25519:

- Payload is arbitrary bytes (often UTF-8 text or JSON)
- Signature uses the app-level private key
- Verification uses the public key stored inside certificate CBOR

### ✔️ Certificate Validation
Each QR contains a small embedded certificate:

- Contains the app public key
- Contains metadata (`nbf`, `exp`, `issuer`)
- Signed by a **trusted root**
- Validated at scan time against files in `trusted_roots/`

### ✔️ QR Encoding
Each build produces:

secure_qr.png – scannable QR image
secure_qr.bin – exact raw binary bytes used inside QR

pgsql


The `.bin` file is extremely useful for debugging and testing.

### ✔️ Byte-Perfect QR Scanning
The scanner ensures that **no character conversion occurs**, which is required for cryptographic verification.

---

## Repository Structure

```
.
├── create_qr_ed25519.py # Generate signed CBOR + QR
├── scan_qr_ed25519.py # Decode and verify QR
├── trusted_roots/ # PEM root keys / certificates
├── payloads/ # Example payload files
├── test_qr_images/ # Test QR PNGs and raw .bin data
└── README.md
```



---

# How It Works

## 1. Generate a QR Code

```bash
python3 create_qr_ed25519.py \
    --payload payload.txt \
    --cert my_app_cert.cbor \
    --key app_private_key.pem \
    --out secure_ed_qr.png
```

Outputs:

```
secure_ed_qr.png (QR image)

secure_ed_qr.bin (raw CBOR or CBOR.z bytes)
```

## 2. Scan and Verify

```
python3 scan_qr_ed25519.py \
    --file secure_ed_qr.png \
    --trusted-dir trusted_roots \
    --dump
```

## The scanner performs:
- Raw byte extraction from QR
- CBOR or zlib-CBOR parsing
- Certificate verification
- Payload signature verification
- Payload display (if valid)
- --dump shows literal bytes extracted from the QR for debugging.

## Certificate Format (CBOR)
# Example structure:

cbor
```
{
  "pub": <Ed25519 32-byte public key>,
  "issuer": "Root Authority",
  "nbf": 20250101,
  "exp": 20251231
}
```
## Signed using Ed25519 by the trusted root.

### Requirements
- nginx
- Python 3.10+
- cbor2
- cryptography
- segno
- pyzbar
- Pillow

### Install dependencies:

```
pip install -r requirements.txt
```

## Use Cases
- Academic certificates
- Digital passes and tickets
- Access control
- Anti-tampering documents
- Offline verifiable credentials
- Compact QR-encoded identity or proof tokens

# License

This project is released under the MIT License.
You are free to use, modify, distribute, and integrate the code in commercial or private projects, provided the original copyright notice is included.

# Disclosure

This software is provided “as is”, without warranties or guarantees of any kind.
It should not be used as the sole security component for critical or safety-related systems.
Use at your own risk.

# Author
Project developed as part of the secure-QR research and tooling initiative.
