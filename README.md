# Secure CBOR QR Codes with Ed25519 Signatures

This toolkit provides an end-to-end solution for generating and verifying cryptographically secure QR codes. It uses **Ed25519** signatures, **CBOR** serialization, and **Zlib** compression to create compact, offline-verifiable payloads.

The system supports two Public Key Infrastructure (PKI) trust models:
1. Root-Only (Direct Trust) – data is signed directly by the Root CA.
2. Root + App (Certificate Chain) – data is signed by an application/department that holds a certificate issued by the Root CA. The reader verifies the entire chain using only the Root Public Key.

## 📂 Repository Structure

```text
.
├── cert_gen/                  # Helper scripts for PKI management
│   ├── gen_ed_keys.py         # Generates Root and App Key Pairs
│   └── create_cose_cert.py    # Issues signed CBOR certificates
├── certs_vault/               # Output folder for private/public keys (Keep private!)
├── trusted_roots/             # Folder for Root Public Keys (for the Reader)
├── test_qr_images/            # Output folder for generated QR images
├── qr-create.py               # Main script to generate secure QR codes
├── qr-read.py                 # Main script to scan and verify QR codes
├── payload.txt                # Sample data input
├── requirements.txt           # Python dependencies
└── README.md
```
## 🚀 Getting Started
Prerequisites
Ensure you have Python 3.10+ installed. Install the required dependencies:

Bash
```
pip install cbor2 cryptography segno opencv-python numpy
pip install -r requirements.txt
```
## 🛠️ Usage Workflow
### Scenario 1: Root-Only (Direct Trust)
In this scenario, the main authority (e.g., Campus) directly signs the QR code.

#### 1. Generate Root CA keys:

First, you need to generate the Ed25519 key pairs. This script generates both the Root CA keys and the Application keys.

Bash
```
python cert_gen/gen_ed_keys.py --root-name "PWr-Campus" --root-only --out-dir ./certs_vault/
```
Output in certs_vault/:

- root_priv.pem / root_pub.pem: The Root Authority keys.

#### 2. Setup Trusted Roots (Crucial Step):
For the reader to verify the QR codes, it needs to "know" the Root CA.
Bash
```
cp ./certs_vault/PWr-Campus_pub.pem ./trusted_roots/
```


#### 3. Create a Secure QR Code:
Bash
```
python qr-create.py --payload "Welcome to PWr campus (Direct Trust)!" --root-priv ./certs_vault/PWr-Campus_priv.pem --out ./test_qr_images/qr_pwr_campus_direct
```

#### 4. Scan and Verify:

Bash
```
python qr-read.py --image ./test_qr_images/qr_pwr_campus_direct.png --trusted-dir ./trusted_roots/ --debug
```

#### Expected Output:

```
[OK] Signature verified by ROOT key.
[OK] Data is AUTHENTIC and UNMODIFIED.
✅ SUCCESS: DATA VERIFIED AND SECURE
```

### Scenario 2: Root + App (Certificate Chain)
The Campus (Root CA) issues a certificate to a department (e.g., W4N-K34). The department signs its own QR codes and attaches the certificate. (Requires Root keys from Scenario 1).

#### 1. Generate application/department keys:


Bash
```
python cert_gen/gen_ed_keys.py --app-only --out-dir ./certs_vault/
```

Output in certs_vault/:

- root_priv.pem / root_pub.pem: The Root Authority keys.

- app_priv.pem / app_pub.pem: The Application keys used to sign QRs.

#### 2. Issue an Application Certificate
Bash
```
python cert_gen/create_cose_cert.py --root-priv ./certs_vault/PWr-Campus_priv.pem --iss "PWr-Campus" --sub "W4N-K34" --pub ./certs_vault/app_pub.pem --not-before "2024-01-01" --not-after "2030-12-31" --out ./certs_vault/cert_W4N_K34.cbor
```


#### 3. Generate the QR code (signed by App):
Bash
```
python qr-create.py --payload "Access to W4N-K34 lab granted." --app-priv ./certs_vault/app_priv.pem --cert-cbor ./certs_vault/cert_W4N_K34.cbor --out ./test_qr_images/qr_w4n_k34_chain
```

#### 4. Read and verify the full chain:

Bash
```
python qr-read.py --image ./test_qr_images/qr_w4n_k34_chain.png --trusted-dir ./trusted_roots/ --debug
```
### Expected Output:

```
[OK] Certificate is TRUSTED.
[OK] Metadata is valid.
[OK] Data is AUTHENTIC and UNMODIFIED.
✅ SUCCESS: DATA VERIFIED AND SECURE
```

It will then display the payload content and a technical summary (QR Version, Compression ratio, etc.).

## ⚙️ Technical Details
### The Trust Chain
 1. Root Key: Generated once. Kept offline. Signs the App Certificate.
 2. App Certificate: Contains app_pub, issue_date, expiration, and issuer. Signed by Root.
 3. QR Payload: Contains User Data + Signature. Signed by app_priv.

### Data Structure (Inside the QR)
The QR code contains a Base64 encoded string, which decodes to a Zlib compressed CBOR object:

JSON
```
{
  "payload": "Actual User Data...",
  "payload_sig": "<Ed25519 Signature of payload>",
  "cert": {
    "sub": "app-id",
    "pub": "<App Public Key Bytes>",
    "exp": "Expiration Date"
  },
  "cert_sig": "<Ed25519 Signature of cert by Root>"
}
```
### Security Features
 - Ed25519: High-performance, high-security elliptic curve signatures.
 - Expiration: Certificates utilize nbf (not before) and exp (expiration) fields.
 - Base64 Safe: The binary data is Base64 encoded to ensure compatibility with standard QR readers and libraries like OpenCV.

## ⚠️ Troubleshooting
 - "Certificate signature INVALID": Ensure trusted_roots/ contains the exact root_pub.pem that corresponds to the root_priv.pem used to create the certificate.
 - "Certificate has EXPIRED": Check the --not-after date used during certificate generation.
 - "Data too large": The QR payload might exceed Version 40 capacity. Try reducing the payload size or ensuring --no-compress is NOT used.

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