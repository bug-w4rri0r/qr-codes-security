# Secure CBOR QR Codes with Ed25519 Signatures

This toolkit provides an end-to-end solution for generating and verifying cryptographically secure QR codes. It uses **Ed25519** signatures, **CBOR** serialization, and **Zlib** compression to create compact, offline-verifiable payloads.

The system implements a **Chain of Trust**: A Root CA signs an Application Certificate, and the Application signs the QR Payload. The reader verifies the entire chain using only the Root Public Key.

## 📂 Repository Structure

```text
.
├── cert_gen/                  # Helper scripts for PKI management
│   ├── gen_ed_keys.py         # Generates Root and App Key Pairs
│   └── create_cose_cert.py    # Issues signed CBOR certificates
├── certs_vault/               # Output folder for private/public keys (Keep private!)
├── trusted_roots/             # Folder for Root Public Keys (for the Reader)
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
```
## 🛠️ Usage Workflow
### 1. Generate Cryptographic Keys
First, you need to generate the Ed25519 key pairs. This script generates both the Root CA keys and the Application keys.

Bash
```
python3 cert_gen/gen_ed_keys.py --gen-app --out-dir certs_vault
```
Output in certs_vault/:

- root_priv.pem / root_pub.pem: The Root Authority keys.

- app_priv.pem / app_pub.pem: The Application keys used to sign QRs.


### 2. Issue an Application Certificate
The Root CA must sign the Application's public key to create a valid certificate. This establishes the trust chain.

Bash
```
python3 cert_gen/create_cose_cert.py \
    --root-priv certs_vault/root_priv.pem \
    --sub "my-app-001" \
    --pub certs_vault/app_pub.pem \
    --not-after 2030-01-01 \
    --out certs_vault/app_cert.cbor
```
Output:
```
certs_vault/app_cert.cbor: A CBOR file containing the App's public key and metadata, signed by the Root CA.
```
### 3. Setup Trusted Roots (Crucial Step)
For the reader to verify the QR codes, it needs to "know" the Root CA. Copy the root public key to the trusted folder.

Bash
```
mkdir -p trusted_roots
cp certs_vault/root_pub.pem trusted_roots/
```
Note: In a real-world scenario, trusted_roots/ is the only folder distributed to the verifier devices.

### 4. Create a Secure QR Code
Now, sign a payload using the Application Private Key and embed the Application Certificate.

Bash
```
python3 qr-create.py \
    --payload payload.txt \
    --file \
    --app-priv certs_vault/app_priv.pem \
    --cert-cbor certs_vault/app_cert.cbor \
    --out secure_qr
```
Note: If encoding a simple string, remove --file and pass the string directly to --payload.

Output:
```
secure_qr.png: The visual QR code.

secure_qr.png.bin (optional): Raw binary data for debugging.
```
### 5. Scan and Verify
Use the reader script to verify the QR code. You must provide the path to the Root Public Key (or the directory containing it).

Bash
```
python3 qr-read.py \
    --image secure_qr.png \
    --root-pub trusted_roots/root_pub.pem \
    --debug
```
Expected Output: If the data is authentic, the script will output:

Plaintext
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