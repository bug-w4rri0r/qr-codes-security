# Secure QR Code Architecture: Usage Guide

This project uses a flexible PKI (Public Key Infrastructure) architecture to generate and verify secure QR codes. It supports a two-tier structure (Root CA + App) for maximum security and scalability. Follow these steps to generate keys, create a certificate, and generate/scan the signed QR codes.

## Step I: Generate Ed25519 Cryptographic Keys

First, you need to generate the cryptographic key pairs. By default, the system requires a Root CA key pair and an Application (Subject) key pair.

**1. Generate both Root and App keys in the current directory:**
``` bash
python3 gen_ed_keys.py --out-dir .
```
(This will generate root_priv.pem, root_pub.pem, app_priv.pem, and app_pub.pem)

Alternative options for custom setups:

``` Bash
# Generate ONLY Root keys with a custom name in a specific directory:
python3 gen_ed_keys.py --root-name "firma_root-demo" --root-only --out-dir ./demo-test/

# Generate ONLY Root keys for a specific campus:
python3 gen_ed_keys.py --root-name "PWr-Campus" --app-only --out-dir ./demo-test/

# Generate ONLY Root keys in the current directory:
python3 gen_ed_keys.py --root-only --out-dir .

```

## Step II: Create the COSE Certificate
Next, the Root CA must "sign" the Application's public key to establish trust. This generates a lightweight CBOR certificate.

``` Bash
python3 create_cose_cert.py --root-priv root_priv.pem --sub app1 --pub app_pub.pem --not-after 2030-01-01 --out app_cert.cbor
```
⚠️ Important: After this step, you must copy or move your root_pub.pem to the trusted_roots/ directory. The scanner will use this folder to verify the certificate chain.


## Step III: Generate the Secure QR Code
Now, use the Application's private key to sign your payload, and embed the generated CBOR certificate into the final QR code image.
``` Bash
python3 create_qr_ed25519.py --payload "[https://example.com/short](https://example.com/short)" --app-priv app_priv.pem --cert-cbor app_cert.cbor --out secure_ed_qr
```

## Step IV: Scan and Verify the QR Code
Finally, the scanner reads the QR code, verifies the App's certificate against the trusted Root CA, and authenticates the payload.
``` Bash
python3 qr-read.py --file secure_ed_qr.png --trusted-dir trusted_roots
```

# Comprehensive Real-World Example
If you are using specific directories for your keys, payloads, and images, a full run looks like this:

## 1. Generate the QR Code from a payload text file:
``` Bash
python3 qr-create.py --payload payload.txt --file --app-priv ./cert_keys/app_priv.pem --cert-cbor ./cert_keys/app_cert.cbor --out ./test_qr_images/secure_ed_qr_v1.4
```
## 2. Scan and verify with debug output:
``` Bash
python3 qr-read.py --image ./test_qr_images/secure_ed_qr_v1.4.png --trusted-dir ./trusted_roots --debug
```