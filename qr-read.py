#!/usr/bin/env python3
"""
Secure QR Code Reader (Base64 Safe Version)

Logic:
1. Uses Standard OpenCV (cv2) to read the QR code as a string.
2. Since the QR contains Base64 text, OpenCV will NOT truncate it.
3. We decode Base64 -> Binary -> Decompress -> Verify.
"""

import argparse
import sys
import zlib
import base64
import cv2  # Standard OpenCV
from pathlib import Path

# Dependencies: pip install cbor2 cryptography opencv-python
import cbor2
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

def load_root_public_key(path: Path):
    if not path.exists():
        raise FileNotFoundError(f"Root key file not found: {path}")
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())

def verify_trust_chain(container: dict, root_pub_key) -> bool:
    print("\n--- STARTING SECURITY VERIFICATION ---")

    try:
        payload = container['payload']
        payload_sig = container['payload_sig']
        cert_map = container['cert']
        cert_sig = container['cert_sig']
    except KeyError as e:
        print(f"[ERROR] Invalid QR structure. Missing field: {e}")
        return False

    # Verify Cert
    print(f"1. Verifying Certificate (Signed by Root?)...")
    try:
        cert_bytes = cbor2.dumps(cert_map)
        root_pub_key.verify(cert_sig, cert_bytes)
        print("   [OK] Certificate is TRUSTED.")
    except Exception as e:
        print(f"   [FAIL] Certificate Invalid: {e}")
        return False

    # Extract App Key
    try:
        app_pub_bytes = cert_map['pub']
        app_pub_key = ed25519.Ed25519PublicKey.from_public_bytes(app_pub_bytes)
    except Exception:
        print("   [FAIL] Bad Key in Cert")
        return False

    # Verify Payload
    print(f"2. Verifying Payload (Signed by App?)...")
    try:
        app_pub_key.verify(payload_sig, payload)
        print("   [OK] Payload is AUTHENTIC.")
    except Exception as e:
        print(f"   [FAIL] Signature Invalid: {e}")
        return False

    return True

def scan_qr(image_path: Path, root_key_path: Path):
    if not image_path.exists():
        print(f"Error: Image not found: {image_path}")
        sys.exit(1)

    print(f"Scanning image: {image_path.name} ...")
    
    # --- OPENCV READING ---
    img = cv2.imread(str(image_path))
    detector = cv2.QRCodeDetector()
    decoded_text, _, _ = detector.detectAndDecode(img)

    if not decoded_text:
        print("[ERROR] No QR code detected or decode failed.")
        return

    print(f"Read QR String (Length: {len(decoded_text)})")

    # --- DECODE BASE64 ---
    try:
        # This is the magic step. Convert Safe Text -> Raw Binary
        raw_bytes = base64.b64decode(decoded_text)
        print(f"Decoded Base64 -> Binary ({len(raw_bytes)} bytes)")
    except Exception as e:
        print(f"[ERROR] Content is not valid Base64! {e}")
        return

    # --- DECOMPRESS & PARSE ---
    try:
        try:
            cbor_data = zlib.decompress(raw_bytes)
            print("Compression:      DETECTED (Zlib)")
        except zlib.error:
            cbor_data = raw_bytes
            print("Compression:      NONE")

        container = cbor2.loads(cbor_data)
        print("Format:           VALID CBOR")

    except Exception as e:
        print(f"[FATAL ERROR] Data corrupt: {e}")
        return

    # --- VERIFY ---
    try:
        root_key = load_root_public_key(root_key_path)
        if verify_trust_chain(container, root_key):
            print("-" * 50)
            print("✅ SUCCESS: VERIFIED SECURE DATA")
            print("-" * 50)
            payload = container['payload']
            try:
                print("PAYLOAD CONTENT:")
                print(payload.decode('utf-8'))
            except:
                print("PAYLOAD (BINARY):", payload.hex())
        else:
            print("❌ VERIFICATION FAILED")
    except Exception as e:
        print(f"Verification Error: {e}")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", required=True)
    parser.add_argument("--root-pub", required=True)
    args = parser.parse_args()
    scan_qr(Path(args.image), Path(args.root_pub))

if __name__ == "__main__":
    main()