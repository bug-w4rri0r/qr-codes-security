#!/usr/bin/env python3
"""
Secure QR Code Reader & Verifier (Ed25519)

This script performs the following steps:
1. Scans a QR code image using OpenCV.
2. Recovers raw binary data (fixing OpenCV's UTF-8 encoding issue).
3. Detects and handles Zlib compression.
4. Parses the CBOR structure.
5. Verifies the cryptographic trust chain:
   - Step A: Verifies the Certificate was signed by the Trusted Root.
   - Step B: Verifies the Payload was signed by the Certificate's key.
"""

import argparse
import sys
import zlib
import cv2
from pathlib import Path

# External libraries for data structure and cryptography
# pip install cbor2 cryptography opencv-python
import cbor2
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

def load_root_public_key(path: Path):
    """
    Loads the trusted Root Public Key from a PEM file.
    This key is the "Anchor of Trust".
    """
    if not path.exists():
        raise FileNotFoundError(f"Root key file not found: {path}")
    
    with open(path, "rb") as f:
        # Load PEM public key
        return serialization.load_pem_public_key(f.read())

def recover_raw_bytes(decoded_text: str) -> bytes:
    """
    CRITICAL FIX for OpenCV:
    OpenCV's QRCodeDetector interprets binary QR data as UTF-8 text, 
    which corrupts non-text bytes (like CBOR or compressed data).
    
    We treat the decoded string as 'latin-1' to map it back 
    1-to-1 to the original raw bytes.
    """
    return decoded_text.encode('latin-1')

def verify_trust_chain(container: dict, root_pub_key) -> bool:
    """
    Performs the cryptographic checks.
    
    Args:
        container (dict): The unpacked CBOR data containing payload, cert, and signatures.
        root_pub_key: The trusted root public key object.
        
    Returns:
        bool: True if valid, False if verification fails.
    """
    print("\n--- STARTING SECURITY VERIFICATION ---")

    # 1. Extract components from the container
    try:
        payload = container['payload']          # The actual user data
        payload_sig = container['payload_sig']  # Signature of the data
        cert_map = container['cert']            # The certificate (App Public Key + Metadata)
        cert_sig = container['cert_sig']        # Signature of the certificate (by Root)
    except KeyError as e:
        print(f"[ERROR] Invalid QR structure. Missing field: {e}")
        return False

    # 2. Verify Step A: Is the Certificate signed by our Trusted Root?
    print(f"1. Verifying Certificate integrity (Signed by Root?)...")
    try:
        # We must verify the bytes of the certificate map exactly as they were signed.
        # We re-serialize the map to CBOR to get those bytes.
        cert_bytes_to_verify = cbor2.dumps(cert_map)
        
        # Verify: (Signature, Data) using Root Key
        root_pub_key.verify(cert_sig, cert_bytes_to_verify)
        print("   [OK] Certificate is VALID and TRUSTED.")
    except Exception as e:
        print(f"   [FAIL] Certificate verification failed! The Root signature does not match. {e}")
        return False

    # 3. Extract the App Public Key from inside the Certificate
    try:
        # The key should be in the 'pub' field of the certificate map
        app_pub_bytes = cert_map['pub']
        # Convert raw bytes back to an Ed25519PublicKey object
        app_pub_key = ed25519.Ed25519PublicKey.from_public_bytes(app_pub_bytes)
    except Exception as e:
        print(f"   [FAIL] Could not extract Public Key from Certificate: {e}")
        return False

    # 4. Verify Step B: Is the Payload signed by the App Certificate?
    print(f"2. Verifying Payload integrity (Signed by App Key?)...")
    try:
        # Verify: (Signature, Payload) using App Key (derived from Cert)
        app_pub_key.verify(payload_sig, payload)
        print("   [OK] Payload is AUTHENTIC and UNMODIFIED.")
    except Exception as e:
        print(f"   [FAIL] Payload signature invalid! Data may have been tampered with. {e}")
        return False

    return True

def scan_qr(image_path: Path, root_key_path: Path):
    """
    Main workflow: Load Image -> Decode -> Decompress -> Parse -> Verify.
    """
    # --- Step 1: File Checks ---
    if not image_path.exists():
        print(f"Error: Image file not found: {image_path}")
        sys.exit(1)

    # --- Step 2: OpenCV Scanning ---
    # Load image using OpenCV
    img = cv2.imread(str(image_path))
    if img is None:
        print(f"Error: Failed to load image (unsupported format?): {image_path}")
        sys.exit(1)

    print(f"Scanning image: {image_path.name} ...")
    detector = cv2.QRCodeDetector()
    
    # detectAndDecode returns: (decoded_text, points, straight_qrcode)
    decoded_text, points, _ = detector.detectAndDecode(img)

    if points is None:
        print("[ERROR] No QR code detected in the image.")
        return

    if not decoded_text:
        print("[ERROR] QR code detected, but failed to decode content.")
        return

    # --- Step 3: Data Recovery & Decompression ---
    try:
        # Fix OpenCV encoding to get raw bytes
        raw_bytes = recover_raw_bytes(decoded_text)
        print(f"Raw data size: {len(raw_bytes)} bytes")

        # Attempt Zlib Decompression
        try:
            cbor_data = zlib.decompress(raw_bytes)
            print("Compression:   DETECTED (Zlib Inflated)")
        except zlib.error:
            # If error, assume data was not compressed
            cbor_data = raw_bytes
            print("Compression:   NONE (Raw Data)")

        # Parse CBOR
        container = cbor2.loads(cbor_data)
        print("Format:        VALID CBOR CONTAINER")

    except Exception as e:
        print("-" * 40)
        print("[FATAL ERROR] Failed to process QR data.")
        print(f"Details: {e}")
        print("Ensure this QR was generated by the secure generator script.")
        print("-" * 40)
        return

    # --- Step 4: Cryptographic Verification ---
    try:
        root_key = load_root_public_key(root_key_path)
        is_secure = verify_trust_chain(container, root_key)
    except Exception as e:
        print(f"[ERROR] Key loading failed: {e}")
        return

    # --- Step 5: Final Output ---
    print("-" * 50)
    if is_secure:
        print("✅ SUCCESS: VERIFIED SECURE DATA")
        print("-" * 50)
        
        payload = container['payload']
        
        # Try to print payload as text, otherwise hex
        try:
            print("PAYLOAD CONTENT:")
            print(payload.decode('utf-8'))
        except UnicodeDecodeError:
            print("PAYLOAD CONTENT (BINARY):")
            print(payload.hex())
            
        # Optional: Print info about who issued this data
        cert = container.get('cert', {})
        if 'iss' in cert: print(f"\nIssuer:  {cert['iss']}")
        if 'sub' in cert: print(f"Subject: {cert['sub']}")
        
    else:
        print("❌ WARNING: VERIFICATION FAILED")
        print("The data cannot be trusted. It may be forged or the certificate is invalid.")
    print("-" * 50)

def main():
    parser = argparse.ArgumentParser(description="Read and Verify Ed25519 Signed QR Codes")
    parser.add_argument("--image", required=True, help="Path to the PNG image file")
    parser.add_argument("--root-pub", required=True, help="Path to the Root Public Key (PEM)")
    
    args = parser.parse_args()
    
    scan_qr(Path(args.image), Path(args.root_pub))

if __name__ == "__main__":
    main()