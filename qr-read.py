#!/usr/bin/env python3
"""
Ultimate Secure QR Code Reader (Base64 + Full Logic)

This script combines:
1. Reliable reading (OpenCV + Base64) - works on Windows/Linux.
2. Full verification (Ed25519 Signatures, Expiry Dates, Trusted Roots).
3. Interactive user warnings.
"""

import argparse
import sys
import zlib
import base64
import cv2
import time
from datetime import datetime, timezone
from pathlib import Path

# External dependencies: pip install cbor2 cryptography opencv-python
import cbor2
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

# --- COLORS FOR READABILITY ---
class Color:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'
    RESET = '\033[0m'

def load_root_keys(path: Path) -> list:
    """Loads trusted public keys (Root) from a file or a directory."""
    keys = []
    
    def load_file(fpath):
        try:
            with open(fpath, "rb") as f:
                # Try loading as PEM Public Key
                keys.append(serialization.load_pem_public_key(f.read()))
                return True
        except Exception:
            return False

    if path.is_file():
        if not load_file(path):
            print(f"{Color.RED}[ERROR] Failed to load key: {path}{Color.RESET}")
            sys.exit(1)
    elif path.is_dir():
        for child in path.iterdir():
            if child.is_file():
                load_file(child)
        if not keys:
            print(f"{Color.RED}[ERROR] No valid keys found in directory: {path}{Color.RESET}")
            sys.exit(1)
    else:
        print(f"{Color.RED}[ERROR] Path does not exist: {path}{Color.RESET}")
        sys.exit(1)
        
    return keys

def check_dates(cert_map: dict) -> bool:
    """
    Checks 'nbf' (Not Before) and 'exp' (Expiration) fields.
    Robustly handles both Integer timestamps and String (ISO) formats.
    """
    now = int(time.time())

    def parse_to_timestamp(val):
        """Helper to convert various date formats to a unix timestamp."""
        # Case 1: Already a number (timestamp)
        if isinstance(val, (int, float)):
            return int(val)
        
        # Case 2: String (ISO 8601)
        if isinstance(val, str):
            try:
                # Replace 'Z' with +00:00 for compatibility
                dt = datetime.fromisoformat(val.replace('Z', '+00:00'))
                # If naive (no timezone), assume UTC
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return int(dt.timestamp())
            except ValueError:
                return None
        return None

    # 1. Check Not Before (nbf)
    if 'nbf' in cert_map:
        raw_nbf = cert_map['nbf']
        nbf = parse_to_timestamp(raw_nbf)
        
        if nbf is None:
             print(f"   {Color.YELLOW}[WARN] Unknown date format for 'nbf': {raw_nbf}{Color.RESET}")
        elif now < nbf:
            print(f"   {Color.RED}[FAIL] Certificate is NOT YET valid.{Color.RESET}")
            print(f"          Current time: {now}, Valid from: {nbf} ({raw_nbf})")
            return False

    # 2. Check Expiration (exp)
    if 'exp' in cert_map:
        raw_exp = cert_map['exp']
        exp = parse_to_timestamp(raw_exp)

        if exp is None:
            print(f"   {Color.YELLOW}[WARN] Unknown date format for 'exp': {raw_exp}{Color.RESET}")
        elif now > exp:
            print(f"   {Color.RED}[FAIL] Certificate has EXPIRED.{Color.RESET}")
            print(f"          Current time: {now}, Expired on: {exp} ({raw_exp})")
            return False

    return True

def verify_trust_chain(container: dict, root_keys: list) -> tuple[bool, str]:
    """
    Verifies the full trust chain:
    Root Key -> Certificate Signature -> Certificate Dates -> Payload Signature
    """
    print(f"\n{Color.CYAN}--- STARTING SECURITY VERIFICATION ---{Color.RESET}")

    # --- Step 0: Extract Structure ---
    try:
        payload = container['payload']
        payload_sig = container['payload_sig']
        cert_map = container['cert']
        cert_sig = container['cert_sig']
    except KeyError as e:
        return False, f"Corrupt data structure. Missing field: {e}"

    # --- Step 1: Verify Certificate Signature (by Root) ---
    print(f"1. Verifying Certificate (Signed by Root?)...")
    cert_verified = False
    
    # We must serialize the cert map back to bytes to check the signature
    cert_bytes = cbor2.dumps(cert_map)

    for root_key in root_keys:
        try:
            root_key.verify(cert_sig, cert_bytes)
            cert_verified = True
            break # Found a matching root key
        except Exception:
            continue
            
    if not cert_verified:
        return False, "Certificate signature INVALID (does not match any trusted root)."
    
    print(f"   {Color.GREEN}[OK] Certificate is TRUSTED.{Color.RESET}")

    # --- Step 2: Validate Metadata (Dates, Issuer) ---
    print(f"2. Validating Metadata (Dates, Issuer)...")
    
    if not check_dates(cert_map):
        return False, "Certificate date validation failed."
        
    if 'iss' in cert_map:
        print(f"   Info: Issuer is '{cert_map['iss']}'")

    print(f"   {Color.GREEN}[OK] Metadata is valid.{Color.RESET}")

    # --- Step 3: Verify Payload Signature (by App Key) ---
    print(f"3. Verifying Data Integrity (Signed by App?)...")
    try:
        # Extract App Public Key from Certificate
        app_pub_bytes = cert_map['pub']
        app_pub_key = ed25519.Ed25519PublicKey.from_public_bytes(app_pub_bytes)
        
        # Verify the actual payload
        app_pub_key.verify(payload_sig, payload)
    except Exception as e:
        return False, f"Payload signature is INVALID. {e}"

    print(f"   {Color.GREEN}[OK] Data is AUTHENTIC and UNMODIFIED.{Color.RESET}")

    return True, "Secure"

def scan_qr(image_path: Path, root_keys_path: Path):
    # 1. Load Trusted Keys
    try:
        root_keys = load_root_keys(root_keys_path)
        print(f"Loaded {len(root_keys)} trusted root key(s).")
    except Exception as e:
        print(f"Key error: {e}")
        return

    # 2. Read Image (OpenCV)
    if not image_path.exists():
        print(f"Error: File does not exist: {image_path}")
        sys.exit(1)

    print(f"Scanning image: {image_path.name} ...")
    
    try:
        img = cv2.imread(str(image_path))
        detector = cv2.QRCodeDetector()
        decoded_text, _, _ = detector.detectAndDecode(img)
    except Exception as e:
        print(f"[ERROR] OpenCV library error: {e}")
        return

    if not decoded_text:
        print(f"{Color.RED}[ERROR] No QR code detected.{Color.RESET}")
        return

    # 3. Decode: Base64 -> Binary -> CBOR
    print(f"Read QR string (Length: {len(decoded_text)})")
    
    try:
        # Decode Base64 (Safe Text -> Raw Bytes)
        raw_bytes = base64.b64decode(decoded_text)
        
        # Try Zlib decompression
        try:
            cbor_data = zlib.decompress(raw_bytes)
            print("Compression:       ZLIB (Decompressed)")
        except zlib.error:
            cbor_data = raw_bytes
            print("Compression:       NONE")

        container = cbor2.loads(cbor_data)
        print("Format:            VALID CBOR")
        
    except Exception as e:
        print(f"{Color.RED}[FATAL] Failed to parse data structure.{Color.RESET}")
        print(f"Details: {e}")
        return

    # 4. Run Verification
    is_valid, status_msg = verify_trust_chain(container, root_keys)

    # 5. User Interaction (UI)
    print("-" * 50)
    
    if is_valid:
        print(f"{Color.GREEN}✅ SUCCESS: DATA VERIFIED AND SECURE{Color.RESET}")
        print("-" * 50)
    else:
        print(f"{Color.RED}❌ SECURITY WARNING: VERIFICATION FAILED{Color.RESET}")
        print(f"Reason: {status_msg}")
        print("-" * 50)
        
        # Ask user if they want to proceed despite the error
        user_input = input(f"{Color.YELLOW}Data is UNTRUSTED. Display payload anyway? (yes/no): {Color.RESET}")
        if user_input.lower() not in ['yes', 'y', 'tak', 't']:
            print("Aborted. Payload hidden.")
            sys.exit(1)

    # 6. Display Content
    payload = container['payload']
    
    print("\nPAYLOAD CONTENT:")
    print("=" * 20)
    try:
        print(payload.decode('utf-8'))
    except UnicodeDecodeError:
        print(f"[Binary Data] {payload.hex()}")
    print("=" * 20)

    # Extra Cert Info
    cert = container.get('cert', {})
    if 'sub' in cert:
        print(f"\nSubject: {cert['sub']}")
    if 'exp' in cert:
        # Handle formatting for display (check if int first)
        exp_val = cert['exp']
        if isinstance(exp_val, int):
            exp_date = datetime.fromtimestamp(exp_val, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
            print(f"Expires: {exp_date}")
        else:
            print(f"Expires: {exp_val}")

def main():
    parser = argparse.ArgumentParser(description="Secure QR Reader (Base64/Ed25519)")
    parser.add_argument("--image", required=True, help="Path to the QR code image file")
    parser.add_argument("--root-pub", required=True, help="Path to root public key file OR directory containing keys")
    
    args = parser.parse_args()
    
    scan_qr(Path(args.image), Path(args.root_pub))

if __name__ == "__main__":
    main()