#!/usr/bin/env python3
"""
Ultimate Secure QR Code Reader (Base64 + Debug Mode)
"""

import argparse
import sys
import zlib
import base64
import cv2
import time
from datetime import datetime, timezone
from pathlib import Path

import cbor2
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

class Color:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'
    RESET = '\033[0m'

def print_debug(label, data, is_text=False):
    """Helper for nice debug printing"""
    print(f"\n{Color.CYAN}[DEBUG] --- {label} ---{Color.RESET}")
    if data is None:
        print(" [None]")
        return
    
    size = len(data)
    print(f" Size: {size}")
    
    if is_text:
        # Show start and end of string
        if size > 100:
            print(f" Content: {data[:50]!r} ... {data[-50:]!r}")
        else:
            print(f" Content: {data!r}")
    else:
        # Hex dump
        hex_str = data.hex()
        preview = hex_str[:128]
        formatted = " ".join([preview[i:i+2] for i in range(0, len(preview), 2)])
        print(f" Hex: {formatted}" + ("..." if len(hex_str) > 128 else ""))

def load_root_keys(path: Path) -> list:
    keys = []
    def load_file(fpath):
        try:
            with open(fpath, "rb") as f:
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
    now = int(time.time())
    
    def parse_to_timestamp(val):
        if isinstance(val, (int, float)): return int(val)
        if isinstance(val, str):
            try:
                dt = datetime.fromisoformat(val.replace('Z', '+00:00'))
                if dt.tzinfo is None: dt = dt.replace(tzinfo=timezone.utc)
                return int(dt.timestamp())
            except ValueError: return None
        return None

    if 'nbf' in cert_map:
        nbf = parse_to_timestamp(cert_map['nbf'])
        if nbf and now < nbf:
            print(f"   {Color.RED}[FAIL] Certificate is NOT YET valid (starts {nbf}).{Color.RESET}")
            return False

    if 'exp' in cert_map:
        exp = parse_to_timestamp(cert_map['exp'])
        if exp and now > exp:
            print(f"   {Color.RED}[FAIL] Certificate has EXPIRED (ended {exp}).{Color.RESET}")
            return False

    return True

def verify_trust_chain(container: dict, root_keys: list, debug: bool = False) -> tuple[bool, str]:
    print(f"\n{Color.CYAN}--- STARTING SECURITY VERIFICATION ---{Color.RESET}")

    try:
        payload = container['payload']
        payload_sig = container['payload_sig']
        cert_map = container['cert']
        cert_sig = container['cert_sig']
    except KeyError as e:
        return False, f"Corrupt data structure. Missing field: {e}"
    
    if debug:
        print_debug("Payload to Verify", payload)
        print_debug("Provided Payload Signature", payload_sig)
        print_debug("Certificate Data", cbor2.dumps(cert_map))
        print_debug("Provided Cert Signature", cert_sig)

    # 1. Verify Certificate
    print(f"1. Verifying Certificate (Signed by Root?)...")
    cert_verified = False
    cert_bytes = cbor2.dumps(cert_map)

    for root_key in root_keys:
        try:
            root_key.verify(cert_sig, cert_bytes)
            cert_verified = True
            break
        except Exception:
            continue
            
    if not cert_verified:
        return False, "Certificate signature INVALID (does not match any trusted root)."
    print(f"   {Color.GREEN}[OK] Certificate is TRUSTED.{Color.RESET}")

    # 2. Metadata
    print(f"2. Validating Metadata (Dates, Issuer)...")
    if not check_dates(cert_map):
        return False, "Certificate date validation failed."
    print(f"   {Color.GREEN}[OK] Metadata is valid.{Color.RESET}")

    # 3. Payload Integrity
    print(f"3. Verifying Data Integrity (Signed by App?)...")
    try:
        app_pub_bytes = cert_map['pub']
        app_pub_key = ed25519.Ed25519PublicKey.from_public_bytes(app_pub_bytes)
        app_pub_key.verify(payload_sig, payload)
    except Exception as e:
        return False, f"Payload signature is INVALID. {e}"

    print(f"   {Color.GREEN}[OK] Data is AUTHENTIC and UNMODIFIED.{Color.RESET}")
    return True, "Secure"

def scan_qr(image_path: Path, root_keys_path: Path, debug: bool = False):
    # 1. Load Keys
    try:
        root_keys = load_root_keys(root_keys_path)
        print(f"Loaded {len(root_keys)} trusted root key(s).")
    except Exception as e:
        print(f"Key error: {e}")
        return

    # 2. Read Image
    if not image_path.exists():
        print(f"Error: File {image_path} does not exist")
        sys.exit(1)

    print(f"Scanning image: {image_path.name} ...")
    try:
        img = cv2.imread(str(image_path))
        detector = cv2.QRCodeDetector()
        decoded_text, _, _ = detector.detectAndDecode(img)
    except Exception as e:
        print(f"[ERROR] OpenCV error: {e}")
        return

    if not decoded_text:
        print(f"{Color.RED}[ERROR] No QR code detected.{Color.RESET}")
        return

    if debug:
        print_debug("Step 1: Raw QR Text (Base64)", decoded_text, is_text=True)

    # 3. Decode
    try:
        raw_bytes = base64.b64decode(decoded_text)
        if debug:
            print_debug("Step 2: Decoded Base64 (Binary)", raw_bytes)
        
        try:
            cbor_data = zlib.decompress(raw_bytes)
            print("Compression:       ZLIB (Decompressed)")
        except zlib.error:
            cbor_data = raw_bytes
            print("Compression:       NONE")
            
        if debug:
            print_debug("Step 3: CBOR Data (Ready to parse)", cbor_data)

        container = cbor2.loads(cbor_data)
        print("Format:            VALID CBOR")
        
    except Exception as e:
        print(f"{Color.RED}[FATAL] Failed to parse data.{Color.RESET}")
        print(f"Details: {e}")
        return

    # 4. Verify
    is_valid, status_msg = verify_trust_chain(container, root_keys, debug=debug)

    print("-" * 50)
    if is_valid:
        print(f"{Color.GREEN}✅ SUCCESS: DATA VERIFIED AND SECURE{Color.RESET}")
    else:
        print(f"{Color.RED}❌ SECURITY WARNING: VERIFICATION FAILED{Color.RESET}")
        print(f"Reason: {status_msg}")
        print("-" * 50)
        
        user_input = input(f"{Color.YELLOW}Data is UNTRUSTED. Display payload anyway? (yes/no): {Color.RESET}")
        if user_input.lower() not in ['yes', 'y', 'tak', 't']:
            sys.exit(1)

    # 5. Display
    print("\nPAYLOAD CONTENT:")
    print("=" * 20)
    try:
        print(container['payload'].decode('utf-8'))
    except:
        print(f"[Binary Data] {container['payload'].hex()}")
    print("=" * 20)

    if 'sub' in container.get('cert', {}):
        print(f"Subject: {container['cert']['sub']}")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", required=True)
    parser.add_argument("--root-pub", required=True)
    parser.add_argument("--debug", action="store_true", help="Enable detailed debug output")
    args = parser.parse_args()
    
    scan_qr(Path(args.image), Path(args.root_pub), debug=args.debug)

if __name__ == "__main__":
    main()