#!/usr/bin/env python3
"""
Ultimate Secure QR Code Reader (v3.0 - Full Debug / No Truncation)
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
    """Prints FULL data without truncation."""
    print(f"\n{Color.CYAN}[DEBUG] --- {label} ---{Color.RESET}")
    if data is None:
        print(" [None]")
        return
    
    size = len(data)
    print(f" Size: {size}")
    
    if is_text:
        # PRINT FULL TEXT
        print(f" Content: {data}")
    else:
        # PRINT FULL HEX DUMP
        hex_str = data.hex()
        chunk_size = 64
        for i in range(0, len(hex_str), chunk_size):
            row = hex_str[i:i+chunk_size]
            formatted = " ".join([row[j:j+2] for j in range(0, len(row), 2)])
            print(f" Hex: {formatted}")

def load_root_keys(path: Path) -> list:
    keys = []
    def load_file(fpath):
        try:
            with open(fpath, "rb") as f:
                keys.append(serialization.load_pem_public_key(f.read()))
                return True
        except Exception:
            return False
    
    if path.is_file(): load_file(path)
    elif path.is_dir():
        for child in path.iterdir():
            if child.is_file(): load_file(child)
    return keys

def check_dates(cert_map: dict) -> bool:
    now = int(time.time())
    if 'exp' in cert_map:
        val = cert_map['exp']
        exp = int(val) if isinstance(val, (int, float)) else None
        if isinstance(val, str):
            try: exp = int(datetime.fromisoformat(val.replace('Z', '+00:00')).timestamp())
            except: pass
        if exp and now > exp:
            print(f"   {Color.RED}[FAIL] Certificate EXPIRED.{Color.RESET}")
            return False
    return True

def verify_trust_chain(container: dict, root_keys: list, debug: bool = False) -> tuple[bool, str]:
    print(f"\n{Color.CYAN}--- STARTING SECURITY VERIFICATION ---{Color.RESET}")

    payload = container.get('payload')
    payload_sig = container.get('payload_sig')
    cert_map = container.get('cert')
    cert_sig = container.get('cert_sig')
    
    if debug:
        print_debug("Payload (Raw Bytes to Verify)", payload)
        print_debug("Payload Signature", payload_sig)
        print_debug("Certificate Structure (CBOR)", cbor2.dumps(cert_map))
        print_debug("Certificate Signature", cert_sig)

    # 1. Verify Cert
    print(f"1. Verifying Certificate...")
    cert_verified = False
    cert_bytes = cbor2.dumps(cert_map)
    for root_key in root_keys:
        try:
            root_key.verify(cert_sig, cert_bytes)
            cert_verified = True
            break
        except: continue
            
    if not cert_verified: return False, "Invalid Cert Signature"
    print(f"   {Color.GREEN}[OK] Certificate Trusted.{Color.RESET}")

    # 2. Metadata
    if not check_dates(cert_map): return False, "Date Validation Failed"

    # 3. Payload
    print(f"3. Verifying Payload...")
    try:
        app_pub_key = ed25519.Ed25519PublicKey.from_public_bytes(cert_map['pub'])
        app_pub_key.verify(payload_sig, payload)
    except Exception as e: return False, f"Invalid Payload Sig: {e}"

    print(f"   {Color.GREEN}[OK] Payload Authentic.{Color.RESET}")
    return True, "Secure"

def scan_qr(image_path: Path, root_keys_path: Path, debug: bool = False):
    root_keys = load_root_keys(root_keys_path)
    if not root_keys:
        print("No root keys found.")
        return

    print(f"Scanning: {image_path.name}")
    img = cv2.imread(str(image_path))
    if img is None:
        print("Failed to load image.")
        return
        
    detector = cv2.QRCodeDetector()
    decoded_text, _, _ = detector.detectAndDecode(img)

    if not decoded_text:
        print(f"{Color.RED}No QR detected.{Color.RESET}")
        return

    if debug:
        print_debug("Step 1: Raw QR Text (Base64)", decoded_text, is_text=True)

    # Decode Flow
    try:
        # 1. Base64 Decode
        raw_bytes = base64.b64decode(decoded_text)
        if debug:
            print_debug("Step 2: Base64 Decoded (Compressed Bytes)", raw_bytes)
        
        # 2. ZLIB Decompress
        try:
            cbor_data = zlib.decompress(raw_bytes)
            if debug:
                print_debug("Step 3: ZLIB Decompressed (CBOR Bytes)", cbor_data)
        except zlib.error:
            cbor_data = raw_bytes
            print("No compression detected.")

        # 3. CBOR Load
        container = cbor2.loads(cbor_data)
        
    except Exception as e:
        print(f"{Color.RED}Parse Error: {e}{Color.RESET}")
        return

    # Verify
    is_valid, msg = verify_trust_chain(container, root_keys, debug=debug)

    if is_valid:
        print(f"\n{Color.GREEN}✅ SUCCESS{Color.RESET}")
        print("-" * 20)
        try:
            print(container['payload'].decode('utf-8'))
        except:
            print(container['payload'].hex())
    else:
        print(f"\n{Color.RED}❌ FAILED: {msg}{Color.RESET}")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", required=True)
    parser.add_argument("--root-pub", required=True)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()
    scan_qr(Path(args.image), Path(args.root_pub), debug=args.debug)

if __name__ == "__main__":
    main()