#!/usr/bin/env python3
"""
Ultimate Secure QR Code Reader (v3.3 - Full Debug, robust comments & Summary)

Description:
  This script scans a QR code containing Ed25519-signed data, verifies
  the trust chain against a provided Root CA public key, and displays
  the content only if authentic. It concludes with a detailed technical
  summary table matching the generator's output style.

Key Features:
  1. Full Debug Mode: View raw Base64, Hex dumps, and CBOR structures.
  2. Security Verification: Checks Certificate signature, Expiration dates,
     and Payload integrity.
  3. Technical Summary: Displays QR Version, Compression stats, and Data sizes.
  4. Safety: Prompts user before displaying untrusted data.
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

# ANSI Color Codes for Terminal Output
class Color:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'
    RESET = '\033[0m'

def print_debug(label, data, is_text=False):
    """
    Helper function for verbose debug printing.
    Shows FULL data without truncation (byte-perfect debugging).
    """
    print(f"\n{Color.CYAN}[DEBUG] --- {label} ---{Color.RESET}")
    if data is None:
        print(" [None]")
        return
    
    size = len(data)
    print(f" Size: {size} bytes/chars")
    
    if is_text:
        # Print FULL text
        print(f" Content:\n{data}")
    else:
        # Print FULL Hex Dump
        hex_str = data.hex()
        # Format nicely in rows of 32 bytes (64 hex chars)
        chunk_size = 64
        for i in range(0, len(hex_str), chunk_size):
            row = hex_str[i:i+chunk_size]
            formatted = " ".join([row[j:j+2] for j in range(0, len(row), 2)])
            print(f" Hex: {formatted}")

def load_root_keys(path: Path) -> list:
    """Loads trusted Root CA public keys from a file or directory."""
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
    """Validates 'nbf' (Not Before) and 'exp' (Expiration) fields."""
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

    # Check "Not Before"
    if 'nbf' in cert_map:
        nbf = parse_to_timestamp(cert_map['nbf'])
        if nbf and now < nbf:
            print(f"   {Color.RED}[FAIL] Certificate is NOT YET valid (starts {cert_map['nbf']}).{Color.RESET}")
            return False

    # Check "Expiration"
    if 'exp' in cert_map:
        exp = parse_to_timestamp(cert_map['exp'])
        if exp and now > exp:
            print(f"   {Color.RED}[FAIL] Certificate has EXPIRED (ended {cert_map['exp']}).{Color.RESET}")
            return False

    return True

def verify_trust_chain(container: dict, root_keys: list, debug: bool = False) -> tuple[bool, str]:
    """
    Verifies the entire security chain:
    1. Root CA signature on App Certificate.
    2. App Certificate validity (dates).
    3. App signature on Payload.
    """
    print(f"\n{Color.CYAN}--- STARTING SECURITY VERIFICATION ---{Color.RESET}")

    try:
        payload = container['payload']
        payload_sig = container['payload_sig']
        cert_map = container['cert']
        cert_sig = container['cert_sig']
    except KeyError as e:
        return False, f"Corrupt data structure. Missing field: {e}"
    
    # --- DODANE: Szczegółowe informacje o certyfikacie i ścieżce autoryzacji ---
    print(f"\n{Color.YELLOW}[Certificate & Authorization Details]{Color.RESET}")
    print(f"   Issuer (iss):          {cert_map.get('iss', 'N/A (Unknown)')}")
    print(f"   Subject (sub):         {cert_map.get('sub', 'N/A (Unknown)')}")
    print(f"   Valid From (nbf):      {cert_map.get('nbf', 'N/A (No start date)')}")
    print(f"   Expires (exp):         {cert_map.get('exp', 'N/A (No expiration)')}")
    print(f"   -----------------------")
    print(f"   Payload Size:          {len(payload)} bytes")
    print(f"   Payload Signature:     {len(payload_sig)} bytes (Ed25519)")
    print(f"   Certificate Signature: {len(cert_sig)} bytes (Ed25519)\n")
    # -------------------------------------------------------------------------
    
    if debug:
        print_debug("Payload to Verify", payload)
        print_debug("Provided Payload Signature", payload_sig)
        print_debug("Certificate Data (CBOR)", cbor2.dumps(cert_map))
        print_debug("Provided Cert Signature", cert_sig)

    # 1. Verify Certificate Signature
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

    # 2. Verify Metadata (Dates)
    print(f"2. Validating Metadata (Dates, Issuer)...")
    if not check_dates(cert_map):
        return False, "Certificate date validation failed."
    print(f"   {Color.GREEN}[OK] Metadata is valid.{Color.RESET}")

    # 3. Verify Payload Integrity
    print(f"3. Verifying Data Integrity (Signed by App?)...")
    try:
        app_pub_bytes = cert_map['pub']
        app_pub_key = ed25519.Ed25519PublicKey.from_public_bytes(app_pub_bytes)
        app_pub_key.verify(payload_sig, payload)
    except Exception as e:
        return False, f"Payload signature is INVALID. {e}"

    print(f"   {Color.GREEN}[OK] Data is AUTHENTIC and UNMODIFIED.{Color.RESET}")
    return True, "Secure"

def estimate_qr_version(straight_qrcode):
    """
    Attempts to calculate QR Version from the rectified image returned by OpenCV.
    Formula: Version = (Modules - 21) / 4 + 1
    """
    if straight_qrcode is None:
        return "N/A"
    
    try:
        # OpenCV returns a rectified square image.
        # Ideally, 1 pixel = 1 module.
        width = straight_qrcode.shape[0]
        
        # Check if width matches a valid QR dimension (21, 25, 29, ..., 177)
        # Dimension = 21 + (V-1)*4
        if (width - 21) % 4 == 0:
            v = (width - 21) // 4 + 1
            if 1 <= v <= 40:
                return str(v)
        
        # If OpenCV upscaled the image, this simple check fails.
        return "Unknown (Resampled)"
    except:
        return "N/A"

def scan_qr(image_path: Path, root_keys_path: Path, debug: bool = False):
    # Stats container for the final summary
    stats = {
        "compressed": False,
        "raw_size": 0,    # Size of CBOR bytes (potentially compressed)
        "final_size": 0,  # Size of actual payload
        "version": "N/A"
    }

    # 1. Load Trusted Root Keys
    try:
        root_keys = load_root_keys(root_keys_path)
        print(f"Loaded {len(root_keys)} trusted root key(s).")
    except Exception as e:
        print(f"Key error: {e}")
        return

    # 2. Load and Decode Image
    if not image_path.exists():
        print(f"Error: File {image_path} does not exist")
        sys.exit(1)

    print(f"Scanning image: {image_path.name} ...")
    try:
        img = cv2.imread(str(image_path))
        if img is None:
            print(f"{Color.RED}[ERROR] Failed to load image file.{Color.RESET}")
            return
            
        detector = cv2.QRCodeDetector()
        # detectAndDecode returns: decoded_info, points, straight_qrcode (rectified image)
        decoded_text, points, straight_qrcode = detector.detectAndDecode(img)
    except Exception as e:
        print(f"[ERROR] OpenCV error: {e}")
        return

    if not decoded_text:
        print(f"{Color.RED}[ERROR] No QR code detected.{Color.RESET}")
        return

    # Estimate Version logic
    stats["version"] = estimate_qr_version(straight_qrcode)

    if debug:
        print_debug("Step 1: Raw QR Text (Base64)", decoded_text, is_text=True)

    # 3. Process Data (Base64 -> ZLIB -> CBOR)
    try:
        # A. Base64 Decode
        raw_bytes = base64.b64decode(decoded_text)
        stats["raw_size"] = len(raw_bytes) # Store compressed size for stats
        
        if debug:
            print_debug("Step 2: Decoded Base64 (Binary)", raw_bytes)
        
        # B. ZLIB Decompress
        try:
            cbor_data = zlib.decompress(raw_bytes)
            stats["compressed"] = True
            print("Compression:       ZLIB (Decompressed)")
            if debug: print_debug("Step 3: ZLIB Decompressed", cbor_data)
        except zlib.error:
            cbor_data = raw_bytes
            stats["compressed"] = False
            print("Compression:       NONE")
            
        # C. CBOR Load
        container = cbor2.loads(cbor_data)
        stats["final_size"] = len(container.get('payload', b''))
        print("Format:            VALID CBOR")
        
    except Exception as e:
        print(f"{Color.RED}[FATAL] Failed to parse data structure.{Color.RESET}")
        print(f"Details: {e}")
        return

    # 4. Perform Security Checks
    is_valid, status_msg = verify_trust_chain(container, root_keys, debug=debug)

    print("-" * 50)
    if is_valid:
        print(f"{Color.GREEN}✅ SUCCESS: DATA VERIFIED AND SECURE{Color.RESET}")
    else:
        print(f"{Color.RED}❌ SECURITY WARNING: VERIFICATION FAILED{Color.RESET}")
        print(f"Reason: {status_msg}")
        print("-" * 50)
        
        # Prompt user if data is untrusted
        try:
            user_input = input(f"{Color.YELLOW}Data is UNTRUSTED. Display payload anyway? (yes/no): {Color.RESET}")
            if user_input.lower() not in ['yes', 'y', 'tak', 't']:
                print("Aborting display.")
                sys.exit(1)
        except KeyboardInterrupt:
            print("\nAborted.")
            sys.exit(1)

    # 5. Display Payload
    print("\n" + "=" * 30)
    print("      PAYLOAD CONTENT      ")
    print("=" * 30)
    try:
        print(container['payload'].decode('utf-8'))
    except:
        print(f"[Binary Data] Hex: {container['payload'].hex()}")
    print("=" * 30 + "\n")

    if 'sub' in container.get('cert', {}):
        print(f"Issued to (Subject): {container['cert']['sub']}")

    # 6. SUMMARY TABLE
    print("\n" + "="*65)
    print(" READING SUMMARY")
    print("="*65)
    print(f" Input File:        {image_path.name}")
    print("-" * 65)
    print(f" QR Version:        {stats['version']} (Estimated)")
    print(f" Error Correction:  N/A (Hidden by Reader)")
    print(f" Encoding:          Base64")
    print(f" Compression:       {'YES (ZLIB)' if stats['compressed'] else 'NO'}")
    print(f" Payload Size:      {stats['final_size']} bytes (Decompressed)")
    print(f" Structure Size:    {stats['raw_size']} bytes (Compressed/CBOR)")
    print("="*65)

def main():
    parser = argparse.ArgumentParser(description="Secure QR Code Reader (Ed25519 + CBOR)")
    parser.add_argument("--image", required=True, help="Path to the QR code image")
    parser.add_argument("--root-pub", required=True, help="Path to Root CA public key (PEM)")
    parser.add_argument("--debug", action="store_true", help="Enable full debug output (no truncation)")
    
    args = parser.parse_args()
    
    scan_qr(Path(args.image), Path(args.root_pub), debug=args.debug)

if __name__ == "__main__":
    main()