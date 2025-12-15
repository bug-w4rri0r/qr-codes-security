#!/usr/bin/env python3
"""
ED25519 Signed QR Code Generator (v3.1 - Full Debug & English Comments)

Description:
  This script generates a secure QR code containing data signed digitally
  with an Ed25519 private key.
  
Key Features:
  1. Signs the data (Payload) with the App's private key.
  2. Packages data and certificate into a CBOR structure.
  3. Compresses data (ZLIB) to save space.
  4. Encodes result to Base64 (safe for QR readers/OpenCV).
  5. Generates the QR code, respecting the Version limit (Max 26).
"""

import argparse
import cbor2
import zlib
import sys
import base64
from pathlib import Path
from typing import Tuple, Optional

# Cryptography and QR libraries
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
import segno

# --- CONFIGURATION ---
# Version 26 limit ensures the QR code isn't too dense for printing/scanning.
MAX_QR_VERSION = 26  
# Error correction levels to try (from lowest to highest)
ERROR_LEVELS = ("L", "M", "Q", "H") 

def print_debug(label, data, is_text=False):
    """
    Helper function for verbose debug printing.
    In this version, it DOES NOT TRUNCATE data. It shows every byte.
    """
    print(f"\n[DEBUG] --- {label} ---")
    if data is None:
        print(" [None]")
        return
    
    size = len(data)
    print(f" Size: {size} bytes/chars")
    
    if is_text:
        # Print FULL text (No truncation)
        print(f" Content:\n{data}")
    else:
        # Print FULL Hex Dump
        hex_str = data.hex()
        # Format nicely in rows of 32 bytes (64 hex chars) for readability
        chunk_size = 64 
        for i in range(0, len(hex_str), chunk_size):
            row = hex_str[i:i+chunk_size]
            formatted = " ".join([row[j:j+2] for j in range(0, len(row), 2)])
            print(f" Hex: {formatted}")

def load_priv(path: Path):
    """Loads Ed25519 private key from a PEM file."""
    if not path.exists():
        raise FileNotFoundError(f"Key file not found: {path}")
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def load_cbor_cert(path: Path):
    """Loads certificate (map and signature) from a CBOR file."""
    if not path.exists():
        raise FileNotFoundError(f"Certificate file not found: {path}")
    data = path.read_bytes()
    try:
        env = cbor2.loads(data)
    except Exception as e:
        raise RuntimeError(f"Failed to decode CBOR cert: {e}")
    
    # Structure check
    if not isinstance(env, dict) or "cert" not in env or "sig" not in env:
        raise RuntimeError("Invalid CBOR structure (missing 'cert' or 'sig' fields)")
    
    return env["cert"], env["sig"]

def find_optimal_qr(data_content: str, max_version=MAX_QR_VERSION):
    """
    Finds the smallest QR version that fits the data without exceeding max_version.
    It iterates through Error Correction levels (L, M, Q, H) to find the best fit.
    """
    best_qr = None
    best_ec = None

    for ec in ERROR_LEVELS:
        try:
            # Create QR in memory
            qr = segno.make(data_content, error=ec)
            
            # Check if version fits within limit
            if qr.version <= max_version:
                if best_qr is None:
                    # First valid result
                    best_qr = qr
                    best_ec = ec
                elif qr.version < best_qr.version:
                    # Found a smaller (better) version
                    best_qr = qr
                    best_ec = ec
                elif qr.version == best_qr.version:
                    # Same version, but prefer higher error correction
                    pref = {'H': 4, 'Q': 3, 'M': 2, 'L': 1}
                    if pref[ec] > pref[best_ec]:
                        best_qr = qr
                        best_ec = ec
        except Exception:
            continue
            
    return best_qr, best_ec

def fits_within_limit(payload: bytes, app_priv, cert_map, cert_sig, max_ver, try_compress, debug=False):
    """
    Core Logic: Sign -> Pack -> Compress -> Base64 -> Fit QR.
    Returns tuple: (success, is_compressed, qr_object, raw_data, ec_level)
    """
    
    # STEP 1: Sign the Payload
    # This guarantees the message content hasn't been altered.
    payload_sig = app_priv.sign(payload)
    
    container = {
        "payload": payload,       # The actual message
        "payload_sig": payload_sig, # Signature of the message
        "cert": cert_map,         # App's Public Certificate
        "cert_sig": cert_sig      # Signature of the Cert (by Root CA)
    }
    
    # STEP 2: CBOR Serialization (Binary format)
    raw_cbor = cbor2.dumps(container)
    if debug:
        print_debug("Step 1: Raw CBOR Structure (Bytes)", raw_cbor)

    # STEP 3: ZLIB Compression (Optional but recommended)
    if try_compress:
        data_to_encode = zlib.compress(raw_cbor, level=9)
        is_compressed = True
        if debug:
            print_debug("Step 2: ZLIB Compressed (Bytes)", data_to_encode)
            ratio = len(data_to_encode)/len(raw_cbor)
            print(f" Compression Ratio: {ratio:.2f} ({(1-ratio)*100:.1f}% smaller)")
    else:
        data_to_encode = raw_cbor
        is_compressed = False
        if debug:
            print("[DEBUG] Compression skipped (--no-compress flag)")

    # STEP 4: Base64 Encoding
    # Converts binary "garbage" into safe text that QR readers prefer.
    b64_safe_data = base64.b64encode(data_to_encode).decode('utf-8')
    if debug:
        print_debug("Step 3: Final Base64 String (Text for QR)", b64_safe_data, is_text=True)

    # STEP 5: QR Code Generation
    qr, ec = find_optimal_qr(b64_safe_data, max_ver)
    
    if qr:
        return True, is_compressed, qr, raw_cbor, ec

    return False, False, None, None, None

def main():
    # Argument Parser Setup
    parser = argparse.ArgumentParser(description="Secure QR Code Generator (Ed25519 + Base64)")
    parser.add_argument("--payload", required=True, help="Text to encode OR file path")
    parser.add_argument("--file", action="store_true", help="Treat --payload as a file path")
    parser.add_argument("--app-priv", required=True, help="Path to App Private Key (PEM)")
    parser.add_argument("--cert-cbor", required=True, help="Path to App Certificate (CBOR)")
    parser.add_argument("--out", default="secure_qr", help="Output filename base (no extension)")
    parser.add_argument("--no-compress", action="store_true", help="Disable ZLIB compression")
    parser.add_argument("--debug", action="store_true", help="Show detailed logs and full data dumps")
    
    args = parser.parse_args()

    # Load Keys
    try:
        app_priv = load_priv(Path(args.app_priv))
        cert_map, cert_sig = load_cbor_cert(Path(args.cert_cbor))
    except Exception as e:
        print(f"[ERROR] Failed to load keys: {e}")
        sys.exit(1)

    # Read Input Payload
    if args.file:
        p_path = Path(args.payload)
        if not p_path.exists():
            print(f"[ERROR] File {args.payload} does not exist.")
            sys.exit(1)
        payload_bytes = p_path.read_bytes()
        print(f"Read {len(payload_bytes)} bytes from file.")
    else:
        payload_bytes = args.payload.encode("utf-8")

    if args.debug:
        print_debug("Input Payload", payload_bytes)

    # Main Generation Process
    print("Generating QR structure (Base64 Format)...")
    
    fits, compressed, qr, final_bin_data, ec = fits_within_limit(
        payload_bytes, 
        app_priv, 
        cert_map, 
        cert_sig, 
        max_ver=MAX_QR_VERSION,
        try_compress=not args.no_compress,
        debug=args.debug
    )

    # Handle "Data Too Large" Error
    if not fits:
        print(f"\n[CRITICAL ERROR] Data is too large!")
        print(f"Could not fit data into QR Version <= {MAX_QR_VERSION}.")
        print("Suggestions:")
        print(" 1. Reduce the payload size.")
        print(" 2. Ensure compression is enabled (remove --no-compress).")
        sys.exit(1)

    # Save Image
    out_img = f"{args.out}.png"
    # scale=8 provides high quality, border=4 is standard quiet zone
    qr.save(out_img, scale=8, border=4, dark="black", light="white")

    # Summary Block
    print("\n" + "="*65)
    print(" SUCCESS - QR CODE GENERATED")
    print("="*65)
    print(f" Output File:       {out_img}")
    print("-" * 65)
    print(f" QR Version:        {qr.version} (Max limit: {MAX_QR_VERSION})")
    print(f" Error Correction:  {ec}")
    print(f" Encoding:          Base64 (Safe for Cameras)")
    print(f" Compression:       {'YES (ZLIB)' if compressed else 'NO'}")
    print(f" Raw Data Size:     {len(final_bin_data)} bytes (before Base64)")
    print("="*65)

if __name__ == "__main__":
    main()