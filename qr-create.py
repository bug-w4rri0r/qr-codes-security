#!/usr/bin/env python3
"""
ED25519 Signed QR Code Generator (v3.0 - Full Debug / No Truncation)
"""

import argparse
import cbor2
import zlib
import sys
import base64
from pathlib import Path
from typing import Tuple, Optional
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
import segno

# Configuration
MAX_QR_VERSION = 26
ERROR_LEVELS = ("L", "M", "Q", "H") 

def print_debug(label, data, is_text=False):
    """Prints FULL data without truncation."""
    print(f"\n[DEBUG] --- {label} ---")
    if data is None:
        print(" [None]")
        return
    
    size = len(data)
    print(f" Size: {size} bytes/chars")
    
    if is_text:
        # PRINT FULL TEXT (No truncation)
        print(f" Content: {data}")
    else:
        # PRINT FULL HEX DUMP
        hex_str = data.hex()
        # Format nicely in rows of 32 bytes
        chunk_size = 64 # 32 bytes * 2 chars per byte
        for i in range(0, len(hex_str), chunk_size):
            row = hex_str[i:i+chunk_size]
            formatted = " ".join([row[j:j+2] for j in range(0, len(row), 2)])
            print(f" Hex: {formatted}")

def load_priv(path: Path):
    if not path.exists():
        raise FileNotFoundError(f"Key file not found: {path}")
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def load_cbor_cert(path: Path):
    if not path.exists():
        raise FileNotFoundError(f"Certificate file not found: {path}")
    data = path.read_bytes()
    try:
        env = cbor2.loads(data)
    except Exception as e:
        raise RuntimeError(f"Failed to decode CBOR cert: {e}")
    return env["cert"], env["sig"]

def find_optimal_qr(data_content: str, max_version=MAX_QR_VERSION):
    best_qr = None
    best_ec = None

    for ec in ERROR_LEVELS:
        try:
            qr = segno.make(data_content, error=ec)
            if qr.version <= max_version:
                if best_qr is None:
                    best_qr = qr
                    best_ec = ec
                elif qr.version < best_qr.version:
                    best_qr = qr
                    best_ec = ec
                elif qr.version == best_qr.version:
                    pref = {'H': 4, 'Q': 3, 'M': 2, 'L': 1}
                    if pref[ec] > pref[best_ec]:
                        best_qr = qr
                        best_ec = ec
        except Exception:
            continue
    return best_qr, best_ec

def fits_within_limit(payload: bytes, app_priv, cert_map, cert_sig, max_ver, try_compress, debug=False):
    # 1. Sign Payload
    payload_sig = app_priv.sign(payload)
    
    container = {
        "payload": payload,
        "payload_sig": payload_sig,
        "cert": cert_map,
        "cert_sig": cert_sig
    }
    
    # 2. CBOR Encode
    raw_cbor = cbor2.dumps(container)
    if debug:
        print_debug("Step 1: Raw CBOR Structure (Bytes)", raw_cbor)

    # 3. Compress (Optional)
    if try_compress:
        data_to_encode = zlib.compress(raw_cbor, level=9)
        is_compressed = True
        if debug:
            print_debug("Step 2: ZLIB Compressed (Bytes)", data_to_encode)
            print(f" Compression Ratio: {len(data_to_encode)/len(raw_cbor):.2f}")
    else:
        data_to_encode = raw_cbor
        is_compressed = False
        if debug:
            print("[DEBUG] Skipping compression")

    # 4. Base64 Encode
    b64_safe_data = base64.b64encode(data_to_encode).decode('utf-8')
    if debug:
        print_debug("Step 3: Final Base64 String (Text)", b64_safe_data, is_text=True)

    # 5. Fit QR
    qr, ec = find_optimal_qr(b64_safe_data, max_ver)
    
    if qr:
        return True, is_compressed, qr, raw_cbor, ec

    return False, False, None, None, None

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--payload", required=True)
    parser.add_argument("--file", action="store_true")
    parser.add_argument("--app-priv", required=True)
    parser.add_argument("--cert-cbor", required=True)
    parser.add_argument("--out", default="secure_qr")
    parser.add_argument("--no-compress", action="store_true")
    parser.add_argument("--debug", action="store_true")
    
    args = parser.parse_args()

    app_priv = load_priv(Path(args.app_priv))
    cert_map, cert_sig = load_cbor_cert(Path(args.cert_cbor))

    if args.file:
        payload_bytes = Path(args.payload).read_bytes()
    else:
        payload_bytes = args.payload.encode("utf-8")

    if args.debug:
        print_debug("Input Payload", payload_bytes)

    print("Generating QR structure...")
    
    fits, compressed, qr, final_bin_data, ec = fits_within_limit(
        payload_bytes, 
        app_priv, 
        cert_map, 
        cert_sig, 
        max_ver=MAX_QR_VERSION,
        try_compress=not args.no_compress,
        debug=args.debug
    )

    if not fits:
        print(f"[ERROR] Data too large for QR Version <= {MAX_QR_VERSION}!")
        sys.exit(1)

    out_img = f"{args.out}.png"
    qr.save(out_img, scale=8, border=4, dark="black", light="white")

    print("\nSUCCESS")
    print(f"QR Version: {qr.version}, EC: {ec}")
    print(f"Saved to: {out_img}")

if __name__ == "__main__":
    main()