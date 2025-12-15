#!/usr/bin/env python3
"""
ED25519 Signed QR Code Generator (Base64 Safe Version + Debug)
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
MAX_QR_VERSION = 26  # Ograniczenie do wersji drukowalnej/webowej
ERROR_LEVELS = ("L", "M", "Q", "H") 

def print_debug(label, data, is_text=False):
    """Helper for nice debug printing"""
    print(f"\n[DEBUG] --- {label} ---")
    if data is None:
        print(" [None]")
        return
    
    size = len(data)
    print(f" Size: {size} bytes/chars")
    
    if is_text:
        print(f" Content (preview): {data[:100]!r}" + ("..." if size > 100 else ""))
    else:
        # Simple Hex Dump
        hex_str = data.hex()
        # Print max 64 bytes for readability
        preview = hex_str[:128] 
        formatted = " ".join([preview[i:i+2] for i in range(0, len(preview), 2)])
        print(f" Hex: {formatted}" + ("..." if len(hex_str) > 128 else ""))

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
    if not isinstance(env, dict) or "cert" not in env or "sig" not in env:
        raise RuntimeError("Invalid COSE-cert CBOR file structure")
    return env["cert"], env["sig"]

def find_optimal_qr(data_content: str, max_version=MAX_QR_VERSION) -> Tuple[Optional[segno.QRCode], Optional[str]]:
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
                    # Prefer higher error correction if version is same
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
        print_debug("Step 1: Raw CBOR Structure", raw_cbor)

    # 3. Compress (Optional)
    if try_compress:
        data_to_encode = zlib.compress(raw_cbor, level=9)
        is_compressed = True
        if debug:
            print_debug("Step 2: ZLIB Compressed", data_to_encode)
            print(f" Compression Ratio: {len(data_to_encode)/len(raw_cbor):.2f}")
    else:
        data_to_encode = raw_cbor
        is_compressed = False
        if debug:
            print("[DEBUG] Skipping compression")

    # 4. Base64 Encode
    b64_safe_data = base64.b64encode(data_to_encode).decode('utf-8')
    if debug:
        print_debug("Step 3: Base64 Final String", b64_safe_data, is_text=True)

    # 5. Fit QR
    qr, ec = find_optimal_qr(b64_safe_data, max_ver)
    
    if qr:
        return True, is_compressed, qr, raw_cbor, ec

    return False, False, None, None, None

def main():
    parser = argparse.ArgumentParser(description="Create Base64-Safe Ed25519 QR codes")
    parser.add_argument("--payload", required=True, help="Text to encode or file path")
    parser.add_argument("--file", action="store_true", help="Treat payload as file path")
    parser.add_argument("--app-priv", required=True, help="App private key (PEM)")
    parser.add_argument("--cert-cbor", required=True, help="Certificate file (CBOR)")
    parser.add_argument("--out", default="secure_qr", help="Output filename base")
    parser.add_argument("--no-compress", action="store_true", help="Disable ZLIB")
    parser.add_argument("--debug", action="store_true", help="Show detailed debug info")
    
    args = parser.parse_args()

    # Load Keys
    try:
        app_priv = load_priv(Path(args.app_priv))
        cert_map, cert_sig = load_cbor_cert(Path(args.cert_cbor))
    except Exception as e:
        print(f"Error loading keys: {e}")
        sys.exit(1)

    # Read Payload
    if args.file:
        p_path = Path(args.payload)
        if not p_path.exists():
            print(f"Error: File {args.payload} not found.")
            sys.exit(1)
        payload_bytes = p_path.read_bytes()
        print(f"Read {len(payload_bytes)} bytes from file.")
    else:
        payload_bytes = args.payload.encode("utf-8")

    if args.debug:
        print_debug("Input Payload", payload_bytes)

    # Generate
    print("Generating QR structure (Base64 Encoded)...")
    
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
        print(f"\n[ERROR] Data too large for QR Version <= {MAX_QR_VERSION}!")
        print("Try reducing payload size or enabling compression.")
        sys.exit(1)

    out_img = f"{args.out}.png"
    # Scale: 5 is usually enough for printing, 10 is very high quality
    qr.save(out_img, scale=8, border=4, dark="black", light="white")

    print("\n" + "="*40)
    print("SUCCESS")
    print("="*40)
    print(f"QR Version:       {qr.version} (Max allowed: {MAX_QR_VERSION})")
    print(f"Error Correction: {ec}")
    print(f"Encoding:         Base64 (Safe for OpenCV)")
    print(f"Compression:      {'YES' if compressed else 'NO'}")
    print(f"Raw Data Size:    {len(final_bin_data)} bytes")
    print("-" * 20)
    print(f"Image saved to:   {out_img}")
    print("="*40)

if __name__ == "__main__":
    main()