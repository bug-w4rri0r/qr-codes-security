#!/usr/bin/env python3
"""
ED25519 Signed QR Code Generator (Fixed & Optimized)

This script creates cryptographically signed QR codes that embed:
  - Payload (user data)
  - Payload signature (Ed25519 digital signature)
  - COSE-like certificate (CBOR format)
  - Certificate signature (Ed25519 digital signature)

All data is CBOR-encoded and packed into a minimal QR code (limit Version 26).
"""

import argparse
import cbor2
import zlib
import sys
from pathlib import Path
from typing import Tuple, Optional, Union
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
import segno

# Configuration
MAX_QR_VERSION = 26
# Priority: Try strongest error correction first if size permits,
# but usually we want to fit data, so we might fallback to L.
# However, for finding the *limit*, we usually check L (High Capacity).
ERROR_LEVELS = ("L", "M", "Q", "H") 

def load_priv(path: Path):
    """Load Ed25519 private key from PEM file."""
    if not path.exists():
        raise FileNotFoundError(f"Key file not found: {path}")
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def load_cbor_cert(path: Path):
    """Load CBOR certificate file."""
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

def find_optimal_qr(data_bytes: bytes, max_version=MAX_QR_VERSION) -> Tuple[Optional[segno.QRCode], Optional[str]]:
    """
    Tries to find the smallest QR version (<= max_version) that fits the data.
    Returns (qr_object, error_level) or (None, None).
    """
    best_qr = None
    best_ec = None

    # We iterate over error levels to see what fits.
    # L = Most Capacity, H = Most Robustness.
    # We want to find *any* fit, preferably with higher EC if version stays same.
    for ec in ERROR_LEVELS:
        try:
            # encoding='binary' is CRITICAL for CBOR/Zlib data
            qr = segno.make(data_bytes, error=ec, encoding='binary')
            
            if qr.version <= max_version:
                # Logic: If we haven't found a fit yet, take this one.
                # If we found a fit, prefer the one with smaller version.
                # If versions are equal, prefer higher error correction.
                if best_qr is None:
                    best_qr = qr
                    best_ec = ec
                elif qr.version < best_qr.version:
                    best_qr = qr
                    best_ec = ec
                elif qr.version == best_qr.version:
                    # Preference: H > Q > M > L
                    pref = {'H': 4, 'Q': 3, 'M': 2, 'L': 1}
                    if pref[ec] > pref[best_ec]:
                        best_qr = qr
                        best_ec = ec
        except Exception:
            # DataOverflow usually
            continue

    return best_qr, best_ec

def pack_data(payload: bytes, app_priv, cert_map, cert_sig) -> bytes:
    """Signs payload and packs everything into CBOR container."""
    payload_sig = app_priv.sign(payload)
    container = {
        "payload": payload,
        "payload_sig": payload_sig,
        "cert": cert_map,
        "cert_sig": cert_sig
    }
    return cbor2.dumps(container)

def fits_within_limit(payload: bytes, app_priv, cert_map, cert_sig, max_ver=MAX_QR_VERSION, try_compress=True):
    """
    Checks if data fits in QR. Returns tuple:
    (fits: bool, used_compress: bool, qr_obj, final_bytes)
    """
    # 1. Try Raw CBOR
    raw_cbor = pack_data(payload, app_priv, cert_map, cert_sig)
    qr, ec = find_optimal_qr(raw_cbor, max_ver)
    
    if qr:
        return True, False, qr, raw_cbor

    # 2. Try Compressed (if allowed)
    if try_compress:
        compressed = zlib.compress(raw_cbor, level=9)
        qr_c, ec_c = find_optimal_qr(compressed, max_ver)
        if qr_c:
            return True, True, qr_c, compressed

    return False, False, None, None

def calculate_max_payload(app_priv, cert_map, cert_sig, limit=1500):
    """Binary search to find max payload size in bytes."""
    low = 0
    high = limit
    best = 0
    
    while low <= high:
        mid = (low + high) // 2
        dummy_payload = b'A' * mid # Dummy data
        fits, _, _, _ = fits_within_limit(dummy_payload, app_priv, cert_map, cert_sig, try_compress=True)
        
        if fits:
            best = mid
            low = mid + 1
        else:
            high = mid - 1
    return best

def main():
    parser = argparse.ArgumentParser(description="Create Ed25519-signed QR codes (v26 limit)")
    parser.add_argument("--payload", required=True, help="Text to encode or file path")
    parser.add_argument("--file", action="store_true", help="Read payload from file path")
    parser.add_argument("--app-priv", required=True, help="App private key (PEM)")
    parser.add_argument("--cert-cbor", required=True, help="Certificate file (CBOR)")
    parser.add_argument("--out", default="secure_qr", help="Output filename base (no extension)")
    parser.add_argument("--no-compress", action="store_true", help="Disable ZLIB compression")
    parser.add_argument("--calc-limit", action="store_true", help="Calculate max payload size and exit")
    
    args = parser.parse_args()

    # 1. Load Keys
    try:
        app_priv = load_priv(Path(args.app_priv))
        cert_map, cert_sig = load_cbor_cert(Path(args.cert_cbor))
    except Exception as e:
        print(f"Error loading keys/certs: {e}")
        sys.exit(1)

    # 2. Optional: Calculate Limit
    if args.calc_limit:
        print("Calculating max payload size for Version 26...")
        limit = calculate_max_payload(app_priv, cert_map, cert_sig)
        print(f"Max payload size: ~{limit} bytes")
        sys.exit(0)

    # 3. Read Payload
    if args.file:
        p_path = Path(args.payload)
        if not p_path.exists():
            print(f"Error: File {args.payload} not found.")
            sys.exit(1)
        payload_bytes = p_path.read_bytes()
        print(f"Read {len(payload_bytes)} bytes from file.")
    else:
        payload_bytes = args.payload.encode("utf-8")
        print(f"Encoding text payload ({len(payload_bytes)} bytes).")

    # 4. Generate QR
    print("Generating QR structure...")
    fits, compressed, qr, final_data = fits_within_limit(
        payload_bytes, 
        app_priv, 
        cert_map, 
        cert_sig, 
        try_compress=not args.no_compress
    )

    if not fits:
        print("\n[ERROR] Data too large for QR Version 26!")
        print("Try shortening the payload or enabling compression.")
        sys.exit(1)

    # 5. Save Outputs
    out_img = f"{args.out}.png"
    out_bin = f"{args.out}.bin"

    # Scale 10 ensures good readability
    qr.save(out_img, scale=10, border=4, dark="black", light="white")
    Path(out_bin).write_bytes(final_data)

    print("\n" + "="*40)
    print("SUCCESS")
    print("="*40)
    print(f"QR Version:      {qr.version}")
    print(f"Error Correction: {qr.error}")
    print(f"Compression:     {'YES (zlib)' if compressed else 'NO'}")
    print(f"Data Size:       {len(final_data)} bytes")
    print("-" * 20)
    print(f"Image saved to:  {out_img}")
    print(f"Raw data saved:  {out_bin}")
    print("="*40)

if __name__ == "__main__":
    main()