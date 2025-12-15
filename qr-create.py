#!/usr/bin/env python3
"""
ED25519 Signed QR Code Generator (Base64 Safe Version)

Changes:
  - Encodes the final CBOR binary blob into Base64 before creating the QR.
  - This ensures standard QR readers (like OpenCV) treat it as text
    and do not truncate null bytes.
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
MAX_QR_VERSION = 40  # Increased limit as Base64 adds ~33% overhead
ERROR_LEVELS = ("L", "M", "Q", "H") 

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
    """Tries to find the smallest QR version that fits the text data."""
    best_qr = None
    best_ec = None

    for ec in ERROR_LEVELS:
        try:
            # Note: We don't force 'binary' encoding here because Base64 is text.
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

def pack_data(payload: bytes, app_priv, cert_map, cert_sig) -> bytes:
    payload_sig = app_priv.sign(payload)
    container = {
        "payload": payload,
        "payload_sig": payload_sig,
        "cert": cert_map,
        "cert_sig": cert_sig
    }
    return cbor2.dumps(container)

def fits_within_limit(payload: bytes, app_priv, cert_map, cert_sig, max_ver=MAX_QR_VERSION, try_compress=True):
    # 1. Create Binary CBOR
    raw_cbor = pack_data(payload, app_priv, cert_map, cert_sig)
    
    # 2. Compress (Optional)
    if try_compress:
        data_to_encode = zlib.compress(raw_cbor, level=9)
        is_compressed = True
    else:
        data_to_encode = raw_cbor
        is_compressed = False

    # 3. CONVERT TO BASE64 (Safe Text)
    # OpenCV loves text. It hates binary null bytes.
    b64_safe_data = base64.b64encode(data_to_encode).decode('utf-8')

    # 4. Fit QR
    qr, ec = find_optimal_qr(b64_safe_data, max_ver)
    
    if qr:
        return True, is_compressed, qr, raw_cbor  # We return raw_cbor just for debug size check

    return False, False, None, None

def main():
    parser = argparse.ArgumentParser(description="Create Base64-Safe Ed25519 QR codes")
    parser.add_argument("--payload", required=True, help="Text to encode or file path")
    parser.add_argument("--file", action="store_true", help="Treat payload as file path")
    parser.add_argument("--app-priv", required=True, help="App private key (PEM)")
    parser.add_argument("--cert-cbor", required=True, help="Certificate file (CBOR)")
    parser.add_argument("--out", default="secure_qr", help="Output filename base")
    parser.add_argument("--no-compress", action="store_true", help="Disable ZLIB")
    
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

    # Generate
    print("Generating QR structure (Base64 Encoded)...")
    fits, compressed, qr, final_bin_data = fits_within_limit(
        payload_bytes, 
        app_priv, 
        cert_map, 
        cert_sig, 
        try_compress=not args.no_compress
    )

    if not fits:
        print("\n[ERROR] Data too large for QR!")
        sys.exit(1)

    out_img = f"{args.out}.png"
    qr.save(out_img, scale=10, border=4, dark="black", light="white")

    print("\n" + "="*40)
    print("SUCCESS")
    print("="*40)
    print(f"QR Version:       {qr.version}")
    print(f"Encoding:         Base64 (Safe for OpenCV)")
    print(f"Compression:      {'YES' if compressed else 'NO'}")
    print(f"Original Size:    {len(final_bin_data)} bytes (Binary)")
    print("-" * 20)
    print(f"Image saved to:   {out_img}")
    print("="*40)

if __name__ == "__main__":
    main()