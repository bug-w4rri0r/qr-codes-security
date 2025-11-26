#!/usr/bin/env python3
"""
ED25519 Signed QR Code Generator

This script creates cryptographically signed QR codes that embed:
  - Payload (user data)
  - Payload signature (Ed25519 digital signature)
  - COSE-like certificate (CBOR format)
  - Certificate signature (Ed25519 digital signature)

All data is CBOR-encoded and packed into a minimal QR code.

Requirements:
  - Application private key in PEM format (Ed25519 recommended)
  - COSE certificate file (CBOR) from create_cose_cert.py with structure:
      { "cert": { ... certificate data ... }, "sig": b"...signature..." }

Behavior:
  - Calculates maximum payload size that fits in QR version <= 26
  - Uses binary search to find the limit
  - Attempts to pack data into the smallest QR version possible
  - Tries error-correction levels in order: L, M, Q, H (L has highest capacity)
  - If raw CBOR doesn't fit, tries zlib compression (level=9)
  - Outputs both PNG (visual QR) and .bin file (raw embedded bytes)
"""

import argparse
import cbor2
import zlib
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
import segno

# Error-correction levels: try L first (largest capacity), then M, Q, H
ERROR_LEVELS = ("L", "M", "Q", "H")
MAX_QR_VERSION = 26


def load_priv(path: Path):
    """
    Load a private key from PEM file.
    
    Args:
        path: Path to PEM-encoded private key file
    
    Returns:
        Private key object (Ed25519PrivateKey or other supported type)
    """
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def load_cbor_cert(path: Path):
    """
    Load a COSE-like certificate envelope from CBOR file.
    
    The CBOR file must contain: { "cert": {...}, "sig": b"..." }
    
    Args:
        path: Path to CBOR certificate file
    
    Returns:
        tuple: (certificate_dict, certificate_signature_bytes)
    
    Raises:
        RuntimeError: If CBOR structure is invalid
    """
    data = path.read_bytes()
    env = cbor2.loads(data)
    if not isinstance(env, dict) or "cert" not in env or "sig" not in env:
        raise RuntimeError("Invalid COSE-cert CBOR file: missing 'cert' or 'sig' fields")
    return env["cert"], env["sig"]


def try_make_qr_for_versions(data_bytes: bytes, max_version=MAX_QR_VERSION):
    """
    Attempt to create a QR code with increasing versions and error levels.
    
    Tries QR versions 1 through max_version, and for each version tries
    error-correction levels in ERROR_LEVELS order.
    
    Args:
        data_bytes: Binary data to encode in QR
        max_version: Maximum QR version to attempt (default: 26)
    
    Returns:
        tuple: (qr_object, version, error_correction_level) on success
               (None, None, None) on failure
    """
    # Iterate through QR versions from smallest to largest
    for v in range(1, max_version + 1):
        # For each version, try error correction levels (L = highest capacity)
        for ec in ERROR_LEVELS:
            try:
                # Create QR with binary encoding (not text encoding)
                qr = segno.make(data_bytes, error=ec, encoding="binary", version=v)
                return qr, v, ec
            except Exception:
                # DataOverflow or other error -> try next error level or version
                continue
    
    # If we get here, data doesn't fit in any version
    return None, None, None


def fits_within_limit(payload_bytes: bytes, app_priv, cert_map, cert_sig, max_version=MAX_QR_VERSION, compress_try=True):
    """
    Test if payload fits in a QR code by building complete container and attempting encoding.
    
    Steps:
    1. Sign the payload with application private key
    2. Build CBOR container with payload, signature, certificate, and cert signature
    3. Try to create QR from raw CBOR bytes
    4. If that fails and compress_try=True, compress with zlib and retry
    
    Args:
        payload_bytes: The actual data to be signed and packed
        app_priv: Application private key (for signing)
        cert_map: Certificate dictionary
        cert_sig: Certificate signature bytes
        max_version: Maximum QR version to attempt
        compress_try: Whether to attempt zlib compression if raw doesn't fit
    
    Returns:
        tuple: (fits: bool, used_compression: bool, qr_object, version, error_level)
    """
    # Step 1: Sign the payload with application private key
    payload_sig = app_priv.sign(payload_bytes)

    # Step 2: Build container with all components
    container = {
        "payload": payload_bytes,           # User data
        "payload_sig": payload_sig,         # Signature of user data
        "cert": cert_map,                   # Certificate structure
        "cert_sig": cert_sig                # Signature of certificate
    }

    # Step 3: CBOR-encode the complete container
    cbor_bytes = cbor2.dumps(container)

    # Try raw CBOR first
    qr, v, ec = try_make_qr_for_versions(cbor_bytes, max_version=max_version)
    if qr is not None:
        return True, False, qr, v, ec

    # Step 4: If raw doesn't fit, try compression
    if compress_try:
        compressed = zlib.compress(cbor_bytes, level=9)  # level=9 for maximum compression
        qr, v, ec = try_make_qr_for_versions(compressed, max_version=max_version)
        if qr is not None:
            return True, True, qr, v, ec

    # Neither raw nor compressed fits
    return False, False, None, None, None


def find_max_payload_size(app_priv, cert_map, cert_sig, limit, max_version=MAX_QR_VERSION):
    """
    Find maximum payload size (bytes) that fits in QR version <= max_version using binary search.
    
    Algorithm:
    - Uses binary search between 0 and 'limit'
    - Tests with dummy payloads of repeated 'A' characters
    - Returns the largest payload size that can be packed
    
    Args:
        app_priv: Application private key
        cert_map: Certificate dictionary
        cert_sig: Certificate signature
        limit: Upper bound for binary search (e.g., 300 bytes)
        max_version: Maximum QR version to use
    
    Returns:
        int: Maximum payload size in bytes (>= 0)
    """
    lo = 0
    hi = limit
    best = 0

    # Binary search: find largest payload that fits
    while lo <= hi:
        mid = (lo + hi) // 2
        # Create test payload of N bytes (filled with 'A')
        test_payload = b"A" * mid
        # Try to fit this payload
        ok, used_comp, qr, v, ec = fits_within_limit(test_payload, app_priv, cert_map, cert_sig, max_version)
        
        if ok:
            # This size fits, try larger
            best = mid
            lo = mid + 1
        else:
            # This size doesn't fit, try smaller
            hi = mid - 1

    return best


def main():
    """
    Main entry point for QR code generation.
    
    Steps:
    1. Parse command line arguments
    2. Load application private key and certificate
    3. Calculate maximum possible payload size (binary search)
    4. Read actual payload (text or file)
    5. Validate payload size against maximum
    6. Build and encode complete container
    7. Create QR code with optimal version and error correction
    8. Save PNG image and raw binary data
    """
    # Step 1: Define and parse command line arguments
    parser = argparse.ArgumentParser(
        description="Create Ed25519-signed QR codes with embedded CBOR certificate"
    )
    parser.add_argument(
        "--payload", 
        required=True, 
        help="Payload text or path to file (when --file flag is used)"
    )
    parser.add_argument(
        "--file", 
        action="store_true", 
        help="Treat --payload as path to a binary or text file"
    )
    parser.add_argument(
        "--app-priv", 
        required=True, 
        help="Path to application private key (PEM format, Ed25519 recommended)"
    )
    parser.add_argument(
        "--cert-cbor", 
        required=True, 
        help="Path to CBOR certificate file (created by create_cose_cert.py)"
    )
    parser.add_argument(
        "--out", 
        default="secure_ed_qr.png", 
        help="Output PNG filename (default: secure_ed_qr.png)"
    )
    parser.add_argument(
        "--max-payload-limit", 
        type=int, 
        default=800, 
        help="""Upper bound for payload size search in bytes (default: 800).
        
QR Code Version 26 Specifications (121x121 modules):
  - Numeric capacity: 1425-3283 digits
  - Alphanumeric capacity: 864-1990 characters  
  - Binary capacity: 593-1367 bytes

Binary capacity range varies by error correction level (L=highest to H=lowest).
With Ed25519 signatures (64B each) + certificate (~150B) + CBOR overhead (~50B),
realistic max payload: ~200-987 bytes depending on error correction level."""
    )
    parser.add_argument(
        "--no-compress", 
        action="store_true", 
        help="Disable zlib compression if raw CBOR doesn't fit in QR"
    )
    args = parser.parse_args()

    # Step 2: Load application private key and certificate
    print("Loading application private key...")
    app_priv = load_priv(Path(args.app_priv))
    print("Loading COSE certificate...")
    cert_map, cert_sig = load_cbor_cert(Path(args.cert_cbor))

    # Step 3: Calculate maximum payload size using binary search
    print("\nCalculating the maximum payload length (bytes) that fits into some QR version <= 26 ...")
    max_payload = find_max_payload_size(app_priv, cert_map, cert_sig, limit=args.max_payload_limit, max_version=MAX_QR_VERSION)
    print(f"Maximum payload length (in bytes) that fits in QR version <= {MAX_QR_VERSION} (search cap {args.max_payload_limit}): {max_payload} bytes")
    print("If your actual payload is longer, it will NOT fit into v<=26 (unless you reduce cert/payload or increase QR max version).")
    print("-----")

    # Step 4: Read actual payload (text or file)
    if args.file:
        print(f"Reading payload from file: {args.payload}")
        payload_bytes = Path(args.payload).read_bytes()
    else:
        payload_bytes = args.payload.encode("utf-8")

    # Step 5: Validate payload size
    print(f"Actual payload size: {len(payload_bytes)} bytes")
    if len(payload_bytes) > args.max_payload_limit:
        print(f"Warning: actual payload length {len(payload_bytes)} exceeds --max-payload-limit {args.max_payload_limit}. The earlier search may not be accurate.")
    if len(payload_bytes) > max_payload:
        print("ERROR: The provided payload is too large to fit into QR v<=26 with the current certificate & signature.")
        print(f"Allowed: {max_payload} bytes, provided: {len(payload_bytes)} bytes")
        return

    # Step 6: Build complete container and encode
    print("\nBuilding QR code...")
    compress_try = not args.no_compress
    ok, used_compression, qr_obj, version, ec = fits_within_limit(payload_bytes, app_priv, cert_map, cert_sig, max_version=MAX_QR_VERSION, compress_try=compress_try)

    if not ok:
        print("ERROR: Payload + certificate + signatures do not fit in any QR version <= 26 (even after compression).")
        return

    # Step 7: Reconstruct exact final bytes for saving (needed because we may use compression)
    payload_sig = app_priv.sign(payload_bytes)
    container = {
        "payload": payload_bytes,
        "payload_sig": payload_sig,
        "cert": cert_map,
        "cert_sig": cert_sig
    }
    cbor_bytes = cbor2.dumps(container)
    
    # Apply compression if it was used to fit in QR
    if used_compression:
        final_bytes = zlib.compress(cbor_bytes, level=9)
    else:
        final_bytes = cbor_bytes

    # Step 8: Save QR code as PNG and raw binary
    print("Saving QR code image...")
    qr_obj.save(args.out, scale=5, dark='black', light='white')
    
    print("Saving raw embedded bytes...")
    Path(args.out + ".bin").write_bytes(final_bytes)

    # Print completion summary
    print("\n✓ QR code successfully created!")
    print(f"Chosen QR version: {version}, error correction level: {ec}, compression used: {used_compression}")
    print(f"Output PNG: {args.out}")
    print(f"Output raw bytes (exact bytes embedded in QR): {args.out}.bin (size {len(final_bytes)} bytes)")


if __name__ == "__main__":
    main()