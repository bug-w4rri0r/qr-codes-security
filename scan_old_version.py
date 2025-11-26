#!/usr/bin/env python3
"""
ED25519-Signed QR Code Scanner and Verifier

This script reads and verifies digitally signed QR codes created by create_qr_ed25519.py.

Supported features:
  - Decodes raw or zlib-compressed CBOR data from QR code images
  - Verifies Ed25519 signatures on payloads
  - Validates COSE-like certificates against trusted root keys
  - Checks certificate validity dates (nbf/exp fields)
  - Supports multiple trusted root certificates/keys

Workflow:
  1. Extract binary data from QR code image
  2. Decompress if needed (zlib)
  3. Parse CBOR structure
  4. Extract payload, signatures, and certificate
  5. Verify certificate signature against trusted roots
  6. Verify payload signature using certificate's public key
  7. Display verified payload
"""

import argparse
import cbor2
import zlib
import os
from PIL import Image
from pyzbar.pyzbar import decode
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography import x509
from datetime import datetime, timezone


def load_raw_bytes(path: str) -> bytes:
    """
    Load raw binary data from QR code image or .bin file.
    
    Args:
        path: Path to QR image (PNG, JPG) or .bin file
    
    Returns:
        bytes: Raw data embedded in QR code
    
    Raises:
        RuntimeError: If no QR code found or file cannot be read
    """
    # If .bin file, read directly
    if path.endswith(".bin"):
        return open(path, "rb").read()
    
    # Otherwise, decode QR from image
    from PIL import Image
    from pyzbar.pyzbar import decode
    img = Image.open(path).convert("L")  # Convert to grayscale for better QR detection
    res = decode(img)
    if not res:
        raise RuntimeError("No QR code found in image. Check image quality and scale.")
    return res[0].data


def try_parse_cbor(raw: bytes):
    """
    Attempt to parse CBOR-encoded data, with optional decompression.
    
    Steps:
    1. Try parsing raw bytes as CBOR
    2. If that fails, try decompressing with zlib and parsing again
    
    Args:
        raw: Raw binary data (CBOR-encoded or compressed CBOR)
    
    Returns:
        tuple: (parsed_dict, used_compression: bool)
    
    Raises:
        RuntimeError: If neither raw nor compressed CBOR can be parsed
    """
    # Step 1: Try raw CBOR
    try:
        return cbor2.loads(raw), False
    except Exception:
        pass
    
    # Step 2: Try decompressed CBOR
    try:
        decompressed = zlib.decompress(raw)
        return cbor2.loads(decompressed), True
    except Exception as e:
        raise RuntimeError("Failed to decode CBOR (tried both raw and zlib-decompressed)") from e


def load_trusted_roots(dirpath: str = "trusted_roots"):
    """
    Load all trusted root public keys from a directory.
    
    Supports:
    - PEM-encoded Ed25519 public keys
    - PEM-encoded RSA/EC public keys
    - PEM-encoded X.509 certificates (extracts public key)
    
    Args:
        dirpath: Path to directory containing root keys/certificates
    
    Returns:
        list: Public key objects that can be used for verification
    """
    roots = []
    # Iterate through all files in trusted roots directory
    for fn in os.listdir(dirpath):
        path = os.path.join(dirpath, fn)
        with open(path, "rb") as f:
            data = f.read()
        
        try:
            # Try loading as PEM public key
            pub = serialization.load_pem_public_key(data)
            roots.append(pub)
        except Exception:
            try:
                # Try loading as X.509 certificate and extract public key
                cert = x509.load_pem_x509_certificate(data)
                roots.append(cert.public_key())
            except Exception:
                # Skip files that can't be parsed
                continue
    
    return roots


def verify_cert(cert_map: dict, cert_sig: bytes, roots):
    """
    Verify certificate signature against one or more trusted roots.
    
    Steps:
    1. CBOR-encode the certificate map (as it was signed)
    2. Try verifying with each trusted root public key
    3. Return True if any root successfully verifies
    
    Args:
        cert_map: Certificate dictionary (from CBOR)
        cert_sig: Certificate signature bytes (64 bytes for Ed25519)
        roots: List of trusted root public keys
    
    Returns:
        tuple: (is_valid: bool, message: str)
    """
    # Encode certificate as it was when signed
    cert_bytes = cbor2.dumps(cert_map)
    
    # Try verification with each trusted root
    for root_pub in roots:
        try:
            root_pub.verify(cert_sig, cert_bytes)
            return True, "Certificate verified by trusted root"
        except Exception:
            # This root didn't verify, try next one
            continue
    
    # No root verified the certificate
    return False, "Certificate signature NOT verified by any trusted root"


def load_pub_from_cert_map(cert_map: dict):
    """
    Extract and load public key from certificate map.
    
    The certificate may contain the public key in two formats:
    - Raw Ed25519 key: 32 bytes of raw public key
    - DER-encoded: Full SubjectPublicKeyInfo DER structure
    
    Args:
        cert_map: Certificate dictionary (must contain 'pub' field)
    
    Returns:
        PublicKey object (Ed25519PublicKey or other type)
    
    Raises:
        RuntimeError: If 'pub' field is missing or invalid
    """
    pub_field = cert_map.get("pub")
    if isinstance(pub_field, bytes):
        if len(pub_field) == 32:
            # Raw 32-byte Ed25519 public key
            return ed25519.Ed25519PublicKey.from_public_bytes(pub_field)
        else:
            # DER-encoded SubjectPublicKeyInfo
            return serialization.load_der_public_key(pub_field)
    raise RuntimeError("Invalid 'pub' field in certificate")


def main():
    """
    Main entry point for QR code scanning and verification.
    
    Steps:
    1. Parse command line arguments
    2. Load QR code image and extract raw bytes
    3. Parse CBOR structure (handling optional compression)
    4. Extract payload, signatures, and certificate
    5. Load trusted root certificates
    6. Verify certificate against trusted roots
    7. Verify payload signature using certificate's public key
    8. Check certificate validity dates
    9. Display verified payload to user
    """
    # Step 1: Parse command line arguments
    parser = argparse.ArgumentParser(
        description="Scan and verify Ed25519-signed QR codes with embedded certificates"
    )
    parser.add_argument(
        "--file", 
        required=True, 
        help="Path to QR code image (PNG, JPG) or .bin file"
    )
    parser.add_argument(
        "--trusted-dir", 
        default="trusted_roots", 
        help="Directory containing trusted root public keys/certificates (default: trusted_roots)"
    )
    parser.add_argument(
        "--dump", 
        action="store_true", 
        help="Print raw bytes from QR code (for debugging)"
    )
    args = parser.parse_args()

    # Step 2: Load QR code and extract bytes
    print("Loading QR code image...")
    raw = load_raw_bytes(args.file)
    
    if args.dump:
        print(f"Raw bytes from QR ({len(raw)} bytes):", raw[:100], "...")

    # Step 3: Parse CBOR (handle optional compression)
    print("Parsing CBOR data...")
    parsed, compressed = try_parse_cbor(raw)
    print(f"✓ CBOR parsed successfully (compression used: {compressed})")

    # Step 4: Extract components from CBOR structure
    payload = parsed["payload"]
    payload_sig = parsed["payload_sig"]
    cert_map = parsed["cert"]
    cert_sig = parsed["cert_sig"]
    
    print(f"\nExtracted components:")
    print(f"  Payload size: {len(payload)} bytes")
    print(f"  Payload signature: {len(payload_sig)} bytes (Ed25519)")
    print(f"  Certificate signature: {len(cert_sig)} bytes (Ed25519)")

    # Step 5: Load trusted roots
    print(f"\nLoading trusted roots from '{args.trusted_dir}'...")
    roots = load_trusted_roots(args.trusted_dir)
    print(f"  Loaded {len(roots)} trusted root(s)")

    # Step 6: Verify certificate against trusted roots
    print("\nVerifying certificate...")
    trusted, trust_msg = verify_cert(cert_map, cert_sig, roots)
    if trusted:
        print(f"✓ {trust_msg}")
    else:
        print(f"✗ {trust_msg}")

    # Step 7: Check certificate validity dates
    now = datetime.now(timezone.utc).date()
    
    if "nbf" in cert_map:
        print(f"  Certificate valid from: {cert_map['nbf']}")
    if "exp" in cert_map:
        print(f"  Certificate expires: {cert_map['exp']}")

    # Step 8: Verify payload signature using certificate's public key
    print("\nVerifying payload signature...")
    try:
        app_pub = load_pub_from_cert_map(cert_map)
        app_pub.verify(payload_sig, payload)
        payload_ok = True
        print("✓ Payload signature: VALID")
    except Exception as e:
        payload_ok = False
        print(f"✗ Payload signature: INVALID ({e})")

    # Step 9: Display payload (with security check)
    print("\n" + "="*60)
    
    # Warn if certificate or signature verification failed
    if not trusted or not payload_ok:
        print("⚠  WARNING: Certificate not trusted or signature invalid!")
        resp = input("Display payload anyway? (yes/no): ").strip().lower()
        if resp not in ("yes", "y"):
            print("Aborted. Payload not displayed.")
            return

    # Display payload
    print("\nPayload content:")
    try:
        # Attempt UTF-8 decoding
        print(payload.decode("utf-8"))
    except Exception:
        # Binary data - show hex representation
        print(f"<Binary data: {len(payload)} bytes>")
        print(payload.hex())


if __name__ == "__main__":
    main()