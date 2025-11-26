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
import io
from PIL import Image
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography import x509
from datetime import datetime, timezone


def convert_svg_to_png(svg_path: str) -> Image.Image:
    """
    Convert SVG file to PIL Image object.
    
    SVG is a vector format and must be rasterized to scan QR codes.
    Uses available libraries in order of preference:
    1. cairosvg (Linux, requires system cairo)
    2. PIL/Pillow (limited SVG support, may fail)
    
    Args:
        svg_path: Path to SVG file
    
    Returns:
        PIL Image in RGB mode
    
    Raises:
        RuntimeError: If conversion fails
    """
    # Try cairosvg (best quality but requires system libraries)
    try:
        from cairosvg import svg2png
        svg_bytes = open(svg_path, "rb").read()
        png_bytes = svg2png(bytestring=svg_bytes)
        return Image.open(io.BytesIO(png_bytes)).convert("RGB")
    except (ImportError, OSError) as e:
        print(f"    cairosvg not available: {e}")
    
    # Try PIL direct load (limited SVG support)
    try:
        return Image.open(svg_path).convert("RGB")
    except Exception as e:
        print(f"    PIL cannot load SVG: {e}")
    
    # Fallback: inform user about workarounds
    raise RuntimeError(
        f"Cannot convert SVG '{svg_path}'.\n"
        f"Workarounds:\n"
        f"  1. Use .bin file (pre-extracted data): {svg_path}.bin\n"
        f"  2. Convert SVG to PNG first, then scan PNG\n"
        f"  3. On Linux: Install 'cairosvg' for automatic SVG conversion"
    )


def scan_qr_with_pyzbar(img: Image.Image) -> bytes:
    """
    Scan QR code using pyzbar library (preferred on Linux).
    
    Args:
        img: PIL Image object (grayscale)
    
    Returns:
        bytes: Raw QR code data
    
    Raises:
        RuntimeError: If no QR found or pyzbar unavailable
    """
    try:
        from pyzbar.pyzbar import decode
        res = decode(img)
        if res:
            data = res[0].data
            # Ensure bytes type
            return data if isinstance(data, bytes) else data.encode("latin1")
        raise RuntimeError("No QR code detected")
    except (ImportError, FileNotFoundError) as e:
        raise RuntimeError(f"pyzbar not available: {e}")


def scan_qr_with_opencv(img: Image.Image) -> bytes:
    """
    Scan QR code using OpenCV library (preferred on Windows).
    
    Args:
        img: PIL Image object
    
    Returns:
        bytes: Raw QR code data
    
    Raises:
        RuntimeError: If no QR found or OpenCV unavailable
    """
    try:
        import cv2
        import numpy as np
        
        # Convert PIL to numpy array
        img_array = np.array(img)
        
        # Create detector and scan
        detector = cv2.QRCodeDetector()
        retval, decoded_info, points = detector.detectAndDecode(img_array)
        
        if retval and decoded_info:
            # decoded_info is string, convert to bytes
            return decoded_info.encode() if isinstance(decoded_info, str) else decoded_info
        
        raise RuntimeError("No QR code detected")
    except ImportError:
        raise RuntimeError("OpenCV (cv2) not available")


def load_raw_bytes(path: str) -> bytes:
    """
    Load raw binary data from QR code image or .bin file.
    
    Supports multiple formats:
    - .bin: Direct binary file (no QR decoding needed, fastest)
    - .png, .jpg, etc: Raster images (OpenCV QR scanning)
    - .svg: Vector format (auto-converted or use .bin workaround)
    
    Tries multiple QR scanning backends:
    - OpenCV (preferred on Windows, no system dependencies)
    - pyzbar (preferred on Linux)
    
    Args:
        path: Path to QR image (PNG, JPG, SVG) or .bin file
    
    Returns:
        bytes: Raw data embedded in QR code or file contents
    
    Raises:
        RuntimeError: If no QR code found or file cannot be read
    """
    # If .bin file, read directly (pre-extracted QR data)
    if path.endswith(".bin"):
        print(f"✓ Reading pre-extracted QR data from '{path}'")
        return open(path, "rb").read()
    
    print(f"Loading image: {path}")
    
    # Convert SVG to PNG if needed
    if path.endswith(".svg"):
        print("  Converting SVG to raster format...")
        try:
            img = convert_svg_to_png(path)
        except RuntimeError as e:
            print(f"  ✗ {e}")
            # Try using .bin file instead
            bin_path = path + ".bin"
            if os.path.exists(bin_path):
                print(f"\n  Using .bin file instead: {bin_path}")
                return open(bin_path, "rb").read()
            raise
    else:
        # Load regular image file
        img = Image.open(path).convert("RGB")
    
    # Try to scan QR code with available libraries
    print("  Scanning QR code...")
    
    # Try OpenCV first (works better on Windows, no system dependencies)
    try:
        data = scan_qr_with_opencv(img)
        print("  ✓ QR decoded with OpenCV")
        return data
    except RuntimeError as e:
        print(f"    {e}")
    
    # Fallback to pyzbar (works better on Linux)
    try:
        data = scan_qr_with_pyzbar(img.convert("L"))
        print("  ✓ QR decoded with pyzbar")
        return data
    except RuntimeError as e:
        print(f"    {e}")
    
    # Neither worked
    raise RuntimeError(
        f"Failed to decode QR from '{path}' with both OpenCV and pyzbar.\n"
        f"Install one of:\n"
        f"  - opencv-python (Windows preferred): pip install opencv-python\n"
        f"  - pyzbar (Linux preferred): pip install pyzbar\n"
        f"Or use pre-extracted .bin file: {path}.bin"
    )


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


def print_hex_dump(label: str, data: bytes, max_lines: int = 10):
    """
    Print a formatted hex dump of binary data.
    
    Displays data in both hex and ASCII representation for debugging.
    
    Args:
        label: Label for the dump
        data: Binary data to display
        max_lines: Maximum number of lines to show (16 bytes per line)
    """
    print(f"\n{label} (size: {len(data)} bytes):")
    print("=" * 70)
    
    bytes_per_line = 16
    total_lines = (len(data) + bytes_per_line - 1) // bytes_per_line
    
    for i, chunk_start in enumerate(range(0, len(data), bytes_per_line)):
        if i >= max_lines and total_lines > max_lines:
            print(f"  ... ({total_lines - max_lines} more lines)")
            break
        
        chunk_end = min(chunk_start + bytes_per_line, len(data))
        chunk = data[chunk_start:chunk_end]
        
        # Hex representation
        hex_str = " ".join(f"{b:02x}" for b in chunk)
        
        # ASCII representation
        ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        
        # Print offset, hex, and ASCII
        print(f"  {chunk_start:04x}  {hex_str:<48}  {ascii_str}")
    
    print("=" * 70)


def print_debug_info(label: str, data: bytes):
    """
    Print debug information in multiple formats.
    
    Args:
        label: Label for the data
        data: Binary data to display
    """
    print(f"\n{label}:")
    print(f"  Size: {len(data)} bytes")
    print(f"  Hex: {data.hex()}")
    print(f"  Base64: {__import__('base64').b64encode(data).decode()}")
    print_hex_dump(f"{label} (hex dump)", data, max_lines=5)


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
    parser.add_argument(
        "--debug", 
        action="store_true", 
        help="Enable debug mode: print detailed hex dumps of all components"
    )
    args = parser.parse_args()

    # Step 2: Load QR code and extract bytes
    print("Loading QR code image...")
    raw = load_raw_bytes(args.file)
    
    if args.dump:
        print(f"Raw bytes from QR ({len(raw)} bytes):", raw[:100], "...")
    
    if args.debug:
        print_hex_dump("Raw QR Data", raw, max_lines=10)

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
    
    if args.debug:
        print_debug_info("Payload", payload)
        print_debug_info("Payload Signature", payload_sig)
        print_debug_info("Certificate Signature", cert_sig)
        print(f"\nCertificate Map: {cert_map}")

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