#!/usr/bin/env python3
"""
scan_qr_ed25519.py

Scan a signed CBOR-based QR code created with create_qr_ed25519.py.
It supports:
  - raw or zlib-compressed CBOR payloads
  - Ed25519 payload signatures
  - COSE-like certificate verification against trusted roots
"""

import argparse
import cbor2
import zlib
import os
import segno
from PIL import Image
from pyzbar.pyzbar import decode
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography import x509
from datetime import datetime, timezone


"""
def decode_qr_image(path: str) -> bytes:
    img = Image.open(path).convert("L")  # convert to grayscale
    res = decode(img)
    if not res:
        raise RuntimeError("No QR code found. Ensure image is not transparent and scale is reasonable.")
    return bytes(res[0].data)
"""

def decode_qr_bytes(path):
    """Odczytuje dokładne bajty z QR w trybie binary."""
    import pyzbar.pyzbar as pyzbar
    img = Image.open(path)
    res = pyzbar.decode(img)
    if not res:
        raise RuntimeError("Brak QR w obrazie lub złe skalowanie")
    #return res[0].data  # dokładne bajty QR
    data = res[0].data
    # pyzbar zwraca już bytes, ale czasem traktuje to jako str
    if isinstance(data, str):
        # zachowaj bajty 1:1
        data = data.encode("latin1")
    return data

"""
def load_raw_bytes(path: str) -> bytes:
    if path.endswith(".bin"):
        # Wczytaj bezpośrednio
        return open(path, "rb").read()
    else:
        # Wczytaj z PNG/QR
        from PIL import Image
        from pyzbar.pyzbar import decode
        img = Image.open(path).convert("L")
        res = decode(img)
        if not res:
            raise RuntimeError("No QR code found")
        return bytes(res[0].data)
"""

def load_raw_bytes(path: str) -> bytes:
    if path.endswith(".bin"):
        return open(path, "rb").read()
    else:
        from PIL import Image
        from pyzbar.pyzbar import decode
        img = Image.open(path).convert("L")
        res = decode(img)
        if not res:
            raise RuntimeError("No QR code found")
        return res[0].data   # <-- zamiast bytes(res[0].data)


def try_parse_cbor(raw: bytes):
    """
    Attempt to parse CBOR from raw bytes.
    If parsing fails, try decompressing with zlib and parsing again.
    Returns (parsed_dict, used_compression: bool)
    """
    try:
        return cbor2.loads(raw), False
    except Exception:
        try:
            dec = zlib.decompress(raw)
            return cbor2.loads(dec), True
        except Exception as e:
            raise RuntimeError("Failed to decode CBOR (raw or decompressed)") from e

def load_trusted_roots(dirpath: str = "trusted_roots"):
    """
    Load all trusted root public keys from the directory.
    Supports PEM public keys and PEM X.509 certificates.
    Returns a list of public key objects.
    """
    roots = []
    for fn in os.listdir(dirpath):
        path = os.path.join(dirpath, fn)
        with open(path, "rb") as f:
            data = f.read()
        try:
            # Try PEM public key
            pub = serialization.load_pem_public_key(data)
            roots.append(pub)
        except Exception:
            try:
                # Try X.509 certificate
                cert = x509.load_pem_x509_certificate(data)
                roots.append(cert.public_key())
            except Exception:
                continue
    return roots

def verify_cert(cert_map: dict, cert_sig: bytes, roots):
    """
    Verify the certificate map signature against trusted roots.
    Returns (True/False, message)
    """
    cert_bytes = cbor2.dumps(cert_map)
    for rpub in roots:
        try:
            rpub.verify(cert_sig, cert_bytes)
            return True, "Certificate verified by trusted root"
        except Exception:
            continue
    return False, "Certificate signature NOT verified by any trusted root"

def load_pub_from_cert_map(cert_map: dict):
    """
    Load Ed25519 public key from certificate map.
    Expects 'pub' field containing either raw 32-byte key or DER-encoded SubjectPublicKeyInfo.
    """
    pub_field = cert_map.get("pub")
    if isinstance(pub_field, bytes):
        if len(pub_field) == 32:
            return ed25519.Ed25519PublicKey.from_public_bytes(pub_field)
        else:
            return serialization.load_der_public_key(pub_field)
    raise RuntimeError("Invalid 'pub' field in certificate")

def main():
    parser = argparse.ArgumentParser(description="Scan Ed25519-signed CBOR QR codes.")
    parser.add_argument("--file", required=True, help="Path to QR code image")
    parser.add_argument("--trusted-dir", default="trusted_roots", help="Directory of trusted root public keys/certs")
    parser.add_argument("--dump", action="store_true", help="Dump raw bytes from QR for debugging")
    args = parser.parse_args()

    # Decode QR
    #raw = decode_qr_image(args.file)
    raw = load_raw_bytes(args.file)

    if args.dump:
        print("Raw bytes from QR:", raw)

    # Parse CBOR
    parsed, compressed = try_parse_cbor(raw)
    print("CBOR parsed successfully (compressed? {})".format(compressed))

    # Extract payload and signatures
    payload = parsed["payload"]
    payload_sig = parsed["payload_sig"]
    cert_map = parsed["cert"]
    cert_sig = parsed["cert_sig"]

    # Load trusted roots and verify certificate
    roots = load_trusted_roots(args.trusted_dir)
    trusted, trust_msg = verify_cert(cert_map, cert_sig, roots)
    print("Certificate trust status:", trusted, "-", trust_msg)

    # Check certificate validity (nbf/exp)
    #now = datetime.utcnow().date()
    now = datetime.now(timezone.utc).date()

    if "nbf" in cert_map:
        print("Certificate valid from:", cert_map["nbf"])
    if "exp" in cert_map:
        print("Certificate expires:", cert_map["exp"])

    # Verify payload signature
    try:
        app_pub = load_pub_from_cert_map(cert_map)
        app_pub.verify(payload_sig, payload)
        payload_ok = True
        print("Payload signature: OK")
    except Exception as e:
        payload_ok = False
        print("Payload signature INVALID:", e)

    # Ask user if payload should be displayed if not trusted
    if not trusted or not payload_ok:
        resp = input("Certificate not trusted or payload signature invalid. Show payload anyway? (yes/no): ").strip().lower()
        if resp not in ("yes", "y"):
            print("Aborted.")
            return

    # Display payload (attempt UTF-8 decoding)
    try:
        print("Payload content:\n", payload.decode("utf-8"))
    except Exception:
        print("<binary data>", len(payload), "bytes")

if __name__ == "__main__":
    main()