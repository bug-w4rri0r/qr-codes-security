#!/usr/bin/env python3
"""
COSE Certificate Generator

This script creates digitally signed certificates in CBOR (Concise Binary Object Representation) format.
It follows a simplified COSE (CBOR Object Signing and Encryption) pattern.

The workflow:
1. Load the root CA private key (used for signing)
2. Load the application's public key
3. Create a certificate structure with metadata (issuer, subject, algorithm, public key)
4. Sign the certificate with the root private key
5. Save the signed certificate in CBOR format

The resulting certificate can be used to verify the authenticity of QR codes and other data
signed by the application.
"""

import argparse
import cbor2
from datetime import datetime, timezone
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from pathlib import Path


def load_root_priv(path):
    """
    Load and return the root CA private key from a PEM file.
    
    Args:
        path: Path to the PEM-encoded private key file (e.g., root_priv.pem)
    
    Returns:
        Ed25519PrivateKey object used for signing certificates
    """
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def load_pubkey_bytes(pem_path):
    """
    Load a public key from PEM format and extract its raw bytes.
    
    For Ed25519 keys, returns the 32-byte raw public key.
    For other key types, returns the DER-encoded SubjectPublicKeyInfo format.
    
    Args:
        pem_path: Path to the PEM-encoded public key file (e.g., app_pub.pem)
    
    Returns:
        tuple: (public_key_bytes, key_type_string)
               - public_key_bytes: Raw bytes of the public key
               - key_type_string: "ed25519" for Ed25519 keys, "other" for other types
    """
    # Read and parse the PEM public key file
    with open(pem_path, "rb") as f:
        data = f.read()
    
    # Load the public key from PEM format
    pub = serialization.load_pem_public_key(data)
    
    # Try to extract raw bytes (works for Ed25519)
    try:
        # For Ed25519, extract the raw 32-byte representation
        raw = pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
        return raw, "ed25519"
    except Exception:
        # Fallback: return DER-encoded format for other key types
        der = pub.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        return der, "other"


def main():
    """
    Main entry point for certificate generation.
    
    Steps:
    1. Parse command line arguments
    2. Load root CA private key and application public key
    3. Create certificate structure with metadata
    4. Sign the certificate using the root private key
    5. Wrap the certificate and signature in a CBOR envelope
    6. Save the signed certificate to file
    """
    # Step 1: Define and parse command line arguments
    parser = argparse.ArgumentParser(
        description="Generate a COSE-like certificate signed by root CA"
    )
    parser.add_argument(
        "--root-priv", 
        required=True, 
        help="Path to root CA private key (e.g., ../certs_vault/root_priv.pem)"
    )
    parser.add_argument(
        "--iss", 
        default="root", 
        help="Certificate issuer name (e.g., 'PWr-Campus' or 'MyRootCA')"
    )
    parser.add_argument(
        "--sub", 
        required=True, 
        help="Certificate subject (identifier, e.g., 'app-001' or 'mobile-app')"
    )
    parser.add_argument(
        "--pub", 
        required=True, 
        help="Path to application public key (e.g., ../certs_vault/app_pub.pem)"
    )
    parser.add_argument(
        "--not-before", 
        help="Certificate validity start date (YYYY-MM-DD format)", 
        default=None
    )
    parser.add_argument(
        "--not-after", 
        help="Certificate validity end date (YYYY-MM-DD format)", 
        default=None
    )
    parser.add_argument(
        "--out", 
        default="app_cert.cbor",
        help="Output file for the signed certificate (default: app_cert.cbor)"
    )
    args = parser.parse_args()

    # Step 2: Load root CA private key and application public key
    print("Loading root CA private key...")
    root = load_root_priv(args.root_priv)
    
    print(f"Loading application public key from {args.pub}...")
    pub_bytes, ktype = load_pubkey_bytes(args.pub)
    print(f"  Detected key type: {ktype}")

    # Step 3: Create certificate structure with metadata
    print("\nBuilding certificate structure...")
    cert = {
        "iss": args.iss,            # Issuer: Root CA name from CLI argument
        "sub": args.sub,            # Subject: Application identifier
        "alg": "Ed25519",           # Algorithm: Ed25519 signature scheme
        "pub": pub_bytes,           # Public key bytes
    }
    
    # Add optional validity dates if provided
    if args.not_before:
        cert["nbf"] = args.not_before  # Not-Before date
    if args.not_after:
        cert["exp"] = args.not_after   # Expiration date

    # Step 4: Encode certificate and sign it
    print(f"Signing certificate with issuer '{args.iss}'...")
    # CBOR-encode the certificate (without signature)
    cert_no_sig = cbor2.dumps(cert)
    
    # Sign the encoded certificate with Ed25519 private key (produces 64-byte signature)
    sig = root.sign(cert_no_sig)

    # Step 5: Wrap certificate and signature in CBOR envelope
    # NOTE: In your QR creation/reading scripts, the keys expected are often "cert" and "cert_sig".
    # I have updated "sig" to "cert_sig" here to maintain compatibility with your qr-read.py
    envelope = {
        "cert": cert,  # Certificate object
        "cert_sig": sig      # Digital signature (64 bytes for Ed25519)
    }

    # Step 6: Save the signed certificate
    print(f"Saving signed certificate to {args.out}...")
    with open(args.out, "wb") as f:
        f.write(cbor2.dumps(envelope))

    print("\n✓ Certificate generated successfully!")
    print(f"  File: {args.out}")
    print(f"  Issuer: {args.iss}")
    print(f"  Subject: {args.sub}")
    if args.not_before:
        print(f"  Valid From (nbf): {args.not_before}")
    if args.not_after:
        print(f"  Expires (exp): {args.not_after}")
    print(f"  Key type: {ktype}")


if __name__ == "__main__":
    main()