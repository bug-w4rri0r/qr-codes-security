#!/usr/bin/env python3
"""
ED25519 Key Pair Generator
Generates Ed25519 cryptographic key pairs for certificate signing and verification.
Supports generation of root CA keys and application keys.
"""

import argparse
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from pathlib import Path


def save_priv(key, path):
    """
    Save a private key to a PEM file.
    
    Args:
        key: Ed25519 private key object
        path: File path to save the private key
    """
    with open(path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))


def save_pub(key, path):
    """
    Save a public key to a PEM file.
    
    Args:
        key: Ed25519 public key object
        path: File path to save the public key
    """
    with open(path, "wb") as f:
        f.write(key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))


def main():
    """
    Main entry point for key generation.
    
    Steps:
    1. Parse command line arguments
    2. Create output directory if it doesn't exist
    3. Generate root CA key pair
    4. Save root private and public keys to PEM files
    5. Optionally generate application key pair
    6. Save application private and public keys to PEM files
    """
    # Step 1: Parse command line arguments
    parser = argparse.ArgumentParser(description="Generate Ed25519 key pairs for certificate signing")
    parser.add_argument("--root-only", action="store_true", 
                       help="Generate only root CA keys (skip app keys)")
    parser.add_argument("--out-dir", default="./certs_vault", 
                       help="Output directory for key files (default: ./certs_vault)")
    parser.add_argument("--gen-app", action="store_true", default=True, 
                       help="Generate application keys (default: True)")
    args = parser.parse_args()

    # Step 2: Create output directory
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    print(f"Output directory: {out.resolve()}")

    # Step 3: Generate root CA key pair
    print("Generating root CA key pair...")
    root_priv = ed25519.Ed25519PrivateKey.generate()
    root_pub = root_priv.public_key()
    
    # Step 4: Save root keys to PEM files
    save_priv(root_priv, out / "root_priv.pem")
    save_pub(root_pub, out / "root_pub.pem")
    print("✓ Saved root_priv.pem and root_pub.pem")

    # Step 5: Generate application key pair (if not --root-only flag)
    if args.gen_app or not args.root_only:
        print("Generating application key pair...")
        app_priv = ed25519.Ed25519PrivateKey.generate()
        app_pub = app_priv.public_key()
        
        # Step 6: Save application keys to PEM files
        save_priv(app_priv, out / "app_priv.pem")
        save_pub(app_pub, out / "app_pub.pem")
        print("✓ Saved app_priv.pem and app_pub.pem")
    
    print("\nKey generation completed successfully!")


if __name__ == "__main__":
    main()
