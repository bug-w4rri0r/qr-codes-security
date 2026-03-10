#!/usr/bin/env python3
"""
ED25519 Key Pair Generator
Generates Ed25519 cryptographic key pairs for certificate signing and verification.
Supports generation of root CA keys and application keys with custom filenames.
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
    
    # Parametry do określania nazw plików bazowych
    parser.add_argument("--root-name", default="root", 
                        help="Base filename for root CA keys (default: root)")
    parser.add_argument("--app-name", default="app", 
                        help="Base filename for application keys (default: app)")
    
    # Flaga blokująca generowanie aplikacji
    parser.add_argument("--root-only", action="store_true", 
                        help="Generate ONLY root CA keys (skip app keys)")
    
    parser.add_argument("--out-dir", default="./certs_vault", 
                        help="Output directory for key files (default: ./certs_vault)")
    
    args = parser.parse_args()

    # Step 2: Create output directory
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    print(f"Output directory: {out.resolve()}")

    # Step 3: Generate root CA key pair
    print(f"Generating root CA key pair ({args.root_name})...")
    root_priv = ed25519.Ed25519PrivateKey.generate()
    root_pub = root_priv.public_key()
    
    # Step 4: Save root keys to PEM files
    save_priv(root_priv, out / f"{args.root_name}_priv.pem")
    save_pub(root_pub, out / f"{args.root_name}_pub.pem")
    print(f"✓ Saved {args.root_name}_priv.pem and {args.root_name}_pub.pem")

    # Step 5: Generate application key pair (only if --root-only is not specified)
    if not args.root_only:
        print(f"Generating application key pair ({args.app_name})...")
        app_priv = ed25519.Ed25519PrivateKey.generate()
        app_pub = app_priv.public_key()
        
        # Step 6: Save application keys to PEM files
        save_priv(app_priv, out / f"{args.app_name}_priv.pem")
        save_pub(app_pub, out / f"{args.app_name}_pub.pem")
        print(f"✓ Saved {args.app_name}_priv.pem and {args.app_name}_pub.pem")
    else:
        print("Skipping application key generation (--root-only provided).")
    
    print("\nKey generation completed successfully!")


if __name__ == "__main__":
    main()