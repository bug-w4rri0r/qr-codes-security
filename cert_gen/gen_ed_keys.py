#!/usr/bin/env python3
import argparse
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from pathlib import Path

def save_priv(key, path):
    with open(path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

def save_pub(key, path):
    with open(path, "wb") as f:
        f.write(key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--root-only", action="store_true")
    p.add_argument("--out-dir", default=".", help="katalog zapisu")
    p.add_argument("--gen-app", action="store_true", help="wygeneruj też klucz app")
    args = p.parse_args()

    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)

    # Root
    root_priv = ed25519.Ed25519PrivateKey.generate()
    root_pub = root_priv.public_key()
    save_priv(root_priv, out / "root_priv.pem")
    save_pub(root_pub, out / "root_pub.pem")
    print("Zapisano root_priv.pem i root_pub.pem")

    if args.gen_app:
        app_priv = ed25519.Ed25519PrivateKey.generate()
        app_pub = app_priv.public_key()
        save_priv(app_priv, out / "app_priv.pem")
        save_pub(app_pub, out / "app_pub.pem")
        print("Zapisano app_priv.pem i app_pub.pem")

if __name__ == "__main__":
    main()
