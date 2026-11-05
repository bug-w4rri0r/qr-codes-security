"""
Ed25519 Key Pair Generator.

Run as `python cert_gen/gen_ed_keys.py ...` or `secureqr-keygen ...` (installed).

Generates Root CA and/or App key pairs as PEM files:
    <name>_priv.pem (PKCS#8) and <name>_pub.pem (SubjectPublicKeyInfo)

Private keys are written unencrypted by default (proof-of-concept). Set the
environment variable SQR_KEY_PASSPHRASE to encrypt them; the other tools read
the same variable. In a real deployment the Root key belongs offline or in an
HSM. Existing keys are never overwritten unless --force is given.
"""

import argparse
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from secureqr import __version__
from secureqr.core import KEY_PASSPHRASE_ENV as PASSPHRASE_ENV


def write_pair(out: Path, name: str, force: bool):
    priv_path, pub_path = out / f"{name}_priv.pem", out / f"{name}_pub.pem"
    if not force and (priv_path.exists() or pub_path.exists()):
        print(f"[ERROR] {priv_path.name} or {pub_path.name} already exists (use --force to overwrite).")
        sys.exit(1)
    key = ed25519.Ed25519PrivateKey.generate()
    password = os.environ.get(PASSPHRASE_ENV)
    encryption = (serialization.BestAvailableEncryption(password.encode("utf-8"))
                  if password else serialization.NoEncryption())
    priv_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                            serialization.PrivateFormat.PKCS8, encryption))
    try:
        os.chmod(priv_path, 0o600)
    except OSError:
        pass
    pub_path.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,
                                                       serialization.PublicFormat.SubjectPublicKeyInfo))
    state = "encrypted" if password else "unencrypted"
    print(f"Saved {priv_path.name} ({state}) and {pub_path.name}")


def main():
    parser = argparse.ArgumentParser(description="Generate Ed25519 key pairs for the Secure QR PKI")
    parser.add_argument("--root-name", default="root", help="Base filename for Root CA keys (default: root)")
    parser.add_argument("--app-name", default="app", help="Base filename for App keys (default: app)")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--root-only", action="store_true", help="Generate only Root CA keys")
    group.add_argument("--app-only", action="store_true", help="Generate only App keys")
    parser.add_argument("--out-dir", default="./certs_vault", help="Output directory (default: ./certs_vault)")
    parser.add_argument("--force", action="store_true", help="Overwrite existing key files")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = parser.parse_args()

    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    print(f"Output directory: {out.resolve()}")
    if not args.app_only:
        print(f"Generating Root CA key pair ({args.root_name})...")
        write_pair(out, args.root_name, args.force)
    if not args.root_only:
        print(f"Generating application key pair ({args.app_name})...")
        write_pair(out, args.app_name, args.force)
    print("\nKey generation completed successfully!")


if __name__ == "__main__":
    main()
