#!/usr/bin/env python3
import argparse, cbor2, datetime
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from pathlib import Path

def load_root_priv(path):
    with open(path,"rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def load_pubkey_bytes(pem_path):
    # jeśli dostarczono PEM pubkey (SubjectPublicKeyInfo), zwracamy surowe bytes (raw data)
    with open(pem_path,"rb") as f:
        data = f.read()
    pub = serialization.load_pem_public_key(data)
    # jeśli to Ed25519, zwróć raw 32B. W przeciwnym razie zwróć SubjectPublicKeyInfo DER
    try:
        raw = pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
        return raw, "ed25519"
    except Exception:
        # zwróć DER
        der = pub.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        return der, "other"

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--root-priv", required=True)
    p.add_argument("--sub", required=True, help="subject (np. app identifier)")
    p.add_argument("--pub", required=True, help="ścieżka do PEM public key (app_pub.pem) lub plik z DER public key bytes")
    p.add_argument("--not-before", help="YYYY-MM-DD", default=None)
    p.add_argument("--not-after", help="YYYY-MM-DD", default=None)
    p.add_argument("--out", default="app_cert.cbor")
    args = p.parse_args()

    root = load_root_priv(args.root_priv)
    pub_bytes, ktype = load_pubkey_bytes(args.pub)

    cert = {
        "iss": "root",         # identyfikator issuera, możesz użyć fingerprintu lub CN
        "sub": args.sub,
        "alg": "Ed25519",
        "pub": pub_bytes,      # bytes
    }
    if args.not_before:
        cert["nbf"] = args.not_before
    if args.not_after:
        cert["exp"] = args.not_after

    # CBOR-encode cert WITHOUT signature
    cert_no_sig = cbor2.dumps(cert)
    sig = root.sign(cert_no_sig)  # Ed25519 signature (64 bytes)

    envelope = {
        "cert": cert,
        "sig": sig
    }

    with open(args.out, "wb") as f:
        f.write(cbor2.dumps(envelope))

    print("Zapisano COSE-like cert:", args.out)
    print("Key type detected for pub:", ktype)

if __name__ == "__main__":
    main()
