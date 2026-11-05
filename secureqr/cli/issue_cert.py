"""
Lightweight CBOR Certificate Generator.

Run as `python cert_gen/create_cose_cert.py ...` or `secureqr-issue-cert ...` (installed).

Issues an App certificate signed by the Root CA:
    cert = {"iss", "sub", "alg": "Ed25519", "pub": <32-byte App key>, "nbf", "exp"}
    cert_sig = Ed25519_Root( "SecureQR/v2/cert" || deterministic_CBOR(cert) )

The file written is a CBOR map {"cert": cert, "cert_sig": cert_sig}, embedded
by qr-create.py in Root+App mode.

The structure is COSE-inspired (CBOR + EdDSA) but it is not a COSE_Sign1
message. The script name create_cose_cert.py is kept for compatibility with v1.
"""

import argparse
import sys
from pathlib import Path

import cbor2

from secureqr import __version__, core


def main():
    parser = argparse.ArgumentParser(description="Issue a lightweight CBOR certificate signed by the Root CA")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--root-priv", required=True, help="Root CA private key (PEM)")
    parser.add_argument("--iss", required=True, help="Issuer name, e.g. 'PWr-Campus'")
    parser.add_argument("--sub", required=True, help="Subject (device / department), e.g. 'W4N-K34'")
    parser.add_argument("--pub", required=True, help="App public key (PEM)")
    parser.add_argument("--not-before", default=None, help="Validity start: YYYY-MM-DD or ISO 8601 (optional)")
    parser.add_argument("--not-after", required=True,
                        help="Validity end: YYYY-MM-DD (valid through that day, UTC) or ISO 8601 (required)")
    parser.add_argument("--out", default="app_cert.cbor", help="Output file (default: app_cert.cbor)")
    args = parser.parse_args()

    try:
        print("Loading root CA private key...")
        root = core.load_private_key(Path(args.root_priv))
        print(f"Loading application public key from {args.pub}...")
        pub = core.raw_public_bytes(core.load_public_key(Path(args.pub)))
        cert = core.build_cert(args.iss, args.sub, pub, args.not_before, args.not_after)
    except Exception as e:
        print(f"[ERROR] {e}")
        sys.exit(1)

    print(f"Signing certificate with issuer '{args.iss}'...")
    envelope = {"cert": cert, "cert_sig": core.sign_cert(root, cert)}
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(cbor2.dumps(envelope))

    print("\nCertificate generated successfully!")
    print(f"  File: {out.as_posix()} ({out.stat().st_size} bytes)")
    print(f"  Issuer: {args.iss}")
    print(f"  Subject: {args.sub}")
    if args.not_before:
        print(f"  Valid From (nbf): {args.not_before}")
    print(f"  Expires (exp): {args.not_after}")
    print("  Key type: ed25519")


if __name__ == "__main__":
    main()
