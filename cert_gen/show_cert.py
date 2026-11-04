#!/usr/bin/env python3
"""
Shows the content of a certificate file written by create_cose_cert.py and,
with --root-pub, checks its Root signature and validity window.

Usage: py cert_gen/show_cert.py --cert certs_vault/cert_W4N_K34.cbor [--root-pub trusted_roots/PWr-Campus_pub.pem]
Exit codes: 0 = shown (and valid, if --root-pub given), 2 = invalid, 1 = error.
"""

import argparse
import sys
import time
from pathlib import Path

import cbor2

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import sqr_core as core  # noqa: E402


def main():
    p = argparse.ArgumentParser(description="Show and check a lightweight CBOR certificate")
    p.add_argument("--cert", required=True, help="Certificate file (.cbor)")
    p.add_argument("--root-pub", help="Root public key (.pem) or trust-store directory to check the signature")
    a = p.parse_args()

    path = Path(a.cert)
    try:
        env = cbor2.loads(path.read_bytes())
        cert, sig = env["cert"], env["cert_sig"]
    except Exception as e:
        print(f"[ERROR] Cannot read certificate {path}: {e}")
        sys.exit(1)

    print(f"Certificate file:  {path.as_posix()} ({path.stat().st_size} bytes)")
    for k in ("iss", "sub", "alg", "nbf", "exp"):
        print(f"  {k:<5}            {cert.get(k, '-')}")
    pub = cert.get("pub", b"")
    print(f"  pub              {pub.hex() if isinstance(pub, bytes) else pub} ({len(pub)} bytes)")
    print(f"  cert_sig         {sig.hex()[:32]}... ({len(sig)} bytes)")

    if not a.root_pub:
        return
    roots = core.load_trusted_roots(Path(a.root_pub))
    sig_ok = any(_ok(k, sig, core.signed_cert_message(cert)) for k in roots)
    print(f"\nRoot signature:    {'VALID' if sig_ok else 'INVALID (not issued by this Root, or a v1 certificate)'}")
    now = int(time.time())
    try:
        exp = core.parse_time(cert["exp"], end_of_day=True)
        nbf = core.parse_time(cert["nbf"]) if "nbf" in cert else None
        dates_ok = (nbf is None or now >= nbf) and now <= exp
        state = "valid now" if dates_ok else ("NOT YET valid" if nbf and now < nbf else "EXPIRED")
    except (KeyError, core.SecureQRError) as e:
        dates_ok, state = False, f"invalid ({e})"
    print(f"Validity window:   {state}")
    sys.exit(0 if sig_ok and dates_ok else 2)


def _ok(key, sig, msg):
    try:
        key.verify(sig, msg)
        return True
    except Exception:
        return False


if __name__ == "__main__":
    main()
