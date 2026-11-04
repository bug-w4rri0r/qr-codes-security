#!/usr/bin/env python3
"""
End-to-end CLI test of the Root+App chain (v2 successor of paper_v1/pprod_test_2tier_pipeline.py).

Builds a fresh PKI in a temporary directory, generates --count QR codes with
realistic ~150-byte ticket URLs through qr-create.py, reads every image back
with qr-read.py --require-chain and checks that the decoded payload matches.

Usage: py benchmarks/e2e_cli_pipeline.py [--count 10] [--debug]
"""

import argparse
import os
import random
import shutil
import string
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def run(cmd, cwd, debug=False, expect=0):
    env = dict(os.environ, PYTHONIOENCODING="utf-8")
    r = subprocess.run([sys.executable, *cmd], cwd=cwd, capture_output=True, text=True, encoding="utf-8", env=env)
    if debug:
        print(f"\n[DEBUG] {' '.join(cmd)}\n{r.stdout.strip()}\n{r.stderr.strip()}")
    if r.returncode != expect:
        print(r.stdout, r.stderr)
        sys.exit(f"[ERROR] {' '.join(cmd)} -> exit {r.returncode}")
    return r.stdout


def main():
    p = argparse.ArgumentParser(description="End-to-end Root+App pipeline through the CLI tools")
    p.add_argument("--count", type=int, default=10)
    p.add_argument("--debug", action="store_true")
    a = p.parse_args()

    with tempfile.TemporaryDirectory(prefix="secure-qr-e2e-") as tmp:
        w = Path(tmp)
        for f in ("qr-create.py", "qr-read.py", "sqr_core.py"):
            shutil.copy(REPO / f, w / f)
        shutil.copytree(REPO / "cert_gen", w / "cert_gen")
        (w / "trusted_roots").mkdir()

        print("=== STAGE 1: PKI ===")
        run(["cert_gen/gen_ed_keys.py", "--root-name", "Global_Mobility_Root", "--app-name",
             "Wroclaw_Transit_Auth", "--out-dir", "certs_vault"], w, a.debug)
        shutil.copy(w / "certs_vault" / "Global_Mobility_Root_pub.pem", w / "trusted_roots")
        run(["cert_gen/create_cose_cert.py", "--root-priv", "certs_vault/Global_Mobility_Root_priv.pem",
             "--iss", "Global_Mobility_Root", "--sub", "PL_WRO_Transit_API",
             "--pub", "certs_vault/Wroclaw_Transit_Auth_pub.pem", "--not-after", "2030-12-31",
             "--out", "certs_vault/Wroclaw_Transit_Auth_cert.cbor"], w, a.debug)

        base = "https://api.mobility.wroclaw.pl/v1/verify-ticket"
        ts = int(time.time())
        payloads = [f"{base}?tkt={''.join(random.choices(string.ascii_uppercase + string.digits, k=12))}"
                    f"&ts={ts + i}&sig={''.join(random.choices(string.ascii_letters + string.digits, k=64))}"
                    for i in range(1, a.count + 1)]

        print(f"=== STAGE 2: GENERATION ({a.count} codes) ===")
        versions = set()
        for i, payload in enumerate(payloads, 1):
            out = run(["qr-create.py", "--payload", payload, "--app-priv", "certs_vault/Wroclaw_Transit_Auth_priv.pem",
                       "--cert-cbor", "certs_vault/Wroclaw_Transit_Auth_cert.cbor",
                       "--out", f"test_qr_images/bench_qr_{i:02d}"], w, a.debug)
            versions.add(next(l.split()[2] for l in out.splitlines() if "QR Version:" in l))

        print("=== STAGE 3: READING AND VERIFICATION ===")
        ok = 0
        for i, payload in enumerate(payloads, 1):
            out = run(["qr-read.py", "--image", f"test_qr_images/bench_qr_{i:02d}.png",
                       "--trusted-dir", "trusted_roots", "--require-chain"], w, a.debug)
            match = payload in out.splitlines()
            ok += match
            print(f"[READ] QR {i:02d}: {'MATCH' if match else 'MISMATCH'}")

    print(f"\n{ok}/{a.count} codes verified and matched (QR versions: {', '.join(sorted(versions, key=int))})")
    sys.exit(0 if ok == a.count else 1)


if __name__ == "__main__":
    main()
