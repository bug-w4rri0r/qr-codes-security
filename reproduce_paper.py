#!/usr/bin/env python3
"""
Reproduces the two proof-of-concept scenarios of the paper with fresh keys.

Runs the real command-line tools (cert_gen/gen_ed_keys.py, cert_gen/create_cose_cert.py,
qr-create.py, qr-read.py) with the payloads, names and dates used in the paper, then
compares the results with the values reported there (Figs. 3-8).

Signatures and keys are random, so the Base64 text differs on every run, but the QR
version, error correction level, payload size and CBOR container size are deterministic.
The ZLIB output size can vary by a byte or two with the random key material.

Usage: py reproduce_paper.py [--workdir paper_run] [--keep]
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent

# Values from the paper (generation and verification outputs, Figs. 3-8).
PAPER = {
    "Scenario 1 (Root-Only)": {"QR Version": "8", "Error Correction": "L", "Payload Size": "39",
                               "CBOR Size": "128", "Encoded Size": "135"},
    "Scenario 2 (Root + App)": {"QR Version": "13", "Error Correction": "L", "Payload Size": "37",
                                "CBOR Size": "314", "Encoded Size": "314"},
}
PAYLOAD_1 = "Welcome to the PWrcampus (Direct Mode)!"
PAYLOAD_2 = "Access to laboratory W4N-K34 granted."


def run(args, cwd, expect=0):
    """Runs a repository script (args[0], relative to the repository) with cwd as working directory."""
    env = dict(os.environ, PYTHONIOENCODING="utf-8")
    r = subprocess.run([sys.executable, str(HERE / args[0]), *args[1:]], cwd=cwd, capture_output=True,
                       text=True, encoding="utf-8", env=env)
    if r.returncode != expect:
        print(r.stdout)
        print(r.stderr)
        sys.exit(f"[ERROR] {' '.join(args)} exited with {r.returncode} (expected {expect})")
    return r.stdout


def field(out, name):
    m = re.search(rf"^\s*{re.escape(name)}:\s+(\S+)", out, re.MULTILINE)
    return m.group(1) if m else "?"


def main():
    p = argparse.ArgumentParser(description="Reproduce the paper's proof-of-concept scenarios")
    p.add_argument("--workdir", help="Directory for keys and images (default: a temporary directory)")
    p.add_argument("--keep", action="store_true", help="Keep the temporary directory")
    a = p.parse_args()

    work = Path(a.workdir) if a.workdir else Path(tempfile.mkdtemp(prefix="secure-qr-"))
    work.mkdir(parents=True, exist_ok=True)
    vault, trusted, images = work / "certs_vault", work / "trusted_roots", work / "test_qr_images"
    trusted.mkdir(exist_ok=True)
    print(f"Working directory: {work}\n")

    print("[1/6] Root CA keys (PWr-Campus)")
    run(["cert_gen/gen_ed_keys.py", "--root-name", "PWr-Campus", "--root-only", "--out-dir", "certs_vault",
         "--force"], work)
    shutil.copy(vault / "PWr-Campus_pub.pem", trusted / "PWr-Campus_pub.pem")

    print("[2/6] Scenario 1: create Root-Only QR")
    gen1 = run(["qr-create.py", "--payload", PAYLOAD_1, "--root-priv", "certs_vault/PWr-Campus_priv.pem",
                "--out", "test_qr_images/qr_pwr_campus_direct"], work)
    print("[3/6] Scenario 1: read and verify")
    read1 = run(["qr-read.py", "--image", "test_qr_images/qr_pwr_campus_direct.png",
                 "--trusted-dir", "trusted_roots"], work)

    print("[4/6] App keys and certificate (iss PWr-Campus, sub W4N-K34, 2025-10-01 .. 2030-12-31)")
    run(["cert_gen/gen_ed_keys.py", "--app-only", "--out-dir", "certs_vault", "--force"], work)
    run(["cert_gen/create_cose_cert.py", "--root-priv", "certs_vault/PWr-Campus_priv.pem",
         "--iss", "PWr-Campus", "--sub", "W4N-K34", "--pub", "certs_vault/app_pub.pem",
         "--not-before", "2025-10-01", "--not-after", "2030-12-31",
         "--out", "certs_vault/cert_W4N_K34.cbor"], work)

    print("[5/6] Scenario 2: create Root + App QR")
    gen2 = run(["qr-create.py", "--payload", PAYLOAD_2, "--app-priv", "certs_vault/app_priv.pem",
                "--cert-cbor", "certs_vault/cert_W4N_K34.cbor",
                "--out", "test_qr_images/qr_w4n_k34_chain"], work)
    print("[6/6] Scenario 2: read and verify (with --require-chain)")
    read2 = run(["qr-read.py", "--image", "test_qr_images/qr_w4n_k34_chain.png",
                 "--trusted-dir", "trusted_roots", "--require-chain"], work)

    rows, all_ok = [], True
    for (label, expected), gen, read in zip(PAPER.items(), (gen1, gen2), (read1, read2)):
        got = {"QR Version": field(gen, "QR Version"), "Error Correction": field(gen, "Error Correction"),
               "Payload Size": field(read, "Payload Size"), "CBOR Size": field(gen, "CBOR Size"),
               "Encoded Size": field(gen, "Encoded Size")}
        verified = "SUCCESS: DATA VERIFIED AND SECURE" in read
        all_ok &= verified
        for k, v in expected.items():
            # ZLIB output depends on random key bytes; allow +-3 bytes for that field only
            same = got[k] == v or (k == "Encoded Size" and got[k].isdigit() and abs(int(got[k]) - int(v)) <= 3)
            rows.append((label, k, v, got[k], "match" if same else "DIFFERENT"))
            all_ok &= same
        rows.append((label, "Verification", "SUCCESS", "SUCCESS" if verified else "FAILED",
                     "match" if verified else "DIFFERENT"))

    print("\n" + "=" * 78)
    print(f" {'Scenario':<25}{'Value':<20}{'Paper':>8}{'This run':>12}   Result")
    print("=" * 78)
    for r in rows:
        print(f" {r[0]:<25}{r[1]:<20}{r[2]:>8}{r[3]:>12}   {r[4]}")
    print("=" * 78)
    print(" Encoded Size (after ZLIB) may differ by a few bytes because keys and signatures are random.")
    print(f"\nImages: {images}")
    if not a.workdir and not a.keep:
        shutil.rmtree(work, ignore_errors=True)
        print("(temporary directory removed; use --keep or --workdir to keep the files)")
    print("\nRESULT:", "ALL VALUES MATCH THE PAPER" if all_ok else "SOME VALUES DIFFER - see table")
    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
