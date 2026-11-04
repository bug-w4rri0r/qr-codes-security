#!/usr/bin/env python3
"""
Full-pipeline benchmark (v2).

Generation:   sign + CBOR + ZLIB + Base64 + QR + PNG file
Verification: PNG file + OpenCV decoding + Base64 + ZLIB + CBOR schema + signature checks

Runs in-process with the same functions as qr-create.py / qr-read.py
(sqr_core), so interpreter start-up is not included. Defaults follow the
configuration of the paper run (Root-Only, ECC H, 3 px per module, 1000
iterations); --mode chain measures the Root+App certificate chain (8 px per
module by default, as written by qr-create.py).

Usage: py benchmarks/benchmark_pipeline.py [--iterations 1000] [--mode root|chain] [--ecc H] [--json out.json]
"""

import argparse
import json
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from cryptography.hazmat.primitives.asymmetric import ed25519  # noqa: E402

import sqr_core as core  # noqa: E402
from env_info import environment  # noqa: E402


def main():
    p = argparse.ArgumentParser(description="Full secure-QR pipeline benchmark")
    p.add_argument("--iterations", type=int, default=1000)
    p.add_argument("--mode", choices=("root", "chain"), default="root")
    p.add_argument("--ecc", choices=core.ERROR_LEVELS, default="H",
                   help="Minimum error correction level (paper run: H)")
    p.add_argument("--scale", type=int, default=None,
                   help="Pixels per module in the PNG (default: 3 for root as in the paper run, 8 for chain "
                        "as in qr-create.py; OpenCV is unreliable below 4 px/module for version >= 14)")
    p.add_argument("--json", help="Write results to this JSON file")
    a = p.parse_args()
    if a.scale is None:
        a.scale = 3 if a.mode == "root" else 8

    root = ed25519.Ed25519PrivateKey.generate()
    roots = [root.public_key()]
    cert = cert_sig = None
    signer = root
    if a.mode == "chain":
        signer = ed25519.Ed25519PrivateKey.generate()
        cert = core.build_cert("Benchmark-Root", "Benchmark-App",
                               core.raw_public_bytes(signer.public_key()), None, "2099-12-31")
        cert_sig = core.sign_cert(root, cert)

    payloads = [f"Test city ticket #{i}, generated for the parking system.".encode() for i in range(a.iterations)]

    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp)
        versions = set()
        t0 = time.perf_counter()
        for i, payload in enumerate(payloads):
            enc = core.build_container(payload, signer, cert, cert_sig)
            qr, _ = core.make_qr(enc.text, min_ecc=a.ecc)
            qr.save(str(out / f"qr_{i}.png"), scale=a.scale)
            versions.add(qr.version)
        gen = time.perf_counter() - t0

        ok = 0
        t0 = time.perf_counter()
        for i, payload in enumerate(payloads):
            try:
                text, _ = core.decode_image(out / f"qr_{i}.png")
                container, _ = core.decode_text(text)
                res = core.verify_container(container, roots)
                ok += res.ok and container["payload"] == payload
            except core.SecureQRError:
                pass
        ver = time.perf_counter() - t0

    n = a.iterations
    result = {
        "benchmark": "full_pipeline", "mode": a.mode, "ecc_min": a.ecc, "scale": a.scale,
        "iterations": n, "qr_versions": sorted(versions), "verified": ok,
        "generation": {"total_s": gen, "ms_per_op": 1000 * gen / n, "ops_per_s": n / gen},
        "verification": {"total_s": ver, "ms_per_op": 1000 * ver / n, "ops_per_s": n / ver},
        "environment": environment(),
    }
    print("=" * 64)
    print(f" FULL PIPELINE ({n} iterations, mode={a.mode}, ECC>={a.ecc}, {a.scale} px/module, "
          f"QR versions {sorted(versions)})")
    print("=" * 64)
    print(f" Verified:      {ok} / {n}")
    print(f" Generation:    {result['generation']['ms_per_op']:.2f} ms/op   {result['generation']['ops_per_s']:.0f} ops/s")
    print(f" Verification:  {result['verification']['ms_per_op']:.2f} ms/op   {result['verification']['ops_per_s']:.0f} ops/s")
    print("-" * 64)
    for k, v in result["environment"].items():
        print(f" {k:<14} {v}")
    if a.json:
        Path(a.json).write_text(json.dumps(result, indent=2))
        print(f"\nSaved {a.json}")
    sys.exit(0 if ok == n else 1)


if __name__ == "__main__":
    main()
