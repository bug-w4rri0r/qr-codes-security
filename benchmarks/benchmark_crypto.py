#!/usr/bin/env python3
"""
Raw Ed25519 benchmark (v2).

Measures signing and verification of a single message, as in the paper's
"Raw Ed25519 Signing / Verification" rows. Uses time.perf_counter() and a
warm-up round, and prints the environment so the numbers can be reproduced.

Usage: py benchmarks/benchmark_crypto.py [--iterations 1000] [--repeats 5] [--json out.json]
"""

import argparse
import json
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from cryptography.hazmat.primitives.asymmetric import ed25519  # noqa: E402

from env_info import environment  # noqa: E402

MESSAGE = b"Przykladowy payload z certyfikatem CBOR o rozmiarze okolo 100 bajtow"  # same as the paper run


def run(fn, iterations: int) -> float:
    start = time.perf_counter()
    for _ in range(iterations):
        fn()
    return time.perf_counter() - start


def main():
    p = argparse.ArgumentParser(description="Raw Ed25519 sign/verify benchmark")
    p.add_argument("--iterations", type=int, default=1000)
    p.add_argument("--repeats", type=int, default=5, help="Independent runs; the median is reported")
    p.add_argument("--json", help="Write results to this JSON file")
    a = p.parse_args()

    key = ed25519.Ed25519PrivateKey.generate()
    pub = key.public_key()
    sig = key.sign(MESSAGE)
    run(lambda: key.sign(MESSAGE), 100)          # warm-up
    run(lambda: pub.verify(sig, MESSAGE), 100)

    sign = [run(lambda: key.sign(MESSAGE), a.iterations) for _ in range(a.repeats)]
    verify = [run(lambda: pub.verify(sig, MESSAGE), a.iterations) for _ in range(a.repeats)]

    def summary(times):
        t = statistics.median(times)
        return {"ms_per_op": 1000 * t / a.iterations, "ops_per_s": a.iterations / t,
                "runs_s": times}

    result = {"benchmark": "ed25519_raw", "iterations": a.iterations, "repeats": a.repeats,
              "message_bytes": len(MESSAGE), "sign": summary(sign), "verify": summary(verify),
              "environment": environment()}

    print("=" * 60)
    print(f" RAW Ed25519 ({a.iterations} iterations x {a.repeats} runs, median)")
    print("=" * 60)
    for name in ("sign", "verify"):
        r = result[name]
        print(f" {name:<7} {r['ms_per_op']:.4f} ms/op   {r['ops_per_s']:,.0f} ops/s")
    print("-" * 60)
    for k, v in result["environment"].items():
        print(f" {k:<14} {v}")
    if a.json:
        Path(a.json).write_text(json.dumps(result, indent=2))
        print(f"\nSaved {a.json}")


if __name__ == "__main__":
    main()
