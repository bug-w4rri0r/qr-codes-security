#!/usr/bin/env python3
"""
End-to-end CLI pipeline: generate X QR codes, read them back, report everything.
(v2 successor of benchmarks/paper_v1/pprod_test_2tier_pipeline.py)

For every code it shows what was created (payload, image file, QR version, ECC
level, CBOR / ZLIB / Base64 sizes) and what was read (PKI mode, certificate,
each verification step, decoded payload, match, exit code), then a summary table
and a JSON report. Optional negative cases check that attacks are rejected.

Examples:
  python scripts/e2e_pipeline.py --count 10
  python scripts/e2e_pipeline.py --count 10 --mode root --workdir e2e_run
  python scripts/e2e_pipeline.py --payloads examples/payloads.txt --negative --workdir e2e_run
  python scripts/e2e_pipeline.py --count 3 --debug          # full tool output incl. byte dumps
"""

import argparse
import json
import os
import random
import re
import shutil
import string
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
ANSI = re.compile(r"\x1b\[[0-9;]*m")


def run(cmd, cwd, debug=False):
    """Runs a repository script (cmd[0], relative to the repository) with cwd as working directory."""
    env = dict(os.environ, PYTHONIOENCODING="utf-8")
    t0 = time.perf_counter()
    r = subprocess.run([sys.executable, str(REPO / cmd[0]), *cmd[1:]], cwd=cwd, capture_output=True,
                       text=True, encoding="utf-8", env=env)
    ms = 1000 * (time.perf_counter() - t0)
    out = ANSI.sub("", r.stdout)
    if debug:
        print(f"\n----- $ python {' '.join(cmd)}  (exit {r.returncode}, {ms:.0f} ms) -----")
        print(out.rstrip())
        if r.stderr.strip():
            print(r.stderr.rstrip())
        print("-" * 70)
    return r.returncode, out, ms


def must(cmd, cwd, debug=False):
    code, out, _ = run(cmd, cwd, debug)
    if code != 0:
        print(out)
        sys.exit(f"[ERROR] {' '.join(cmd)} -> exit {code}")
    return out


def field(out, name):
    m = re.search(rf"^\s*{re.escape(name)}:\s+(.+?)\s*$", out, re.MULTILINE)
    return m.group(1) if m else ""


def number(text):
    m = re.match(r"\d+", text)
    return int(m.group()) if m else None


def decoded_payload(out):
    m = re.search(r"PAYLOAD CONTENT[^\n]*\n=+\n(.*?)\n=+", out, re.DOTALL)
    return m.group(1) if m else None


def checks(out):
    return re.findall(r"^\d+\. (.+)\n\s+\[(OK|FAIL)\]", out, re.MULTILINE)


def short(text, n=48):
    return text if len(text) <= n else text[:n - 3] + "..."


def random_payloads(count):
    base = "https://api.mobility.wroclaw.pl/v1/verify-ticket"
    ts = int(time.time())
    rnd = lambda k, a: "".join(random.choices(a, k=k))  # noqa: E731
    return [f"{base}?tkt={rnd(12, string.ascii_uppercase + string.digits)}&ts={ts + i}"
            f"&sig={rnd(64, string.ascii_letters + string.digits)}" for i in range(1, count + 1)]


def setup_pki(w, debug):
    (w / "trusted_roots").mkdir(exist_ok=True)
    must(["cert_gen/gen_ed_keys.py", "--root-name", "Global_Mobility_Root", "--app-name", "Wroclaw_Transit_Auth",
          "--out-dir", "certs_vault", "--force"], w, debug)
    shutil.copy(w / "certs_vault" / "Global_Mobility_Root_pub.pem", w / "trusted_roots")
    must(["cert_gen/create_cose_cert.py", "--root-priv", "certs_vault/Global_Mobility_Root_priv.pem",
          "--iss", "Global_Mobility_Root", "--sub", "PL_WRO_Transit_API",
          "--pub", "certs_vault/Wroclaw_Transit_Auth_pub.pem", "--not-before", "2025-10-01",
          "--not-after", "2030-12-31", "--out", "certs_vault/transit_cert.cbor"], w, debug)
    print(" Root CA:      Global_Mobility_Root (public key in trusted_roots/)")
    print(" App:          Wroclaw_Transit_Auth, certificate sub=PL_WRO_Transit_API, 2025-10-01 .. 2030-12-31")


def create_args(mode, payload, out, min_ecc, cert="certs_vault/transit_cert.cbor",
                app="certs_vault/Wroclaw_Transit_Auth_priv.pem"):
    if mode == "root":
        keys = ["--root-priv", "certs_vault/Global_Mobility_Root_priv.pem"]
    else:
        keys = ["--app-priv", app, "--cert-cbor", cert]
    return ["qr-create.py", "--payload", payload, *keys, "--out", out, "--min-ecc", min_ecc]


def main():
    p = argparse.ArgumentParser(description="Generate X secure QR codes, read them back and report every step")
    p.add_argument("--count", type=int, default=10, help="Number of random ticket URLs (ignored with --payloads)")
    p.add_argument("--payloads", help="Text file with one payload per line")
    p.add_argument("--mode", choices=("chain", "root"), default="chain", help="PKI mode (default: chain)")
    p.add_argument("--min-ecc", choices=("L", "M", "Q", "H"), default="L")
    p.add_argument("--negative", action="store_true", help="Also run attack cases that must be rejected")
    p.add_argument("--workdir", help="Keep keys, images and report.json here (default: temporary, removed)")
    p.add_argument("--debug", action="store_true", help="Print the full output of every tool call (incl. --debug dumps)")
    a = p.parse_args()

    if a.payloads:
        # utf-8-sig drops the BOM that Windows editors / PowerShell may write
        payloads = [l.rstrip("\r\n") for l in Path(a.payloads).read_text(encoding="utf-8-sig").splitlines()
                    if l.strip()]
    else:
        payloads = random_payloads(a.count)

    temp = None if a.workdir else tempfile.TemporaryDirectory(prefix="secure-qr-e2e-")
    w = Path(a.workdir or temp.name).resolve()
    w.mkdir(parents=True, exist_ok=True)
    tool_debug = ["--debug"] if a.debug else []

    print("=" * 78)
    print(f" STAGE 1: PKI   (working directory: {w})")
    print("=" * 78)
    setup_pki(w, a.debug)

    print("\n" + "=" * 78)
    print(f" STAGE 2: GENERATION ({len(payloads)} codes, mode={a.mode}, min ECC {a.min_ecc})")
    print("=" * 78)
    cases = []
    for i, payload in enumerate(payloads, 1):
        img = f"test_qr_images/case_{i:02d}"
        code, out, ms = run(create_args(a.mode, payload, img, a.min_ecc) + tool_debug, w, a.debug)
        case = {"id": i, "payload": payload, "payload_bytes": len(payload.encode("utf-8")),
                "image": f"{img}.png", "create_exit": code, "create_ms": round(ms),
                "qr_version": number(field(out, "QR Version")), "ecc": field(out, "Error Correction"),
                "cbor_bytes": number(field(out, "CBOR Size")), "zlib_bytes": number(field(out, "Encoded Size")),
                "base64_chars": number(field(out, "QR Text Length")), "modules": field(out, "QR Size")}
        cases.append(case)
        status = "OK" if code == 0 else f"FAILED (exit {code})"
        print(f"[CREATE {i:02d}] {status}  {case['image']}")
        print(f"            payload: \"{short(payload, 70)}\" ({case['payload_bytes']} B)")
        print(f"            QR v{case['qr_version']} ({case['modules']}), ECC {case['ecc']}, "
              f"CBOR {case['cbor_bytes']} B -> ZLIB {case['zlib_bytes']} B -> Base64 {case['base64_chars']} chars")

    print("\n" + "=" * 78)
    print(" STAGE 3: READING AND VERIFICATION")
    print("=" * 78)
    for case in cases:
        if case["create_exit"] != 0:
            case.update(read_exit=None, verified=False, match=False)
            continue
        args = ["qr-read.py", "--image", case["image"], "--trusted-dir", "trusted_roots"]
        if a.mode == "chain":
            args.append("--require-chain")
        code, out, ms = run(args + tool_debug, w, a.debug)
        got = decoded_payload(out)
        case.update(read_exit=code, read_ms=round(ms), verified=code == 0, decoded=got,
                    match=got == case["payload"], mode=field(out, "PKI Mode"),
                    certificate=field(out, "Certificate"),
                    checks=[f"{label}: {res}" for label, res in checks(out)],
                    read_version=field(out, "QR Version"), reason=field(out, "Reason"))
        i = case["id"]
        print(f"[READ   {i:02d}] {'VERIFIED' if case['verified'] else 'REJECTED'} (exit {code}, {ms:.0f} ms)  "
              f"mode: {case['mode'] or '-'}")
        if case["certificate"]:
            print(f"            certificate: {case['certificate']}")
        for c in case["checks"]:
            print(f"            check  {c}")
        if case["reason"]:
            print(f"            reason: {case['reason']}")
        print(f"            decoded: \"{short(got or '<not shown>', 70)}\"")
        print(f"            payload match: {'YES' if case['match'] else 'NO'}")

    negatives = []
    if a.negative:
        print("\n" + "=" * 78)
        print(" STAGE 4: NEGATIVE CASES (each must be REJECTED, exit 2)")
        print("=" * 78)
        neg_dir = w / "negative"
        (neg_dir / "other_root").mkdir(parents=True, exist_ok=True)
        must(["cert_gen/gen_ed_keys.py", "--root-name", "Attacker_Root", "--app-name", "Attacker_App",
              "--out-dir", "negative", "--force"], w, a.debug)
        shutil.copy(neg_dir / "Attacker_Root_pub.pem", neg_dir / "other_root")
        must(["cert_gen/create_cose_cert.py", "--root-priv", "certs_vault/Global_Mobility_Root_priv.pem",
              "--iss", "Global_Mobility_Root", "--sub", "Expired_Device", "--pub", "negative/Attacker_App_pub.pem",
              "--not-before", "2020-01-01", "--not-after", "2021-12-31", "--out", "negative/expired_cert.cbor"],
             w, a.debug)
        must(["cert_gen/create_cose_cert.py", "--root-priv", "negative/Attacker_Root_priv.pem",
              "--iss", "Global_Mobility_Root", "--sub", "Fake_Device", "--pub", "negative/Attacker_App_pub.pem",
              "--not-after", "2030-12-31", "--out", "negative/forged_cert.cbor"], w, a.debug)
        p0 = payloads[0]
        scenarios = [
            ("Code signed by an untrusted Root (attacker's own PKI)",
             ["qr-create.py", "--payload", p0, "--root-priv", "negative/Attacker_Root_priv.pem",
              "--out", "negative/untrusted_root"], ["--trusted-dir", "trusted_roots"]),
            ("Certificate forged by an attacker Root, issuer name copied",
             create_args("chain", p0, "negative/forged_cert", "L", "negative/forged_cert.cbor",
                         "negative/Attacker_App_priv.pem"), ["--trusted-dir", "trusted_roots"]),
            ("Expired certificate (valid 2020-01-01 .. 2021-12-31)",
             create_args("chain", p0, "negative/expired", "L", "negative/expired_cert.cbor",
                         "negative/Attacker_App_priv.pem"), ["--trusted-dir", "trusted_roots"]),
            ("Root-Only code where a certificate chain is required",
             ["qr-create.py", "--payload", p0, "--root-priv", "certs_vault/Global_Mobility_Root_priv.pem",
              "--out", "negative/root_only"], ["--trusted-dir", "trusted_roots", "--require-chain"]),
            ("Genuine code checked against a different trust store",
             None, ["--trusted-dir", "negative/other_root"]),
        ]
        for n, (title, create, read_opts) in enumerate(scenarios, 1):
            if create is None:
                image = cases[0]["image"]
            else:
                must(create, w, a.debug)
                image = create[create.index("--out") + 1] + ".png"
            code, out, _ = run(["qr-read.py", "--image", image, *read_opts], w, a.debug)
            ok = code == 2 and p0 not in (decoded_payload(out) or "")
            reason = field(out, "Reason") or out.strip().splitlines()[-1]
            negatives.append({"case": title, "image": image, "read_exit": code, "reason": reason, "rejected": ok})
            print(f"[NEG {n}] {'REJECTED as expected' if ok else 'NOT REJECTED - PROBLEM'}  (exit {code})")
            print(f"        {title}")
            print(f"        reason: {reason}")

    print("\n" + "=" * 78)
    print(" SUMMARY")
    print("=" * 78)
    print(f" {'#':>2}  {'payload':<40} {'B':>4} {'QR':>4} {'ECC':>3} {'CBOR':>5} {'B64':>5}  {'read':<9} match")
    for c in cases:
        print(f" {c['id']:>2}  {short(c['payload'], 40):<40} {c['payload_bytes']:>4} "
              f"{('v' + str(c['qr_version'])) if c['qr_version'] else '-':>4} {c['ecc'] or '-':>3} "
              f"{c['cbor_bytes'] or '-':>5} {c['base64_chars'] or '-':>5}  "
              f"{'VERIFIED' if c['verified'] else 'REJECTED':<9} {'YES' if c['match'] else 'NO'}")
    good = sum(c["verified"] and c["match"] for c in cases)
    print("-" * 78)
    print(f" Positive cases: {good}/{len(cases)} verified and matched")
    if negatives:
        print(f" Negative cases: {sum(n['rejected'] for n in negatives)}/{len(negatives)} rejected as expected")

    report = {"mode": a.mode, "min_ecc": a.min_ecc, "workdir": str(w), "cases": cases, "negative": negatives}
    if a.workdir:
        (w / "report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f" Images:  {w / 'test_qr_images'}")
        print(f" Report:  {w / 'report.json'}")
    else:
        temp.cleanup()
        print(" (temporary directory removed; use --workdir DIR to keep images and report.json)")

    all_ok = good == len(cases) and all(n["rejected"] for n in negatives)
    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
