#!/usr/bin/env python3
"""
Secure QR Code Reader (v2.0 - Dual Mode)

Scans a QR code image, detects the PKI mode (Root-Only vs Root+App), verifies
the trust chain against trusted Root public keys and shows the payload only if
it is authentic.

Verification is fail-fast: Base64/ZLIB/CBOR schema checks run before any
cryptography, and the first failing check stops processing.

Exit codes: 0 = verified, 2 = verification failed, 1 = input or usage error.
"""

import argparse
import sys
from pathlib import Path

import sqr_core as core


class Color:
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    RESET = "\033[0m"


def print_debug(label, data, is_text=False):
    print(f"\n{Color.CYAN}[DEBUG] --- {label} ---{Color.RESET}")
    print(f" Size: {len(data)} {'chars' if is_text else 'bytes'}")
    if is_text:
        print(f" Content:\n{data}")
        return
    hex_str = data.hex()
    for i in range(0, len(hex_str), 64):
        row = hex_str[i:i + 64]
        print(" Hex: " + " ".join(row[j:j + 2] for j in range(0, len(row), 2)))


def main():
    parser = argparse.ArgumentParser(description="Secure QR Code Reader (Dual Mode)")
    parser.add_argument("--image", required=True, help="Path to the QR code image")
    parser.add_argument("--trusted-dir", required=True, dest="trusted",
                        help="Trusted Root CA public key (.pem) or a directory of Root *.pem keys")
    parser.add_argument("--require-chain", action="store_true",
                        help="Accept only Root+App codes (reject Root-Only codes)")
    parser.add_argument("--legacy-v1", action="store_true",
                        help="Verify codes produced by the v1 tools (no domain separation), e.g. the paper's figures")
    parser.add_argument("--show-untrusted", action="store_true",
                        help="Print the payload even if verification fails (clearly marked as UNTRUSTED)")
    parser.add_argument("--debug", action="store_true", help="Show full data dumps")
    args = parser.parse_args()

    try:
        roots = core.load_trusted_roots(Path(args.trusted))
    except Exception as e:
        print(f"{Color.RED}[ERROR] {e}{Color.RESET}")
        sys.exit(1)
    print(f"Loaded {len(roots)} trusted root key(s).")

    image = Path(args.image)
    print(f"Scanning image: {image.name} ...")
    try:
        text, version = core.decode_image(image)
    except Exception as e:
        print(f"{Color.RED}[ERROR] {e}{Color.RESET}")
        sys.exit(1)
    if args.debug:
        print_debug("Step 1: Raw QR Text (Base64)", text, is_text=True)

    try:
        container, stats = core.decode_text(text)
    except core.SecureQRError as e:
        print(f"{Color.RED}[FATAL] Rejected before verification: {e}{Color.RESET}")
        sys.exit(2)
    print(f"Compression:       {'ZLIB (Decompressed)' if stats['compressed'] else 'NONE'}")
    print("Format:            VALID CBOR (schema checked)")

    payload = container["payload"]
    print(f"\n{Color.CYAN}--- STARTING SECURITY VERIFICATION ---{Color.RESET}")
    if "cert" in container:
        cert = container["cert"]
        print(f"\n{Color.YELLOW}[Certificate & Authorization Details - Mode: {core.MODE_CHAIN}]{Color.RESET}")
        print(f"   Issuer (iss):          {cert['iss']}")
        print(f"   Subject (sub):         {cert['sub']}")
        print(f"   Valid From (nbf):      {cert.get('nbf', 'N/A (No start date)')}")
        print(f"   Expires (exp):         {cert.get('exp', 'N/A (missing - will be rejected)')}")
        print("   -----------------------")
        print(f"   Payload Size:          {len(payload)} bytes")
        print(f"   Payload Signature:     {len(container['payload_sig'])} bytes (Ed25519)")
        print(f"   Certificate Signature: {len(container['cert_sig'])} bytes (Ed25519)\n")
    else:
        print(f"\n{Color.YELLOW}[Direct Trust Details - Mode: {core.MODE_ROOT}]{Color.RESET}")
        print(f"   Payload Size:          {len(payload)} bytes")
        print(f"   Payload Signature:     {len(container['payload_sig'])} bytes (Ed25519)\n")
    if args.legacy_v1:
        print(f"{Color.YELLOW}[LEGACY] Verifying with v1 rules (no domain separation).{Color.RESET}")

    result = core.verify_container(container, roots, require_chain=args.require_chain,
                                   legacy_v1=args.legacy_v1)
    for i, (label, ok) in enumerate(result.checks, 1):
        mark = f"{Color.GREEN}[OK]" if ok else f"{Color.RED}[FAIL]"
        print(f"{i}. {label}\n   {mark}{Color.RESET}")

    print("-" * 50)
    if result.ok:
        print(f"{Color.GREEN}SUCCESS: DATA VERIFIED AND SECURE{Color.RESET}")
    else:
        print(f"{Color.RED}SECURITY WARNING: VERIFICATION FAILED{Color.RESET}")
        print(f"Reason: {result.reason}")
        if not args.show_untrusted:
            print("Payload not displayed (use --show-untrusted to print it anyway).")
            sys.exit(2)

    print("\n" + "=" * 30)
    print("      PAYLOAD CONTENT" + ("" if result.ok else " (UNTRUSTED)"))
    print("=" * 30)
    try:
        print(payload.decode("utf-8"))
    except UnicodeDecodeError:
        print(f"[Binary Data] Hex: {payload.hex()}")
    print("=" * 30 + "\n")
    if "cert" in container:
        print(f"Issued to (Subject): {container['cert']['sub']}")

    print("\n" + "=" * 65)
    print(" READING SUMMARY")
    print("=" * 65)
    print(f" Input File:        {image.name}")
    print(f" PKI Mode:          {result.mode}")
    print("-" * 65)
    print(f" QR Version:        {version if version else 'Unknown'} (Estimated)")
    print(" Error Correction:  N/A (Hidden by Reader)")
    print(" Encoding:          Base64")
    print(f" Compression:       {'YES (ZLIB)' if stats['compressed'] else 'NO'}")
    print(f" Payload Size:      {stats['payload']} bytes")
    print(f" CBOR Size:         {stats['cbor']} bytes (decompressed container)")
    print(f" Encoded Size:      {stats['encoded']} bytes (after Base64 decoding)")
    print("=" * 65)
    sys.exit(0 if result.ok else 2)


if __name__ == "__main__":
    main()
