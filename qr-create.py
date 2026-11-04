#!/usr/bin/env python3
"""
Secure QR Code Generator (v2.0 - Dual Mode: Root-Only or Root+App)

Signs a payload with Ed25519 and packs it into a QR code:
    payload -> signature -> CBOR container -> ZLIB -> Base64 -> QR

PKI modes:
  * Root-Only (Mode A): --root-priv signs the payload directly.
  * Root + App (Mode B): --app-priv signs the payload and the App certificate
    (--cert-cbor, issued by the Root with cert_gen/create_cose_cert.py) is embedded.

Defaults reproduce the configuration used in the paper (ZLIB always on,
smallest QR version, version <= 26). See README.md for the v2 changes.
"""

import argparse
import sys
from pathlib import Path

import cbor2

import sqr_core as core


def load_cert_envelope(path: Path):
    """Loads {'cert': map, 'cert_sig': bytes} written by cert_gen/create_cose_cert.py."""
    if not path.is_file():
        raise FileNotFoundError(f"Certificate file not found: {path}")
    try:
        env = cbor2.loads(path.read_bytes())
    except Exception as e:
        raise core.SecureQRError(f"Failed to decode CBOR certificate: {e}")
    if not isinstance(env, dict) or "cert" not in env or "cert_sig" not in env:
        raise core.SecureQRError("Invalid certificate file (missing 'cert' or 'cert_sig')")
    return env["cert"], env["cert_sig"]


def print_debug(label, data, is_text=False):
    print(f"\n[DEBUG] --- {label} ---")
    print(f" Size: {len(data)} {'chars' if is_text else 'bytes'}")
    if is_text:
        print(f" Content:\n{data}")
        return
    hex_str = data.hex()
    for i in range(0, len(hex_str), 64):
        row = hex_str[i:i + 64]
        print(" Hex: " + " ".join(row[j:j + 2] for j in range(0, len(row), 2)))


def main():
    parser = argparse.ArgumentParser(
        description="Secure QR Code Generator (Ed25519 + CBOR + ZLIB + Base64, Root-Only / Root+App)")
    parser.add_argument("--payload", required=True, help="Text to encode OR file path (with --file)")
    parser.add_argument("--file", action="store_true", help="Treat --payload as a file path")
    parser.add_argument("--out", default="secure_qr", help="Output filename base (no extension)")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--root-priv", help="Root CA private key (Root-Only mode)")
    mode.add_argument("--app-priv", help="App private key (Root+App mode, needs --cert-cbor)")
    parser.add_argument("--cert-cbor", help="App certificate issued by the Root (Root+App mode)")
    parser.add_argument("--compress", choices=("always", "auto", "never"), default="always",
                        help="ZLIB: always (paper default), auto (only if smaller), never")
    parser.add_argument("--no-compress", action="store_true", help="Same as --compress never")
    parser.add_argument("--min-ecc", choices=core.ERROR_LEVELS, default="L",
                        help="Lowest error correction level to consider (default L = smallest code)")
    parser.add_argument("--max-version", type=int, default=core.MAX_QR_VERSION,
                        help=f"Largest QR version allowed (default {core.MAX_QR_VERSION})")
    parser.add_argument("--debug", action="store_true", help="Show full data dumps")
    args = parser.parse_args()

    if args.app_priv and not args.cert_cbor:
        parser.error("--cert-cbor is required with --app-priv (Root+App mode)")
    if args.root_priv and args.cert_cbor:
        parser.error("--cert-cbor is only valid with --app-priv")
    compress = "never" if args.no_compress else args.compress

    cert = cert_sig = None
    try:
        if args.root_priv:
            mode_name = core.MODE_ROOT
            print(f"Loading Root CA Private Key from {args.root_priv}...")
            key = core.load_private_key(Path(args.root_priv))
        else:
            mode_name = core.MODE_CHAIN
            print(f"Loading App Private Key from {args.app_priv}...")
            key = core.load_private_key(Path(args.app_priv))
            print(f"Loading App Certificate from {args.cert_cbor}...")
            cert, cert_sig = load_cert_envelope(Path(args.cert_cbor))
            if core.raw_public_bytes(key.public_key()) != cert.get("pub"):
                raise core.SecureQRError("The App private key does not match the public key in the certificate")
    except Exception as e:
        print(f"[ERROR] Failed to load keys/certificate: {e}")
        sys.exit(1)

    if args.file:
        p = Path(args.payload)
        if not p.is_file():
            print(f"[ERROR] File {args.payload} does not exist.")
            sys.exit(1)
        payload = p.read_bytes()
        print(f"Read {len(payload)} bytes from file.")
    else:
        payload = args.payload.encode("utf-8")

    print(f"Generating QR structure using {mode_name}...")
    try:
        enc = core.build_container(payload, key, cert, cert_sig, compress=compress)
    except core.SecureQRError as e:
        print(f"[ERROR] {e}")
        sys.exit(1)
    if args.debug:
        print_debug("Input Payload", payload)
        print_debug("CBOR container", enc.cbor)
        if enc.compressed:
            print_debug("ZLIB compressed", enc.data)
        print_debug("Base64 text stored in the QR code", enc.text, is_text=True)

    qr, ecc = core.make_qr(enc.text, min_ecc=args.min_ecc, max_version=args.max_version)
    if qr is None:
        print(f"\n[CRITICAL ERROR] Data does not fit into a QR code of version <= {args.max_version}"
              f" at error correction >= {args.min_ecc}.")
        print("Reduce the payload, keep compression enabled or lower --min-ecc.")
        sys.exit(1)

    out_img = Path(f"{args.out}.png")
    out_img.parent.mkdir(parents=True, exist_ok=True)
    # scale=8 px per module, border=4 modules (standard quiet zone)
    qr.save(str(out_img), scale=8, border=4, dark="black", light="white")

    s = enc.sizes
    print("\n" + "=" * 65)
    print(" SUCCESS - QR CODE GENERATED")
    print("=" * 65)
    print(f" PKI Mode:          {mode_name}")
    print(f" Output File:       {out_img.as_posix()}")
    print("-" * 65)
    print(f" QR Version:        {qr.version} (Max limit: {args.max_version})")
    print(f" Error Correction:  {ecc}")
    print(f" Encoding:          Base64 (Safe for Cameras)")
    print(f" Compression:       {'YES (ZLIB)' if enc.compressed else 'NO'}")
    print(f" CBOR Size:         {s['cbor']} bytes (before compression)")
    print(f" Encoded Size:      {s['encoded']} bytes (after compression, before Base64)")
    print(f" QR Text Length:    {s['base64']} chars (Base64)")
    print("=" * 65)


if __name__ == "__main__":
    main()
