#!/usr/bin/env python3
"""
create_qr_ed25519.py

Create a compact, signed QR that contains:
  - payload (bytes)
  - payload signature (Ed25519)
  - COSE-like cert (CBOR map) and cert signature (Ed25519)

Requirements:
  - app private key in PEM (Ed25519 or other supported by cryptography)
  - a COSE-like cert file (CBOR) produced by create_cose_cert.py with structure:
      { "cert": { ... cert map ... }, "sig": b"...signature..." }

Behavior:
  - At start prints the maximum payload size (in bytes) that can fit into any QR
    version <= 26 given the current cert + signature sizes. The maximum is
    found by binary-search up to --max-payload-limit.
  - When creating a QR for an actual payload, it will attempt to pack the data
    into the smallest possible QR version (from 1 up to 26). It also tries
    error-correction levels in this order: L, M, Q, H (L -> highest capacity).
  - If raw CBOR does not fit, the script tries zlib compression (level=9).
  - If neither fits in any version<=26, the script fails.
"""
import argparse
import cbor2
import zlib
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
import segno

# Error-correction order: try L first (largest capacity), then M, Q, H
ERROR_LEVELS = ("L", "M", "Q", "H")
MAX_QR_VERSION = 26


def load_priv(path: Path):
    """Load a PEM private key (supports Ed25519 or other types)."""
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def load_cbor_cert(path: Path):
    """Load a COSE-like cert envelope saved as CBOR (envelope: {'cert':..., 'sig':...})."""
    data = path.read_bytes()
    env = cbor2.loads(data)
    if not isinstance(env, dict) or "cert" not in env or "sig" not in env:
        raise RuntimeError("Invalid COSE-cert CBOR file: missing 'cert' or 'sig' fields")
    return env["cert"], env["sig"]


def try_make_qr_for_versions(data_bytes: bytes, max_version=MAX_QR_VERSION):
    """
    Try to create a QR code using ascending versions (1..max_version).
    For each version try error levels in ERROR_LEVELS order.
    Returns (qr_obj, version, ec_level) on success or (None, None, None) on failure.
    """
    for v in range(1, max_version + 1):
        for ec in ERROR_LEVELS:
            try:
                # segno.make accepts binary bytes when encoding='binary'
                qr = segno.make(data_bytes, error=ec, encoding="binary", version=v)
                return qr, v, ec
            except Exception:
                # DataOverflow or other -> try next ec or next version
                continue
    return None, None, None


def fits_within_limit(payload_bytes: bytes, app_priv, cert_map, cert_sig, max_version=MAX_QR_VERSION, compress_try=True):
    """
    Build container and test if it fits into any QR version <= max_version.
    Returns (True/False, used_compression_bool, qr_obj_or_None, version, ec_level)
    """
    # sign the payload
    # Note: sign must use the actual private key type. For Ed25519 this is app_priv.sign(payload)
    payload_sig = app_priv.sign(payload_bytes)

    container = {
        "payload": payload_bytes,
        "payload_sig": payload_sig,
        "cert": cert_map,
        "cert_sig": cert_sig
    }

    # CBOR encode
    cbor_bytes = cbor2.dumps(container)

    # try raw
    qr, v, ec = try_make_qr_for_versions(cbor_bytes, max_version=max_version)
    if qr is not None:
        return True, False, qr, v, ec

    # try compressed optionally
    if compress_try:
        compressed = zlib.compress(cbor_bytes, level=9)
        qr, v, ec = try_make_qr_for_versions(compressed, max_version=max_version)
        if qr is not None:
            return True, True, qr, v, ec

    return False, False, None, None, None


def find_max_payload_size(app_priv, cert_map, cert_sig, limit, max_version=MAX_QR_VERSION):
    """
    Binary search maximum payload length (in bytes) that fits into some QR <= max_version.
    We will test with a dummy payload of ASCII 'A' repeated N times.
    Returns integer max_len (>=0).
    """
    lo = 0
    hi = limit
    best = 0

    # Quick check: if even hi doesn't fit, we still find best by binary search
    while lo <= hi:
        mid = (lo + hi) // 2
        test_payload = b"A" * mid
        ok, used_comp, qr, v, ec = fits_within_limit(test_payload, app_priv, cert_map, cert_sig, max_version)
        if ok:
            best = mid
            lo = mid + 1
        else:
            hi = mid - 1

    return best


def main():
    parser = argparse.ArgumentParser(description="Create Ed25519-signed CBOR QR. Chooses smallest QR version <=26 that fits.")
    parser.add_argument("--payload", required=True, help="payload text or path to file when --file used")
    parser.add_argument("--file", action="store_true", help="treat --payload as path to a file")
    parser.add_argument("--app-priv", required=True, help="PEM private key (app) used to sign payload (Ed25519 recommended)")
    parser.add_argument("--cert-cbor", required=True, help="CBOR certificate envelope (created by create_cose_cert.py)")
    parser.add_argument("--out", default="secure_ed_qr.png", help="output PNG filename")
    parser.add_argument("--max-payload-limit", type=int, default=300, help="upper bound to search for maximum payload size (bytes). Default 300")
    parser.add_argument("--no-compress", action="store_true", help="do not attempt zlib compression if raw CBOR doesn't fit")
    args = parser.parse_args()

    # load keys and cert
    app_priv = load_priv(Path(args.app_priv))
    cert_map, cert_sig = load_cbor_cert(Path(args.cert_cbor))

    # Report maximum possible payload size (binary-search up to given limit)
    print("Calculating the maximum payload length (bytes) that fits into some QR version <= 26 ...")
    max_payload = find_max_payload_size(app_priv, cert_map, cert_sig, limit=args.max_payload_limit, max_version=MAX_QR_VERSION)
    print(f"Maximum payload length (in bytes) that fits in QR version <= {MAX_QR_VERSION} (search cap {args.max_payload_limit}): {max_payload} bytes")
    print("If your actual payload is longer, it will NOT fit into v<=26 (unless you reduce cert/payload or increase QR max version).")
    print("-----")

    # read actual payload
    if args.file:
        payload_bytes = Path(args.payload).read_bytes()
    else:
        payload_bytes = args.payload.encode("utf-8")

    print(f"Actual payload size: {len(payload_bytes)} bytes")
    if len(payload_bytes) > args.max_payload_limit:
        print(f"Warning: actual payload length {len(payload_bytes)} exceeds --max-payload-limit {args.max_payload_limit}. The earlier search may not be accurate.")
    if len(payload_bytes) > max_payload:
        print("ERROR: The provided payload is too large to fit into QR v<=26 with the current certificate & signature.")
        print(f"Allowed: {max_payload} bytes, provided: {len(payload_bytes)} bytes")
        return

    # build and test packing (try raw, then optional compress)
    compress_try = not args.no_compress
    ok, used_compression, qr_obj, version, ec = fits_within_limit(payload_bytes, app_priv, cert_map, cert_sig, max_version=MAX_QR_VERSION, compress_try=compress_try)

    if not ok:
        print("Failed: payload + cert + signatures do not fit in any QR version <= 26 (even after optional compression).")
        return

    # Save final bytes to .bin in addition to PNG, so the scanner can read exact bytes if needed.
    # We reconstruct the exact final bytes used (raw CBOR or compressed)
    # To do that we need to re-create the container and its CBOR bytes, then compress if used.
    payload_sig = app_priv.sign(payload_bytes)
    container = {
        "payload": payload_bytes,
        "payload_sig": payload_sig,
        "cert": cert_map,
        "cert_sig": cert_sig
    }
    cbor_bytes = cbor2.dumps(container)
    if used_compression:
        final_bytes = zlib.compress(cbor_bytes, level=9)
    else:
        final_bytes = cbor_bytes

    # Save binary and PNG
    #qr_obj.save(args.out, scale=4)
    # ensure PNG is plain RGB with white background (no alpha)
    qr_obj.save(args.out, scale=5, dark='black', light='white')

    #data = open("qr_package.cbor", "rb").read()
    #qr = segno.make(data, micro=False, error='L')
    #qr.save("secure_qr.png", kind='png', scale=5, dark='black', light='white', binary=True)


    Path(args.out + ".bin").write_bytes(final_bytes)

    print("QR successfully created.")
    print(f"Chosen QR version: {version}, error correction level: {ec}, compression used: {used_compression}")
    print(f"Output PNG: {args.out}")
    print(f"Output raw bytes (exact bytes embedded in QR): {args.out}.bin (size {len(final_bytes)} bytes)")

if __name__ == "__main__":
    main()