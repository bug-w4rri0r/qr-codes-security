#!/usr/bin/env python3
"""
Simple QR reader for PNG files.
- Prefers `pyzbar` (returns raw bytes correctly, supports binary payloads)
- Falls back to OpenCV `QRCodeDetector` if `pyzbar` isn't available (warnings apply)

Usage examples (PowerShell):
  python qr_read_png.py --file .\test_qr_images\test_qr_v1.2.png --debug
  python qr_read_png.py --file input.png --save-bin out.bin
"""

import argparse
import base64
import binascii
import sys
from PIL import Image


def hex_dump(data: bytes, width: int = 16) -> str:
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i : i + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join((chr(b) if 32 <= b < 127 else ".") for b in chunk)
        lines.append(f"{i:04x}  {hex_part:<{width*3}}  {ascii_part}")
    return "\n".join(lines)


def try_pyzbar(img: Image.Image):
    try:
        from pyzbar.pyzbar import decode
    except Exception:
        return None, "pyzbar not available"

    try:
        decoded = decode(img)
    except Exception as e:
        return None, f"pyzbar.decode failed: {e}"

    if not decoded:
        return [], "no QR codes found"

    results = []
    for i, obj in enumerate(decoded):
        data = obj.data  # bytes
        results.append({
            "type": obj.type,
            "data": data,
            "rect": getattr(obj, "rect", None),
        })
    return results, "ok"


def try_opencv(img: Image.Image):
    try:
        import cv2
        import numpy as np
    except Exception as e:
        return None, f"opencv not available: {e}"

    arr = np.array(img.convert("RGB"))
    detector = cv2.QRCodeDetector()

    # detectAndDecode returns (text, points, straight_qrcode)
    try:
        text, pts, straight = detector.detectAndDecode(arr)
    except Exception as e:
        return None, f"detectAndDecode failed: {e}"

    results = []
    if text:
        # OpenCV returns text (str). Re-encode as latin-1 to preserve bytes
        # but note: if OpenCV dropped NULs or characters during decode, data may be truncated.
        raw = text.encode("latin-1")
        results.append({"type": "QR_CODE", "data": raw, "points": pts is not None})
        return results, "ok"

    # try multi if available
    try:
        info_list, points, _ = detector.detectAndDecodeMulti(arr)
    except Exception:
        info_list = None

    if info_list:
        for s in info_list:
            if s:
                results.append({"type": "QR_CODE", "data": s.encode("latin-1")})
        return results, "ok"

    return [], "no QR codes found"


def main():
    p = argparse.ArgumentParser(description="Read QR codes from PNG and print/save raw bytes")
    p.add_argument("--file", required=True, help="PNG/JPG image path")
    p.add_argument("--save-bin", help="Save first QR raw bytes to this file")
    p.add_argument("--debug", action="store_true", help="Print debug info and dumps")
    args = p.parse_args()

    try:
        img = Image.open(args.file)
    except Exception as e:
        print(f"Cannot open image '{args.file}': {e}")
        sys.exit(2)

    # Try pyzbar first (recommended for binary-safe reads)
    res, msg = try_pyzbar(img)
    backend = "pyzbar"
    if res is None:
        # pyzbar not available, fallback to OpenCV
        res, msg = try_opencv(img)
        backend = "opencv"

    print(f"Backend: {backend} -> {msg}")

    if not res:
        print("No QR codes found.")
        sys.exit(0)

    for i, entry in enumerate(res, 1):
        data = entry.get("data", b"")
        print("\n" + "-"*60)
        print(f"QR #{i}  type: {entry.get('type')}  bytes: {len(data)}")

        # Try UTF-8 decode for human-readable payloads
        try:
            text = data.decode("utf-8")
            print("Decoded (utf-8):\n", text)
        except Exception:
            print("Decoded (utf-8): <binary or non-utf8 data>")
            print("Base64:", base64.b64encode(data).decode())

        if args.debug:
            print("Hex dump:")
            print(hex_dump(data))

        if i == 1 and args.save_bin:
            try:
                with open(args.save_bin, "wb") as f:
                    f.write(data)
                print(f"Saved first QR raw bytes to: {args.save_bin}")
            except Exception as e:
                print(f"Failed to save to {args.save_bin}: {e}")

    print("\nDone.")


if __name__ == '__main__':
    main()
