#!/usr/bin/env python3
"""
Simple QR Generator (selects smallest version up to v26)

This script chooses the smallest QR version (<= 26) that can encode the
provided input. It tries multiple error-correction levels and picks the
combination that produces the smallest QR version. The script supports reading
the input from a text argument or from a file. It always writes a PNG image
and a companion raw bytes file (.png.bin) into a folder named `qr_img`.

Usage examples:
  python scanner/generator.py --text "Hello"              # text input
  python scanner/generator.py --input-file data.bin        # binary file input

Notes:
- When input is read from file, the script encodes data in binary mode.
- The script will not create QR versions larger than 26; if data is too
  large it will print an error and exit.
"""

import argparse
from pathlib import Path
import segno
from typing import Tuple, Union


# Error correction preference order (from highest capacity to strongest):
ERROR_LEVELS = ("L", "M", "Q", "H")
MAX_QR_VERSION = 26


def choose_best_qr(data: Union[str, bytes]) -> Tuple[segno.QRCode, str]:
    """
    Choose the smallest QR code (version <= MAX_QR_VERSION) that can encode
    `data`. The function iterates over error-correction levels and requests
    segno to produce the minimal version possible for that level. For bytes
    input, segno is invoked with `encoding='binary'`.

    Returns:
        (qr_object, error_level) on success, or (None, None) if nothing fits.
    """
    best_qr = None
    best_ec = None

    for ec in ERROR_LEVELS:
        try:
            # If data is bytes, request binary encoding; otherwise let segno
            # choose the appropriate textual encoding.
            if isinstance(data, (bytes, bytearray)):
                qr = segno.make(data, error=ec, encoding="binary")
            else:
                qr = segno.make(data, error=ec)
        except Exception:
            # segno may raise if it cannot encode using given options
            continue

        # Accept only QR versions <= MAX_QR_VERSION
        if qr.version <= MAX_QR_VERSION:
            if best_qr is None or qr.version < best_qr.version:
                best_qr = qr
                best_ec = ec
            elif qr.version == best_qr.version:
                # If same version choose stronger error correction (H preferred)
                pref_order = {"L": 3, "M": 2, "Q": 1, "H": 0}
                if pref_order.get(ec, 99) < pref_order.get(best_ec, 99):
                    best_qr = qr
                    best_ec = ec

    return best_qr, best_ec


def main() -> None:
    """
    Command-line entry point.

    Options:
      --text TEXT        Provide input as a simple text string.
      --input-file PATH  Read raw bytes from PATH and encode as binary in QR.
      --out NAME         Base output name (without extension). Defaults to
                         'basic_qr_test1' inside `qr_img` directory.
      --scale N          Pixel scale for PNG output (default: 10).
    """
    parser = argparse.ArgumentParser(description="Generate smallest QR (<=v26) and save PNG+BIN")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--text", help="Text to encode into QR")
    group.add_argument("--input-file", help="Path to a file to read as binary input")
    parser.add_argument("--out", default="basic_qr_test1", help="Output base name (no extension). Saved under ./qr_img/")
    parser.add_argument("--scale", type=int, default=10, help="PNG scale (pixels per module). Default 10")
    args = parser.parse_args()

    # Build output directory and file paths
    out_dir = Path.cwd() / "qr_img"
    out_dir.mkdir(parents=True, exist_ok=True)

    # Determine input bytes or text
    if args.input_file:
        input_path = Path(args.input_file)
        if not input_path.exists():
            print(f"Error: input file not found: {input_path}")
            return
        data = input_path.read_bytes()
        print(f"Read {len(data)} bytes from {input_path}")
    else:
        data = args.text
        print(f"Encoding text: '{data}'")

    # Choose best QR code (smallest version <= MAX_QR_VERSION)
    qr, ec = choose_best_qr(data)
    if qr is None:
        print("Error: data does not fit into any QR version <= 26 for tested error levels.")
        print("Try shortening the input or reducing embedded metadata.")
        return

    # Prepare output filenames. PNG filename: <out>.png, BIN filename: <out>.png.bin
    png_name = f"{args.out}.png" if not args.out.endswith(".png") else args.out
    png_path = out_dir / png_name
    bin_path = out_dir / (png_name + ".bin")

    try:
        # Save PNG with specified scale for readability/printing
        qr.save(str(png_path), scale=args.scale, border=4)
        print(f"Saved PNG: {png_path}")

        # Save raw bytes embedded in QR - when using binary encoding we can
        # simply write the same bytes we passed to segno. For text input write
        # UTF-8 bytes.
        if isinstance(data, (bytes, bytearray)):
            raw_bytes = bytes(data)
        else:
            raw_bytes = str(data).encode("utf-8")

        bin_path.write_bytes(raw_bytes)
        print(f"Saved raw bytes: {bin_path} (size {bin_path.stat().st_size} bytes)")

        print(f"Chosen QR version: {qr.version}, error correction: {ec}")
    except Exception as e:
        print(f"Error writing outputs: {e}")


if __name__ == "__main__":
    main()