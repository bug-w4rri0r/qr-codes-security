#!/usr/bin/env python3
"""
Simple QR Scanner (uses OpenCV)

This script reads a PNG file containing a QR code and attempts to decode it
using OpenCV. It prints the decoded content to stdout.

Usage examples:
  python scanner/scanner.py --image qr_img/basic_qr_test1.png
"""

import argparse
import cv2
import sys
from pathlib import Path

def scan_qr(image_path: Path):
    """
    Reads image from image_path and decodes QR code using OpenCV.
    """
    # 1. Sprawdzenie czy plik istnieje / Check if file exists
    if not image_path.exists():
        print(f"Error: File not found: {image_path}")
        sys.exit(1)

    # 2. Wczytanie obrazu / Load image
    # cv2.imread zwraca None jeśli nie uda się wczytać obrazu
    img = cv2.imread(str(image_path))
    if img is None:
        print(f"Error: Could not read image (format unsupported or file corrupted): {image_path}")
        sys.exit(1)

    # 3. Inicjalizacja detektora QR / Initialize QR Detector
    detector = cv2.QRCodeDetector()

    # 4. Wykrywanie i dekodowanie / Detect and Decode
    # detectAndDecode zwraca krotkę: (decoded_info, points, straight_qrcode)
    data, points, _ = detector.detectAndDecode(img)

    if points is None:
        print("No QR code detected in the image.")
        return
    
    if data:
        print("-" * 40)
        print(f"SUCCESS: QR Code found in {image_path.name}")
        print("-" * 40)
        print("Decoded Content:")
        print(data)
        print("-" * 40)
    else:
        # Czasami QR jest wykryty (points is not None), ale nie udało się go odkodować
        # (np. uszkodzony, zbyt zniekształcony lub specyficzne kodowanie binarne)
        print("QR code detected, but failed to decode the data.")
        print("The QR might contain raw binary data not compatible with simple text decoding.")

def main():
    parser = argparse.ArgumentParser(description="Read QR code from a PNG file using OpenCV")
    parser.add_argument("--image", required=True, help="Path to the PNG file containing QR code")
    
    args = parser.parse_args()
    
    img_path = Path(args.image)
    scan_qr(img_path)

if __name__ == "__main__":
    main()