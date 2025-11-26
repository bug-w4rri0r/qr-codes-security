#!/usr/bin/env python3
"""Compare OpenCV-decoded PNG with .bin file."""

from PIL import Image
import cv2
import numpy as np

# Load PNG and convert to grayscale for OpenCV
img = Image.open('test_qr_images/test_qr_v1.2.png')
img_gray = img.convert('L')  # Grayscale
img_array = np.array(img_gray)

detector = cv2.QRCodeDetector()

# Try detectAndDecode (returns string)
decoded_text, points, straight = detector.detectAndDecode(img_array)
print('detectAndDecode (string) length:', len(decoded_text) if decoded_text else 'None')
if decoded_text:
    decoded_bytes = decoded_text.encode('utf-8')  # This is wrong! String was already corrupted
    print('  Hex:', decoded_bytes.hex()[:60])

# Try decoding with latin1 (lossless re-encode)
if decoded_text:
    try:
        # Reverse UTF-8 mangling: interpret as latin1 (raw bytes)
        decoded_latin1 = decoded_text.encode('latin-1')
        print()
        print('Decoded as latin-1 (should be raw bytes):', decoded_latin1.hex()[:60])
    except Exception as e:
        print('  latin-1 encode failed:', e)

print()

# Load .bin for comparison
with open('test_qr_images/test_qr_v1.2.png.bin', 'rb') as f:
    bin_data = f.read()
print('.bin file (length):', len(bin_data))
print('.bin file (hex):', bin_data.hex()[:60])

