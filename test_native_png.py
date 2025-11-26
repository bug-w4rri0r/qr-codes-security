#!/usr/bin/env python3
from PIL import Image
import cv2
import numpy as np

img = Image.open('./test_qr_images/test_qr_native.png')
img_gray = img.convert('L')
img_array = np.array(img_gray)

detector = cv2.QRCodeDetector()
decoded_text, points, _ = detector.detectAndDecode(img_array)

if decoded_text:
    raw = decoded_text.encode('latin-1')
    print(f'Extracted: {len(raw)} bytes')
    print(f'Hex: {raw.hex()[:100]}')
else:
    print('No QR found')

# Compare with .bin
with open('./test_qr_images/test_qr_native.svg.bin', 'rb') as f:
    bin_data = f.read()
print()
print(f'Expected (.bin): {len(bin_data)} bytes')
print(f'Hex: {bin_data.hex()[:100]}')
print()
if decoded_text:
    print(f'Match: {raw == bin_data}')
