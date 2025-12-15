#!/usr/bin/env python3
"""
Simple QR Scanner (MVP)
Odczytuje tekst z pliku obrazka QR.
"""
import argparse
import cv2
import sys
from pathlib import Path

def main():
    parser = argparse.ArgumentParser(description="Odczytaj prosty kod QR")
    parser.add_argument("--file", required=True, help="Ścieżka do pliku obrazka (png/jpg)")
    args = parser.parse_args()

    path = Path(args.file)
    if not path.exists():
        print(f"Błąd: Plik {args.file} nie istnieje.")
        sys.exit(1)

    # Wczytanie obrazu przez OpenCV
    img = cv2.imread(str(path))
    
    # Inicjalizacja detektora QR
    detector = cv2.QRCodeDetector()
    
    # Detekcja i dekodowanie
    data, bbox, straight_qrcode = detector.detectAndDecode(img)

    if bbox is not None and data:
        print("-" * 30)
        print("SUKCES: Kod QR został odczytany.")
        print("-" * 30)
        print(f"ODCZYTANA ZAWARTOŚĆ:\n{data}")
        print("-" * 30)
    else:
        print("BŁĄD: Nie udało się wykryć lub odczytać kodu QR na tym obrazku.")

if __name__ == "__main__":
    main()