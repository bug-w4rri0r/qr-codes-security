#!/usr/bin/env python3
"""
Advanced QR Code Reader
Odczytuje i wyświetla szczegółowe informacje o kodach QR z plików PNG/JPG
- Dane (tekst i hex dump)
- Rozmiar w bajtach
- Typ kodowania
- Pozycja na obrazku
- Obsługuje wiele kodów QR na jednym obrazie

Usage (PowerShell):
  python qr_reader_full.py --file .\test_qr_images\test.png
  python qr_reader_full.py --file .\test_qr_images\test.png --debug
  python qr_reader_full.py --file .\test_qr_images\test.png --save-bin data.bin
"""

import argparse
import base64
import sys
from pathlib import Path
from PIL import Image


def hex_dump(data: bytes, width: int = 16) -> str:
    """Tworzy hexdump danych"""
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i : i + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join((chr(b) if 32 <= b < 127 else ".") for b in chunk)
        lines.append(f"{i:04x}  {hex_part:<{width*3}}  {ascii_part}")
    return "\n".join(lines)


def detect_encoding_type(data: bytes) -> str:
    """Próbuje określić typ kodowania danych"""
    if not data:
        return "EMPTY"
    
    # Spróbuj UTF-8
    try:
        data.decode('utf-8')
        return "UTF-8 TEXT"
    except:
        pass
    
    # Spróbuj ASCII
    try:
        data.decode('ascii')
        return "ASCII TEXT"
    except:
        pass
    
    # Spróbuj Latin-1
    try:
        data.decode('latin-1')
        # Sprawdzaj czy to binarne czy tekst
        text = data.decode('latin-1')
        if any(ord(c) < 32 and c not in '\n\r\t' for c in text):
            return "BINARY DATA"
        return "LATIN-1 TEXT"
    except:
        pass
    
    return "BINARY DATA"


def try_pyzbar(img: Image.Image) -> tuple:
    """Próbuje użyć pyzbar do odczytania kodów QR"""
    try:
        from pyzbar.pyzbar import decode
    except ImportError:
        return None, "pyzbar niedostępny"

    try:
        decoded = decode(img)
    except Exception as e:
        return None, f"Błąd pyzbar: {e}"

    if not decoded:
        return [], "Brak kodów QR"

    results = []
    for obj in decoded:
        results.append({
            "type": obj.type,
            "data": obj.data,
            "rect": getattr(obj, "rect", None),
            "quality": "pyzbar",
        })
    return results, "OK"


def try_opencv(img: Image.Image) -> tuple:
    """Próbuje użyć OpenCV do odczytania kodów QR"""
    try:
        import cv2
        import numpy as np
    except ImportError as e:
        return None, f"OpenCV niedostępny: {e}"

    try:
        arr = np.array(img.convert("RGB"))
        detector = cv2.QRCodeDetector()
        
        # Spróbuj detectAndDecodeMulit (OpenCV 4.7+)
        try:
            info_list, points, _ = detector.detectAndDecodeMulti(arr)
            results = []
            if info_list:
                for text in info_list:
                    if text:
                        results.append({
                            "type": "QR_CODE",
                            "data": text.encode("utf-8"),
                            "quality": "opencv-multi",
                        })
                if results:
                    return results, "OK (multi)"
        except:
            pass
        
        # Fallback na detectAndDecode
        text, pts, _ = detector.detectAndDecode(arr)
        if text:
            results = [{
                "type": "QR_CODE",
                "data": text.encode("utf-8"),
                "quality": "opencv-single",
            }]
            return results, "OK (single)"
        
        return [], "Brak kodów QR"
        
    except Exception as e:
        return None, f"Błąd OpenCV: {e}"


def main():
    parser = argparse.ArgumentParser(
        description="Zaawansowany odczytywacz kodów QR",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Przykłady:
  python qr_reader_full.py --file test.png
  python qr_reader_full.py --file test.png --debug
  python qr_reader_full.py --file test.png --save-bin output.bin
        """
    )
    parser.add_argument("--file", required=True, help="Ścieżka do pliku PNG/JPG")
    parser.add_argument("--save-bin", help="Zapisz dane pierwszego kodu QR do pliku binarnego")
    parser.add_argument("--debug", action="store_true", help="Wyświetl szczegółowy hexdump")
    parser.add_argument("--format", choices=["utf-8", "hex", "base64"], default="auto",
                        help="Format wyświetlania danych")
    
    args = parser.parse_args()

    # Otwórz obraz
    try:
        img = Image.open(args.file)
        print(f"📷 Obraz: {args.file}")
        print(f"   Rozmiar: {img.size[0]}x{img.size[1]} px, Format: {img.format}")
    except Exception as e:
        print(f"❌ Nie można otworzyć '{args.file}': {e}")
        sys.exit(2)

    # Spróbuj pyzbar najpierw (lepszy dla danych binarnych)
    results, msg = try_pyzbar(img)
    backend = "pyzbar"
    
    if results is None:
        # Fallback na OpenCV
        results, msg = try_opencv(img)
        backend = "opencv"

    print(f"🔍 Backend: {backend} -> {msg}\n")

    if not results:
        print("⚠️  Brak kodów QR na obrazie.")
        sys.exit(0)

    # Wyświetl wyniki
    for i, qr in enumerate(results, 1):
        data = qr.get("data", b"")
        qr_type = qr.get("type", "QR_CODE")
        encoding_type = detect_encoding_type(data)
        size_bytes = len(data)
        
        print("─" * 70)
        print(f"🎯 KOD QR #{i}")
        print("─" * 70)
        print(f"Typ:            {qr_type}")
        print(f"Rozmiar:        {size_bytes} bajtów")
        print(f"Kodowanie:      {encoding_type}")
        print(f"Backend:        {qr.get('quality', 'unknown')}")
        
        if qr.get("rect"):
            r = qr["rect"]
            print(f"Pozycja:        x={r.left}, y={r.top}, width={r.width}, height={r.height}")
        
        print("\nDane:")
        print("─" * 70)
        
        # Wyświetl dane w wybranym formacie
        if args.format == "hex" or encoding_type == "BINARY DATA":
            # Hex dump
            print("Hex:")
            print(hex_dump(data))
        elif args.format == "base64":
            print("Base64:")
            print(base64.b64encode(data).decode())
        else:  # auto
            # Spróbuj tekst, jeśli się nie uda, hex
            try:
                text = data.decode("utf-8")
                print("Tekst (UTF-8):")
                print(text)
                if len(text) > 200:
                    print(f"\n[... truncated, full size: {size_bytes} bytes ...]")
            except:
                print("Hex (dane binarne):")
                print(hex_dump(data))
        
        # Debug mode - pokaż wszystko
        if args.debug:
            print("\n[DEBUG]")
            print("Base64:", base64.b64encode(data).decode())
            print("\nHex dump:")
            print(hex_dump(data))
            print(f"\nRaw bytes (repr): {repr(data[:100])}")
        
        # Zapisz pierwszy kod do pliku
        if i == 1 and args.save_bin:
            try:
                with open(args.save_bin, "wb") as f:
                    f.write(data)
                print(f"\n✅ Zapisano dane do: {args.save_bin}")
            except Exception as e:
                print(f"\n❌ Błąd przy zapisie: {e}")
    
    print("\n" + "=" * 70)
    print(f"✅ Znaleziono {len(results)} kod(y) QR")
    print("=" * 70)


if __name__ == '__main__':
    main()
