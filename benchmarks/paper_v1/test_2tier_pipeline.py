import os
import sys
import subprocess
import argparse
import shutil
from pathlib import Path
import random
import string

def get_script_path(script_name):
    """Szuka skryptu w obecnym katalogu lub w podkatalogu cert_gen"""
    if os.path.exists(script_name):
        return script_name
    elif os.path.exists(os.path.join("cert_gen", script_name)):
        return os.path.join("cert_gen", script_name)
    else:
        return None

# def run_cmd(cmd, debug=False, step_name=""):
#     if debug:
#         print(f"\n[DEBUG - {step_name}] Wykonywanie komendy: {' '.join(cmd)}")
#     result = subprocess.run(cmd, capture_output=True, text=True)
#     if debug:
#         if result.stdout:
#             print(f"[DEBUG STDOUT]\n{result.stdout.strip()}")
#         if result.stderr:
#             print(f"[DEBUG STDERR]\n{result.stderr.strip()}")
#     if result.returncode != 0:
#         print(f"[BŁĄD] {step_name} zakończone niepowodzeniem!")
#         if not debug:
#             print(result.stderr)
#         sys.exit(1)
#     return result.stdout

def run_cmd(cmd, debug=False, step_name=""):
    if debug:
        print(f"\n[DEBUG - {step_name}] Wykonywanie komendy: {' '.join(cmd)}")
        
    # Kopiujemy zmienne środowiskowe i wymuszamy na podprocesie kodowanie UTF-8
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    
    # Dodajemy env=env oraz encoding="utf-8" do wywołania
    result = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", env=env)
    
    if debug:
        if result.stdout:
            print(f"[DEBUG STDOUT]\n{result.stdout.strip()}")
        if result.stderr:
            print(f"[DEBUG STDERR]\n{result.stderr.strip()}")
    if result.returncode != 0:
        print(f"[BŁĄD] {step_name} zakończone niepowodzeniem!")
        if not debug:
            print(result.stderr)
        sys.exit(1)
    return result.stdout

def main():
    parser = argparse.ArgumentParser(description="Test dwuwarstwowego potoku QR")
    parser.add_argument("--debug", action="store_true", help="Włącz dokładne logi z procesów")
    args = parser.parse_args()

    # Konfiguracja ścieżek
    CERT_DIR = Path("certs_vault")
    TRUSTED_DIR = Path("trusted_roots")
    IMG_DIR = Path("test_qr_images")
    
    CERT_DIR.mkdir(exist_ok=True)
    TRUSTED_DIR.mkdir(exist_ok=True)
    IMG_DIR.mkdir(exist_ok=True)

    # Nazwy plików dla infrastruktury testowej
    root_priv = CERT_DIR / "root_Ca_bench_priv.pem"
    root_pub = CERT_DIR / "root_Ca_bench_pub.pem"
    app_priv = CERT_DIR / "app_test_bench_priv.pem"
    app_pub = CERT_DIR / "app_test_bench_pub.pem"
    app_cert = CERT_DIR / "app_test_bench_cert.cbor"
    trusted_root_dest = TRUSTED_DIR / "root_Ca_bench_pub.pem"

    # Wyszukiwanie narzędzi (w katalogu głównym lub cert_gen)
    gen_keys_script = get_script_path("gen_ed_keys.py")
    create_cert_script = get_script_path("create_cose_cert.py")
    
    print("=== ETAP 1: GENEROWANIE INFRASTRUKTURY PKI ===")
    if not gen_keys_script or not create_cert_script:
        print("[BŁĄD] Nie znaleziono skryptów 'gen_ed_keys.py' lub 'create_cose_cert.py'. Upewnij się, że są w głównym katalogu lub 'cert_gen/'.")
        sys.exit(1)

    # Krok 1: Generowanie kluczy Root
    print("-> Generowanie kluczy Root CA...")
    run_cmd([sys.executable, gen_keys_script, "--root-name", "root_Ca_bench", "--root-only", "--out-dir", str(CERT_DIR)], args.debug, "Klucze Root")

    # Krok 2: Generowanie kluczy App
    print("-> Generowanie kluczy Aplikacji (App)...")
    run_cmd([sys.executable, gen_keys_script, "--app-name", "app_test_bench", "--app-only", "--out-dir", str(CERT_DIR)], args.debug, "Klucze App")

    # Krok 3: Generowanie certyfikatu CBOR
    print("-> Generowanie certyfikatu CBOR dla Aplikacji...")
    run_cmd([sys.executable, create_cert_script, 
             "--root-priv", str(root_priv), 
             "--sub", "TestApp", 
             "--pub", str(app_pub), 
             "--not-after", "2030-01-01", 
             "--out", str(app_cert)], args.debug, "Certyfikat CBOR")

    # Krok 4: Kopiowanie klucza publicznego ROOT do zaufanych
    print("-> Kopiowanie Root CA do zaufanego magazynu (trusted_roots)...")
    shutil.copy(root_pub, trusted_root_dest)
    print("[OK] Infrastruktura gotowa.\n")

    print("=== ETAP 2: GENEROWANIE I ODCZYT (10 KODÓW) ===")
    
    PAYLOAD_PREFIX = "https://pwr.edu.pl/ticket/"
    
    for i in range(1, 11):
        # Losowy payload (łącznie 45 znaków)
        random_str = ''.join(random.choices(string.ascii_letters + string.digits, k=15))
        payload = f"{PAYLOAD_PREFIX}{i:02d}-{random_str}"
        img_base = IMG_DIR / f"bench_qr_{i:02d}"
        
        # GENEROWANIE
        print(f"[CREATE] QR {i:02d} | Payload wgrany: {payload}")
        cmd_create = [
            sys.executable, "qr-create.py",
            "--payload", payload,
            "--app-priv", str(app_priv),
            "--cert-cbor", str(app_cert),
            "--out", str(img_base)
        ]
        run_cmd(cmd_create, args.debug, f"Generowanie QR {i}")

        # ODCZYT
        img_file = f"{img_base}.png"
        cmd_read = [
            sys.executable, "qr-read.py",
            "--image", img_file,
            "--trusted-dir", str(TRUSTED_DIR)
        ]
        if args.debug:
            cmd_read.append("--debug")
            
        read_out = run_cmd(cmd_read, args.debug, f"Odczyt QR {i}")
        
        # Ekstrakcja zdekodowanego tekstu z wyjścia
        # Skaner z reguły wypisuje payload gdzieś na standardowe wyjście, spróbujmy go wyłuskać
        extracted_payload = "NIE ZNALEZIONO"
        for line in read_out.splitlines():
            if "Payload" in line or payload in line or "http" in line:
                extracted_payload = line.strip()
                break
                
        print(f"[READ]   QR {i:02d} | Odczyt z QR:   {extracted_payload}")
        print("-" * 60)

    print("\n[SUKCES] Pipeline dwuwarstwowy przetestowany pomyślnie!")

if __name__ == "__main__":
    main()