import os
import sys
import subprocess
import argparse
import shutil
from pathlib import Path
import random
import string
import time

def get_script_path(script_name):
    """Finds the script in the current directory or cert_gen subdirectory."""
    if os.path.exists(script_name):
        return script_name
    elif os.path.exists(os.path.join("cert_gen", script_name)):
        return os.path.join("cert_gen", script_name)
    else:
        return None

def run_cmd(cmd, debug=False, step_name=""):
    if debug:
        print(f"\n[DEBUG - {step_name}] Executing command: {' '.join(cmd)}")
        
    # Copy environment variables and force UTF-8 encoding for subprocesses
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    
    # Run process with forced UTF-8 environment to prevent charmap errors on Windows
    result = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", env=env)
    
    if debug:
        if result.stdout:
            print(f"[DEBUG STDOUT]\n{result.stdout.strip()}")
        if result.stderr:
            print(f"[DEBUG STDERR]\n{result.stderr.strip()}")
    if result.returncode != 0:
        print(f"[ERROR] {step_name} failed!")
        if not debug:
            print(result.stderr)
        sys.exit(1)
    return result.stdout

def main():
    parser = argparse.ArgumentParser(description="2-Tier Secure QR Code Pipeline Benchmark")
    parser.add_argument("--debug", action="store_true", help="Enable verbose process logs")
    parser.add_argument("--count", type=int, default=10, help="Number of QR codes to generate and test (default: 10)")
    args = parser.parse_args()

    # Directory configuration
    CERT_DIR = Path("certs_vault")
    TRUSTED_DIR = Path("trusted_roots")
    IMG_DIR = Path("test_qr_images")
    
    CERT_DIR.mkdir(exist_ok=True)
    TRUSTED_DIR.mkdir(exist_ok=True)
    IMG_DIR.mkdir(exist_ok=True)

    # Realistic PKI Environment Names
    ROOT_NAME = "Global_Mobility_Root"
    APP_NAME = "Wroclaw_Transit_Auth"
    APP_SUBJECT = "PL_WRO_Transit_API"

    # File paths for testing infrastructure
    root_priv = CERT_DIR / f"{ROOT_NAME}_priv.pem"
    root_pub = CERT_DIR / f"{ROOT_NAME}_pub.pem"
    app_priv = CERT_DIR / f"{APP_NAME}_priv.pem"
    app_pub = CERT_DIR / f"{APP_NAME}_pub.pem"
    app_cert = CERT_DIR / f"{APP_NAME}_cert.cbor"
    trusted_root_dest = TRUSTED_DIR / f"{ROOT_NAME}_pub.pem"

    # Find tools (in root dir or cert_gen/)
    gen_keys_script = get_script_path("gen_ed_keys.py")
    create_cert_script = get_script_path("create_cose_cert.py")
    
    print("=== STAGE 1: PKI INFRASTRUCTURE GENERATION ===")
    if not gen_keys_script or not create_cert_script:
        print("[ERROR] Could not find 'gen_ed_keys.py' or 'create_cose_cert.py'. Ensure they are in the current or 'cert_gen/' directory.")
        sys.exit(1)

    # Step 1: Generate Root Keys
    print(f"-> Generating Root CA keys ({ROOT_NAME})...")
    run_cmd([sys.executable, gen_keys_script, "--root-name", ROOT_NAME, "--root-only", "--out-dir", str(CERT_DIR)], args.debug, "Root Keys Generation")

    # Step 2: Generate App Keys
    print(f"-> Generating Application keys ({APP_NAME})...")
    run_cmd([sys.executable, gen_keys_script, "--app-name", APP_NAME, "--app-only", "--out-dir", str(CERT_DIR)], args.debug, "App Keys Generation")

    # Step 3: Generate CBOR Certificate
    print(f"-> Generating CBOR Certificate for Subject: {APP_SUBJECT}...")
    run_cmd([sys.executable, create_cert_script, 
             "--root-priv", str(root_priv), 
             "--sub", APP_SUBJECT, 
             "--pub", str(app_pub), 
             "--not-after", "2030-12-31", 
             "--out", str(app_cert)], args.debug, "CBOR Certificate Generation")

    # Step 4: Copy ROOT public key to trusted store
    print("-> Copying Root CA public key to trusted_roots directory...")
    shutil.copy(root_pub, trusted_root_dest)
    print("[OK] Infrastructure ready.\n")

    # Pre-generate payloads
    payloads = []
    base_url = "https://api.mobility.wroclaw.pl/v1/verify-ticket"
    current_ts = int(time.time())

    for i in range(1, args.count + 1):
        ticket_id = ''.join(random.choices(string.ascii_uppercase + string.digits, k=12))
        sec_token = ''.join(random.choices(string.ascii_letters + string.digits, k=64))
        # Realistic payload: ~150 chars URL with query parameters
        payload = f"{base_url}?tkt={ticket_id}&ts={current_ts + i}&sig={sec_token}"
        payloads.append(payload)

    print(f"=== STAGE 2: BATCH QR CODE GENERATION ({args.count} CODES) ===")
    for i, payload in enumerate(payloads, 1):
        img_base = IMG_DIR / f"bench_qr_{i:02d}"
        
        print(f"[CREATE] QR {i:02d} | Payload: {payload[:60]}... (Total {len(payload)} bytes)")
        cmd_create = [
            sys.executable, "qr-create.py",
            "--payload", payload,
            "--app-priv", str(app_priv),
            "--cert-cbor", str(app_cert),
            "--out", str(img_base)
        ]
        run_cmd(cmd_create, args.debug, f"QR Generation {i}")

    print("\n=== STAGE 3: BATCH QR CODE READING & VERIFICATION ===")
    for i, original_payload in enumerate(payloads, 1):
        img_file = IMG_DIR / f"bench_qr_{i:02d}.png"
        
        cmd_read = [
            sys.executable, "qr-read.py",
            "--image", str(img_file),
            "--trusted-dir", str(TRUSTED_DIR)
        ]
        if args.debug:
            cmd_read.append("--debug")
            
        read_out = run_cmd(cmd_read, args.debug, f"QR Reading {i}")
        
        # Extract payload from standard output
        extracted_payload = "NOT FOUND"
        for line in read_out.splitlines():
            # Match part of the original payload to robustly find it in the output
            if "http" in line and "tkt=" in line:
                extracted_payload = line.strip()
                break
                
        print(f"[READ]   QR {i:02d} | Decoded: {extracted_payload[:60]}...")
        
        # Simple integrity check against expected payload
        if extracted_payload == original_payload:
            print(f"         Status: MATCH (Integrity Verified)")
        else:
            print(f"         Status: MISMATCH!")
            print(f"         Expected: {original_payload}")
            print(f"         Got:      {extracted_payload}")
            print(f"         ---> DETAILED ERROR OUTPUT FROM qr-read.py <---")
            # Wypisuje surowy log z readera, by zobaczyć co naprawdę poszło nie tak
            print(read_out.strip())
        print("-" * 70)

    print(f"\n[SUCCESS] 2-Tier Pipeline tested with {args.count} realistic QR codes!")

if __name__ == "__main__":
    main()

#     print("\n=== STAGE 3: BATCH QR CODE READING & VERIFICATION ===")
#     for i, original_payload in enumerate(payloads, 1):
#         img_file = IMG_DIR / f"bench_qr_{i:02d}.png"
        
#         cmd_read = [
#             sys.executable, "qr-read.py",
#             "--image", str(img_file),
#             "--trusted-dir", str(TRUSTED_DIR)
#         ]
#         if args.debug:
#             cmd_read.append("--debug")
            
#         read_out = run_cmd(cmd_read, args.debug, f"QR Reading {i}")
        
#         # Extract payload from standard output
#         extracted_payload = "NOT FOUND"
#         for line in read_out.splitlines():
#             # Match part of the original payload to robustly find it in the output
#             if "http" in line and "tkt=" in line:
#                 extracted_payload = line.strip()
#                 break
                
#         print(f"[READ]   QR {i:02d} | Decoded: {extracted_payload[:60]}...")
        
#         # Simple integrity check against expected payload
#         if extracted_payload == original_payload:
#             print(f"         Status: MATCH (Integrity Verified)")
#         else:
#             print(f"         Status: MISMATCH! \nExpected: {original_payload}\nGot: {extracted_payload}")
#         print("-" * 70)

#     print(f"\n[SUCCESS] 2-Tier Pipeline successfully tested with {args.count} realistic QR codes!")

# if __name__ == "__main__":
#     main()