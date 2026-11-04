import os
import sys
import time
import subprocess
import random
import string
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

# --- CONFIGURATION ---
ITERATIONS = 100  # Default set to 100 because calling external CLI scripts adds OS process overhead
PAYLOAD_PREFIX = "https://pwr.edu.pl/ticket/"
TARGET_PAYLOAD_LENGTH = 60

# Dirs setup based on your structure
CERT_DIR = Path("bench_cert_vault")
IMG_DIR = Path("bench_test_qr_images")
CERT_DIR.mkdir(exist_ok=True)
IMG_DIR.mkdir(exist_ok=True)

ROOT_PRIV = CERT_DIR / "bench_root_priv.pem"
ROOT_PUB = CERT_DIR / "bench_root_pub.pem"

def generate_random_url(prefix: str, total_len: int) -> str:
    """Generates a URL padded with random chars to match total_len."""
    random_len = total_len - len(prefix)
    if random_len < 0:
        return prefix
    random_str = ''.join(random.choices(string.ascii_letters + string.digits, k=random_len))
    return prefix + random_str

print(f"--- 1. GENERATING NEW ROOT CA KEYS ---")
private_key = ed25519.Ed25519PrivateKey.generate()
public_key = private_key.public_key()

ROOT_PRIV.write_bytes(private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
))
ROOT_PUB.write_bytes(public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
))
print(f"[OK] Keys securely saved to {CERT_DIR}")

print(f"\n--- 2. BENCHMARKING GENERATION ({ITERATIONS} iterations) ---")
print("Executing your qr-create.py script via CLI...")
start_gen = time.time()
gen_success = 0

for i in range(ITERATIONS):
    payload = generate_random_url(f"{PAYLOAD_PREFIX}{i:04d}/", TARGET_PAYLOAD_LENGTH)
    out_file = IMG_DIR / f"bench_qr_{i}"
    
    cmd = [
        sys.executable, "qr-create.py",
        "--payload", payload,
        "--root-priv", str(ROOT_PRIV),
        "--out", str(out_file)
    ]
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode == 0:
        gen_success += 1
    else:
        print(f"[ERROR] Generation failed for QR {i}: {result.stderr}")

end_gen = time.time()
gen_time = end_gen - start_gen

print(f"\n--- 3. BENCHMARKING VERIFICATION ({ITERATIONS} iterations) ---")
print("Executing your qr-read.py script via CLI...")
start_read = time.time()
read_success = 0

for i in range(ITERATIONS):
    img_file = IMG_DIR / f"bench_qr_{i}.png"
    
    cmd = [
        sys.executable, "qr-read.py",
        "--image", str(img_file),
        "--trusted-dir", str(CERT_DIR)
    ]
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    # We look for the success message defined in your qr-read.py
    if "SUCCESS: DATA VERIFIED AND SECURE" in result.stdout:
        read_success += 1
    else:
        print(f"[ERROR] Read/Verify failed for QR {i}")

end_read = time.time()
read_time = end_read - start_read

# --- METRICS & ANALYSIS ---
gen_ms_per_op = (gen_time / ITERATIONS) * 1000
read_ms_per_op = (read_time / ITERATIONS) * 1000

print("\n==================================================")
print("       REAL SCRIPT PIPELINE BENCHMARK RESULTS")
print("==================================================")
print(f"Generated successfully: {gen_success} / {ITERATIONS}")
print(f"Read successfully:      {read_success} / {ITERATIONS}")
print("-" * 50)
print("1. GENERATION PHASE (Calling qr-create.py)")
print(f"   Total time:  {gen_time:.2f} s")
print(f"   Time per op: {gen_ms_per_op:.2f} ms")
print("-" * 50)
print("2. VERIFICATION PHASE (Calling qr-read.py)")
print(f"   Total time:  {read_time:.2f} s")
print(f"   Time per op: {read_ms_per_op:.2f} ms")
print("==================================================")
print("NOTE: These times include Python interpreter startup overhead")
print("for every iteration, simulating real-world CLI usage.")