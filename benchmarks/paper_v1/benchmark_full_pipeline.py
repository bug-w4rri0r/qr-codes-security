import time
import os
import segno
import cv2
import cbor2
import zlib
import base64
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature

# --- Configuration ---
ITERATIONS = 1000
OUT_DIR = "test_benchmark_qrs"
os.makedirs(OUT_DIR, exist_ok=True)

print(f"--- STARTING FULL PIPELINE BENCHMARK ({ITERATIONS} iterations) ---")

# Key Generation (Direct Trust Mode)
root_priv = ed25519.Ed25519PrivateKey.generate()
root_pub = root_priv.public_key()

# =====================================================================
# PHASE 1: QR CODE GENERATION & SAVING
# =====================================================================
print("Phase 1: Generating and saving QR codes...")
start_gen = time.time()

for i in range(ITERATIONS):
    # 1. Unique payload
    payload = f"Test city ticket #{i}, generated for the parking system."
    
    # 2. Cryptographic Signature (Ed25519)
    signature = root_priv.sign(payload.encode('utf-8'))
    
    # 3. CBOR Structure (Mode A - Direct Trust)
    cbor_data = cbor2.dumps({
        "payload": payload,
        "payload_sig": signature
    })
    
    # 4. Zlib Compression and Base64 Encoding
    compressed = zlib.compress(cbor_data, level=9)
    b64_data = base64.b64encode(compressed).decode('utf-8')
    
    # 5. Rendering and saving physical QR code image
    qr = segno.make(b64_data, error='H')
    qr.save(f"{OUT_DIR}/qr_{i}.png", scale=3)

end_gen = time.time()
gen_time = end_gen - start_gen


# =====================================================================
# PHASE 2: QR CODE READING & VERIFICATION
# =====================================================================
print("Phase 2: Reading and verifying QR codes (Computer Vision + Crypto)...")
start_read = time.time()
detector = cv2.QRCodeDetector()

success_count = 0
failure_count = 0

for i in range(ITERATIONS):
    # 1. Load image from disk
    img = cv2.imread(f"{OUT_DIR}/qr_{i}.png")
    
    # 2. Visual QR decoding using OpenCV
    data_str, _, _ = detector.detectAndDecode(img)
    
    if not data_str:
        print(f"[ERROR] Failed to visually read QR code: {i}")
        failure_count += 1
        continue
        
    try:
        # 3. Base64 decoding and Zlib decompression
        compressed_back = base64.b64decode(data_str)
        cbor_back = zlib.decompress(compressed_back)
        
        # 4. CBOR unpacking
        parsed_data = cbor2.loads(cbor_back)
        
        # 5. Cryptographic verification
        root_pub.verify(parsed_data["payload_sig"], parsed_data["payload"].encode('utf-8'))
        success_count += 1
        
    except InvalidSignature:
        print(f"[ERROR] Invalid signature for QR code: {i}")
        failure_count += 1
    except Exception as e:
        print(f"[ERROR] Unexpected error processing QR code {i}: {e}")
        failure_count += 1

end_read = time.time()
read_time = end_read - start_read


# =====================================================================
# RESULTS & METRICS CALCULATION
# =====================================================================
gen_ms_per_op = (gen_time / ITERATIONS) * 1000
gen_ops_per_sec = ITERATIONS / gen_time

read_ms_per_op = (read_time / ITERATIONS) * 1000
read_ops_per_sec = ITERATIONS / read_time

print("\n==================================================")
print("       FULL PIPELINE BENCHMARK RESULTS")
print("==================================================")
print(f"Successful verifications: {success_count} / {ITERATIONS}")
print(f"Failed verifications:     {failure_count} / {ITERATIONS}")
print("-" * 50)
print("1. GENERATION PHASE (CBOR + Zlib + Sign + PNG)")
print(f"   Total time:  {gen_time:.2f} seconds")
print(f"   Throughput:  {gen_ops_per_sec:.0f} ops/sec")
print(f"   Time per op: {gen_ms_per_op:.2f} ms")
print("-" * 50)
print("2. VERIFICATION PHASE (OpenCV + Unzip + Parse + Verify)")
print(f"   Total time:  {read_time:.2f} seconds")
print(f"   Throughput:  {read_ops_per_sec:.0f} ops/sec")
print(f"   Time per op: {read_ms_per_op:.2f} ms")
print("==================================================")