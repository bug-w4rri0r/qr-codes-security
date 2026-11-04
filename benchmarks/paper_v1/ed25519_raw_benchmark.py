import time
from cryptography.hazmat.primitives.asymmetric import ed25519

# Generowanie klucza do testu
private_key = ed25519.Ed25519PrivateKey.generate()
public_key = private_key.public_key()
data = b"Przykladowy payload z certyfikatem CBOR o rozmiarze okolo 100 bajtow"

iterations = 10000

# TEST 1: Podpisywanie
start_time = time.time()
for _ in range(iterations):
    signature = private_key.sign(data)
end_time = time.time()
sign_time = end_time - start_time

# TEST 2: Weryfikacja
start_time_v = time.time()
for _ in range(iterations):
    public_key.verify(signature, data)
end_time_v = time.time()
verify_time = end_time_v - start_time_v

print(f"--- WYNIKI BENCHMARKU Ed25519 ---")
print(f"Wygenerowano {iterations} podpisow w {sign_time:.4f} s.")
print(f"Szybkosc PODPISYWANIA: {iterations/sign_time:.0f} operacji / sekunde.")
print(f"Zweryfikowano {iterations} podpisow w {verify_time:.4f} s.")
print(f"Szybkosc WERYFIKACJI: {iterations/verify_time:.0f} operacji / sekunde.")