======================================================
🇵🇱 WERSJA POLSKA: Zestaw komend - Secure QR Codes
======================================================

PRZYGOTOWANIE (upewnij sie, ze foldery istnieja):
mkdir -p certs_vault trusted_roots test_qr_images

======================================================
SCENARIUSZ 1: Root-Only (Bezposrednie zaufanie)
======================================================

1. Generowanie kluczy Root CA:
python cert_gen/gen_ed_keys.py --root-name "PWr-Campus" --root-only --out-dir ./certs_vault/

2. Kopiowanie klucza publicznego do zaufanych (dla skanera):
cp ./certs_vault/PWr-Campus_pub.pem ./trusted_roots/

3. Tworzenie kodu QR (podpisanego przez Root):
python qr-create.py --payload "Witaj na kampusie PWr (Tryb Bezposredni)!" --root-priv ./certs_vault/PWr-Campus_priv.pem --out ./test_qr_images/qr_pwr_campus_direct

4. Odczyt i weryfikacja kodu QR:
python qr-read.py --image ./test_qr_images/qr_pwr_campus_direct.png --trusted-dir ./trusted_roots/ --debug


======================================================
SCENARIUSZ 2: Root + App (Lancuch Certyfikatow)
======================================================
UWAGA: Wymaga kluczy Root z kroku 1 Scenariusza 1.

1. Generowanie kluczy dla aplikacji/wydzialu:
python cert_gen/gen_ed_keys.py --app-only --out-dir ./certs_vault/

2. Wystawienie certyfikatu przez Root dla aplikacji:
python cert_gen/create_cose_cert.py --root-priv ./certs_vault/PWr-Campus_priv.pem --iss "PWr-Campus" --sub "W4N-K34" --pub ./certs_vault/app_pub.pem --not-before "2024-01-01" --not-after "2030-12-31" --out ./certs_vault/cert_W4N_K34.cbor

3. Tworzenie kodu QR (podpisanego przez aplikacje + z certyfikatem):
python qr-create.py --payload "Dostep do laboratorium W4N-K34 przyznany." --app-priv ./certs_vault/app_priv.pem --cert-cbor ./certs_vault/cert_W4N_K34.cbor --out ./test_qr_images/qr_w4n_k34_chain

4. Odczyt i weryfikacja calego lancucha zaufania:
python qr-read.py --image ./test_qr_images/qr_w4n_k34_chain.png --trusted-dir ./trusted_roots/ --debug



======================================================
🇬🇧 ENGLISH VERSION: Command set - Secure QR Codes
======================================================

PREPARATION (make sure directories exist):
mkdir -p certs_vault trusted_roots test_qr_images

======================================================
SCENARIO 1: Root-Only (Direct Trust)
======================================================

1. Generate Root CA keys:
python cert_gen/gen_ed_keys.py --root-name "PWr-Campus" --root-only --out-dir ./certs_vault/

2. Copy the public key to trusted roots (for the scanner):
cp ./certs_vault/PWr-Campus_pub.pem ./trusted_roots/

3. Create the QR code (signed by Root):
python qr-create.py --payload "Welcome to PWr campus (Direct Trust)!" --root-priv ./certs_vault/PWr-Campus_priv.pem --out ./test_qr_images/qr_pwr_campus_direct

4. Read and verify the QR code:
python qr-read.py --image ./test_qr_images/qr_pwr_campus_direct.png --trusted-dir ./trusted_roots/ --debug


======================================================
SCENARIO 2: Root + App (Certificate Chain)
======================================================
NOTE: Requires Root keys from Step 1 of Scenario 1.

1. Generate keys for the application/department:
python cert_gen/gen_ed_keys.py --app-only --out-dir ./certs_vault/

2. Issue a certificate from Root for the application:
python cert_gen/create_cose_cert.py --root-priv ./certs_vault/PWr-Campus_priv.pem --iss "PWr-Campus" --sub "W4N-K34" --pub ./certs_vault/app_pub.pem --not-before "2024-01-01" --not-after "2030-12-31" --out ./certs_vault/cert_W4N_K34.cbor

3. Create the QR code (signed by the application + containing the certificate):
python qr-create.py --payload "Access to W4N-K34 lab granted." --app-priv ./certs_vault/app_priv.pem --cert-cbor ./certs_vault/cert_W4N_K34.cbor --out ./test_qr_images/qr_w4n_k34_chain

4. Read and verify the entire chain of trust:
python qr-read.py --image ./test_qr_images/qr_w4n_k34_chain.png --trusted-dir ./trusted_roots/ --debug