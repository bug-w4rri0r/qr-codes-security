# I.
python3 gen_ed_keys.py --gen-app --out-dir .

# python3 gen_ed_keys.py --root-name "firma_root-demo" --root-only --out-dir .\demo-test\ 
# python3 gen_ed_keys.py --root-only --out-dir .
# python3 gen_ed_keys.py --root-name "PWr-Campus" --root-only --out-dir .\demo-test\
# teraz masz root_priv.pem, root_pub.pem, app_priv.pem, app_pub.pem


# II.
python3 create_cose_cert.py --root-priv root_priv.pem --sub app1 --pub app_pub.pem --not-after 2030-01-01 --out app_cert.cbor
# Add root_pub.pem to the 'trusted_roots/'


# III. 
python3 create_qr_ed25519.py --payload "https://example.com/short" --app-priv app_priv.pem --cert-cbor app_cert.cbor -o secure_ed_qr.png
#

# IV.
python3 scan_qr_ed25519.py --file secure_ed_qr.png --trusted-dir trusted_roots
#

# example runs:
python3 create_qr_ed25519.py --payload payload.txt --file --app-priv ./cert_keys/app_priv.pem --cert-cbor ./cert_keys/app_cert.cbor --out ./test_qr_images/secure_ed_qr_v1.4.png 

python3 scan_qr_ed25519.py --file ./test_qr_images/secure_ed_qr_v1.4.png --trusted-dir ./trusted_roots --dump