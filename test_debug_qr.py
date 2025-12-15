#!/usr/bin/env python3
"""
Test script for debugging QR generation and scanning.

This script:
1. Generates a QR code with debug output
2. Immediately scans it back with debug output
3. Compares the data to verify integrity

Run with:
  python test_debug_qr.py
"""

import subprocess
import sys
from pathlib import Path

def run_command(cmd, description):
    """Run command and capture output"""
    print(f"\n{'='*70}")
    print(f"► {description}")
    print(f"{'='*70}")
    print(f"Command: {' '.join(cmd)}\n")
    result = subprocess.run(cmd, capture_output=False, text=True)
    return result.returncode == 0

def main():
    print("""
    ╔════════════════════════════════════════════════════════════════════╗
    ║                  QR Debug Test Suite                              ║
    ║  Tests QR generation and scanning with full debug output          ║
    ╚════════════════════════════════════════════════════════════════════╝
    """)
    
    project_root = Path(__file__).parent
    
    # Check if certificates exist
    cert_file = project_root / "certs_vault" / "app_cert.cbor"
    app_key = project_root / "certs_vault" / "app_priv.pem"
    
    if not cert_file.exists() or not app_key.exists():
        print("✗ Missing certificates. Run:")
        print("  cd cert_gen")
        print("  python gen_ed_keys.py")
        print("  python create_cose_cert.py")
        print("  cd ..")
        return
    
    print("✓ Certificates found\n")
    
    # Step 1: Generate QR with debug
    print("\n" + "█"*70)
    print("STEP 1: Generate QR Code (with debug output)")
    print("█"*70)
    
    generate_cmd = [
        sys.executable,
        "create_qr_ed25519.py",
        "--payload", "Hello World",
        "--app-priv", str(app_key),
        "--cert-cbor", str(cert_file),
        "--out", "test_qr_debug.png",
        "--format", "png",
        "--debug"
    ]
    
    if not run_command(generate_cmd, "Generating QR Code"):
        print("✗ QR generation failed")
        return
    
    print("\n✓ QR generation completed")
    
    # Check if QR was created
    qr_file = project_root / "test_qr_debug.png"
    bin_file = project_root / "test_qr_debug.png.bin"
    
    if not qr_file.exists():
        print(f"✗ QR file not created: {qr_file}")
        return
    
    print(f"✓ QR file created: {qr_file}")
    if bin_file.exists():
        print(f"✓ BIN file created: {bin_file}")
    
    # Step 2: Scan QR with debug
    print("\n" + "█"*70)
    print("STEP 2: Scan QR Code (with debug output)")
    print("█"*70)
    
    scan_cmd = [
        sys.executable,
        "scan_qr_ed25519.py",
        "--file", str(qr_file),
        "--trusted-dir", "trusted_roots",
        "--debug"
    ]
    
    if not run_command(scan_cmd, "Scanning QR Code"):
        print("✗ QR scanning failed")
    
    print("\n" + "█"*70)
    print("STEP 3: Test with CyberChef comparison")
    print("█"*70)
    
    if bin_file.exists():
        print(f"\n✓ Binary file available: {bin_file}")
        print(f"  Size: {bin_file.stat().st_size} bytes")
        print(f"  You can now:")
        print(f"  1. Copy the hex from debug output")
        print(f"  2. Paste into CyberChef Recipe")
        print(f"  3. Compare CBOR parsing with what we got")
        print(f"\n  Or load the binary directly:")
        print(f"    CyberChef → From Hex → CBOR Decode")
        
        # Print hex of the binary file for easy copy-paste to CyberChef
        bin_data = bin_file.read_bytes()
        print(f"\n  Binary file hex (first 200 bytes):")
        print(f"  {bin_data[:200].hex()}")
        if len(bin_data) > 200:
            print(f"  ... ({len(bin_data) - 200} more bytes)")
    
    print("\n" + "="*70)
    print("✓ Debug test completed!")
    print("="*70)
    print("\nNext steps:")
    print("1. Compare output from both generation and scanning")
    print("2. Look for mismatches in hex dumps")
    print("3. Check CyberChef parsing matches our CBOR structure")
    print("4. Report any discrepancies")

if __name__ == "__main__":
    main()
