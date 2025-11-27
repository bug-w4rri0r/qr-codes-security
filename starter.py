#!/usr/bin/env python3
"""
QR Codes Security - Automated Starter Script
Automatycznie uruchamia wszystkie Setup steps
"""

import sys
import os
import subprocess
from pathlib import Path

def print_banner():
    """Print ASCII banner"""
    banner = """
    
    ╔════════════════════════════════════════════════════╗
    ║                                                    ║
    ║      🎉 QR-CODES-SECURITY STARTER SCRIPT 🎉      ║
    ║                                                    ║
    ║    Complete QR Code Generation & Verification      ║
    ║         with Ed25519 Signatures                   ║
    ║                                                    ║
    ║    Desktop: PyQt5 GUI + Live Camera               ║
    ║    Mobile: Kotlin + ML Kit (Android)              ║
    ║                                                    ║
    ╚════════════════════════════════════════════════════╝
    
    """
    print(banner)

def ask_question(question, default="yes"):
    """Ask yes/no question"""
    valid = {"yes": True, "y": True, "no": False, "n": False}
    
    prompt = f"\n{question} [{default}]: "
    
    while True:
        choice = input(prompt).lower() or default
        if choice in valid:
            return valid[choice]
        print("  ✗ Please answer 'yes' or 'no'")

def run_command(cmd, description):
    """Run shell command"""
    print(f"\n▶ {description}")
    print(f"  Command: {cmd}")
    
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            print(f"  ✓ Success")
            return True
        else:
            print(f"  ✗ Failed: {result.stderr[:200]}")
            return False
    except Exception as e:
        print(f"  ✗ Error: {str(e)}")
        return False

def main():
    """Main starter script"""
    
    print_banner()
    
    print("=" * 54)
    print("Welcome! This script will set up the project for you.")
    print("=" * 54)
    
    project_root = Path(__file__).parent
    
    # Step 1: Check Python version
    print(f"\n📋 Step 1: Check Python Version")
    print(f"  Current: Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")
    
    if sys.version_info < (3, 8):
        print(f"  ✗ Python 3.8+ required!")
        sys.exit(1)
    else:
        print(f"  ✓ Python version OK")
    
    # Step 2: Check dependencies
    print(f"\n📋 Step 2: Check Dependencies")
    missing = []
    
    for package in ["cryptography", "cbor2", "segno", "Pillow", "cv2", "PyQt5", "numpy"]:
        try:
            __import__(package)
            print(f"  ✓ {package}")
        except ImportError:
            print(f"  ✗ {package}")
            missing.append(package)
    
    if missing:
        print(f"\n  Missing: {', '.join(missing)}")
        if ask_question("  Install missing packages?", "yes"):
            if not run_command(
                f"{sys.executable} -m pip install -r requirements.txt",
                "Installing dependencies"
            ):
                print("  ✗ Installation failed. Please try manually.")
                sys.exit(1)
    
    # Step 3: Check certificates
    print(f"\n📋 Step 3: Check Certificates")
    certs_vault = project_root / "certs_vault"
    
    if certs_vault.exists() and (certs_vault / "app_cert.cbor").exists():
        print(f"  ✓ Certificates found")
    else:
        print(f"  ✗ Certificates not found")
        if ask_question("  Generate new certificates?", "yes"):
            if run_command(
                f"{sys.executable} cert_gen/gen_ed_keys.py",
                "Generating Ed25519 keys"
            ) and run_command(
                f"{sys.executable} cert_gen/create_cose_cert.py",
                "Creating CBOR certificate"
            ):
                print("  ✓ Certificates created")
            else:
                print("  ✗ Certificate generation failed")
                sys.exit(1)
    
    # Step 4: Check QR images
    print(f"\n📋 Step 4: Check QR Images")
    test_qr = project_root / "test_qr_images" / "test_qr_v2.png"
    
    if test_qr.exists():
        print(f"  ✓ QR images found")
    else:
        print(f"  ✗ QR images not found")
        if ask_question("  Generate test QR codes?", "yes"):
            if run_command(
                f"{sys.executable} create_qr_ed25519.py --format both",
                "Generating QR codes"
            ):
                print("  ✓ QR codes created")
            else:
                print("  ✗ QR generation failed")
                sys.exit(1)
    
    # Step 5: Run health check
    print(f"\n📋 Step 5: Run Health Check")
    if ask_question("  Run system health check?", "yes"):
        run_command(f"{sys.executable} health_check.py", "Health check")
    
    # Step 6: Choose next action
    print(f"\n{'=' * 54}")
    print("Setup complete! What would you like to do next?")
    print(f"{'=' * 54}")
    print("""
    1. Run Desktop GUI (qr_scanner_gui.py)
    2. View Quick Start Guide (QUICK_START.md)
    3. View Full Documentation (FULL_PROJECT_DOCUMENTATION.md)
    4. Exit
    """)
    
    choice = input("Select option (1-4): ").strip()
    
    if choice == "1":
        print("\n▶ Launching Desktop GUI...")
        os.system(f"{sys.executable} qr_scanner_gui.py")
    elif choice == "2":
        print("\n📖 Opening QUICK_START.md...")
        quick_start = project_root / "QUICK_START.md"
        if quick_start.exists():
            if sys.platform == "win32":
                os.startfile(quick_start)
            else:
                os.system(f"xdg-open {quick_start}")
        else:
            print("  ✗ QUICK_START.md not found")
    elif choice == "3":
        print("\n📖 Opening FULL_PROJECT_DOCUMENTATION.md...")
        full_doc = project_root / "FULL_PROJECT_DOCUMENTATION.md"
        if full_doc.exists():
            if sys.platform == "win32":
                os.startfile(full_doc)
            else:
                os.system(f"xdg-open {full_doc}")
        else:
            print("  ✗ Documentation not found")
    else:
        print("\nExiting. Happy scanning! 🎉")
    
    print(f"\n{'=' * 54}")
    print("Next steps:")
    print(f"{'=' * 54}")
    print("""
    1. Desktop:
       - Run: python qr_scanner_gui.py
       - Load PNG/SVG file
       - Verify signatures
    
    2. Android:
       - Read: ANDROID_SETUP_GUIDE.md
       - Create Android project
       - Copy source files
       - Run on device/emulator
    
    3. Documentation:
       - QUICK_START.md - 3 minute intro
       - FULL_PROJECT_DOCUMENTATION.md - Complete guide
       - FILE_INDEX.md - File overview
    """)
    
    print("\n🚀 Project is ready to use!")
    print("📚 For more info, read QUICK_START.md\n")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nAborted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n✗ Error: {str(e)}")
        sys.exit(1)
