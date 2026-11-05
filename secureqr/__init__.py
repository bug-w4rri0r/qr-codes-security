"""
Secure QR Codes: Ed25519-signed QR codes with lightweight CBOR certificates.

Reference implementation for the paper "Secure QR Codes: Authenticity
Verification via EdDSA Signatures and CBOR Certificates".

Modules:
    secureqr.core   format, signing, decoding and verification
    secureqr.debug  --debug output shared by the command-line tools
    secureqr.cli    command-line tools (create, read, keygen, issue_cert, show_cert)
"""

__version__ = "2.0.0"
