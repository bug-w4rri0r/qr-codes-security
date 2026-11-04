"""
Debug output shared by qr-create.py and qr-read.py (--debug).

Prints every byte, without truncation, so each stage of the pipeline
(payload -> signature -> CBOR -> ZLIB -> Base64 -> QR) can be inspected.
"""

CYAN = "\033[96m"
RESET = "\033[0m"


def dump(label: str, data, is_text: bool = False, color: bool = False):
    """Full hex dump (32 bytes per row) or full text."""
    head = f"\n[DEBUG] --- {label} ---"
    print(f"{CYAN}{head}{RESET}" if color else head)
    if data is None:
        print(" [None]")
        return
    print(f" Size: {len(data)} {'chars' if is_text else 'bytes'}")
    if is_text:
        print(f" Content:\n{data}")
        return
    hex_str = data.hex()
    for i in range(0, len(hex_str), 64):
        row = hex_str[i:i + 64]
        print(" Hex: " + " ".join(row[j:j + 2] for j in range(0, len(row), 2)))


def payload_info(payload: bytes) -> str:
    """One-line description: text (if UTF-8) and size."""
    try:
        text = payload.decode("utf-8")
        shown = text if len(text) <= 120 else text[:117] + "..."
        return f'"{shown}" ({len(payload)} bytes, UTF-8 text)'
    except UnicodeDecodeError:
        return f"<binary> ({len(payload)} bytes) {payload[:16].hex()}..."


def dump_container(container: dict, color: bool = False):
    """Field-by-field view of the CBOR container."""
    head = "\n[DEBUG] --- CBOR container structure ---"
    print(f"{CYAN}{head}{RESET}" if color else head)
    p = container["payload"]
    print(f" payload      bstr[{len(p)}]  {payload_info(p)}")
    print(f" payload_sig  bstr[{len(container['payload_sig'])}]  {container['payload_sig'].hex()}")
    if "cert" in container:
        cert = container["cert"]
        print(" cert         map")
        for k, v in cert.items():
            shown = f"bstr[{len(v)}]  {v.hex()}" if isinstance(v, bytes) else repr(v)
            print(f"   {str(k):<10} {shown}")
        print(f" cert_sig     bstr[{len(container['cert_sig'])}]  {container['cert_sig'].hex()}")
