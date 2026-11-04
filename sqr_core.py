#!/usr/bin/env python3
"""
Secure QR Codes - shared core (format v2).

Used by qr-create.py, qr-read.py, cert_gen/*, benchmarks/ and tests/ so that
the command-line tools, the benchmarks and the tests exercise exactly the same
code path.

Data flow (as described in the paper):
    payload -> Ed25519 signature -> CBOR container -> ZLIB -> Base64 -> QR

Container (CBOR map), unchanged from v1 so that sizes match the paper:
    {"payload": bstr, "payload_sig": bstr(64)}                       Mode A
    {"payload": bstr, "payload_sig": bstr(64),
     "cert": {iss, sub, alg, pub, nbf, exp}, "cert_sig": bstr(64)}   Mode B

Changes in v2 (no extra bytes in the QR code):
  * Domain separation: every Ed25519 signature covers a context string plus
    the data, so a certificate signature can never be replayed as a payload
    signature and an App-signed payload can never pass as Root-signed.
  * Certificates are signed over their deterministic CBOR encoding
    (RFC 8949, Section 4.2), so any reader implementation can recompute
    exactly the signed bytes.
  * Fail-closed validation: strict schema checks, mandatory and parseable
    validity window, algorithm check, bounded decompression.

The structure is COSE-inspired (CBOR + EdDSA as in RFC 8152 / RFC 9052) but it
is NOT a COSE_Sign1 message.
"""

from __future__ import annotations

import base64
import binascii
import os
import zlib
from dataclasses import dataclass, field
from datetime import datetime, time as dtime, timezone
from pathlib import Path
from typing import Iterable, Optional

import cbor2
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

FORMAT_VERSION = 2

# Domain-separation contexts (v2). The trailing NUL keeps them prefix-free.
CTX_ROOT_PAYLOAD = b"SecureQR/v2/root-payload\x00"
CTX_APP_PAYLOAD = b"SecureQR/v2/app-payload\x00"
CTX_CERT = b"SecureQR/v2/cert\x00"

MAX_QR_VERSION = 26             # keeps codes printable and scannable
ERROR_LEVELS = ("L", "M", "Q", "H")
MAX_BASE64_CHARS = 4096         # larger than any QR code of version <= 40
MAX_DECOMPRESSED = 64 * 1024    # bound for ZLIB output (decompression bomb)
SIG_LEN = 64
PUB_LEN = 32

MODE_ROOT = "Root-Only (Direct Trust)"
MODE_CHAIN = "Root + App (Certificate Chain)"

KEY_PASSPHRASE_ENV = "SQR_KEY_PASSPHRASE"


class SecureQRError(Exception):
    """Raised for malformed input (fail-closed)."""


# --------------------------------------------------------------------------
# Keys
# --------------------------------------------------------------------------

def _passphrase() -> Optional[bytes]:
    value = os.environ.get(KEY_PASSPHRASE_ENV)
    return value.encode("utf-8") if value else None


def load_private_key(path: Path) -> ed25519.Ed25519PrivateKey:
    """Loads an Ed25519 private key (PEM). Encrypted keys use $SQR_KEY_PASSPHRASE."""
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(f"Key file not found: {path}")
    data = path.read_bytes()
    try:
        key = serialization.load_pem_private_key(data, password=None)
    except TypeError:
        password = _passphrase()
        if password is None:
            raise SecureQRError(f"{path} is encrypted; set {KEY_PASSPHRASE_ENV}")
        key = serialization.load_pem_private_key(data, password=password)
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise SecureQRError(f"{path} is not an Ed25519 private key")
    return key


def load_public_key(path: Path) -> ed25519.Ed25519PublicKey:
    key = serialization.load_pem_public_key(Path(path).read_bytes())
    if not isinstance(key, ed25519.Ed25519PublicKey):
        raise SecureQRError(f"{path} is not an Ed25519 public key")
    return key


def load_trusted_roots(path: Path) -> list[ed25519.Ed25519PublicKey]:
    """Loads Root CA public keys from a .pem file or from the *.pem files of a directory.

    Only Root keys belong here. Thanks to domain separation an App key placed
    in this store by mistake still cannot validate a Root-Only code.
    """
    path = Path(path)
    if path.is_file():
        files = [path]
    elif path.is_dir():
        files = sorted(p for p in path.iterdir() if p.is_file() and p.suffix.lower() == ".pem")
    else:
        raise FileNotFoundError(f"Trusted root path does not exist: {path}")
    keys = []
    for f in files:
        try:
            keys.append(load_public_key(f))
        except (ValueError, SecureQRError):
            continue
    if not keys:
        raise SecureQRError(f"No Ed25519 public keys found in {path}")
    return keys


def raw_public_bytes(key: ed25519.Ed25519PublicKey) -> bytes:
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


# --------------------------------------------------------------------------
# Certificates
# --------------------------------------------------------------------------

def encode_cert(cert: dict, legacy_v1: bool = False) -> bytes:
    """Bytes covered by the certificate signature.

    v2: deterministic CBOR (canonical). v1: insertion-order CBOR, as produced
    by the original scripts used for the paper's figures.
    """
    return cbor2.dumps(cert) if legacy_v1 else cbor2.dumps(cert, canonical=True)


def signed_cert_message(cert: dict, legacy_v1: bool = False) -> bytes:
    """Exact bytes covered by cert_sig."""
    return (b"" if legacy_v1 else CTX_CERT) + encode_cert(cert, legacy_v1)


def payload_context(has_cert: bool, legacy_v1: bool = False) -> bytes:
    if legacy_v1:
        return b""
    return CTX_APP_PAYLOAD if has_cert else CTX_ROOT_PAYLOAD


def signed_payload_message(container: dict, legacy_v1: bool = False) -> bytes:
    """Exact bytes covered by payload_sig."""
    return payload_context("cert" in container, legacy_v1) + container["payload"]


def sign_cert(root_key: ed25519.Ed25519PrivateKey, cert: dict) -> bytes:
    return root_key.sign(signed_cert_message(cert))


def parse_time(value, end_of_day: bool = False) -> int:
    """Parses an int timestamp, 'YYYY-MM-DD' or an ISO 8601 date-time (UTC if no zone).

    A date-only `exp` is valid until the end of that day (UTC).
    Raises SecureQRError for anything else (fail-closed).
    """
    if isinstance(value, bool):
        raise SecureQRError(f"Invalid time value: {value!r}")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip()
        try:
            if len(text) == 10:
                d = datetime.strptime(text, "%Y-%m-%d").date()
                t = dtime(23, 59, 59) if end_of_day else dtime(0, 0, 0)
                return int(datetime.combine(d, t, tzinfo=timezone.utc).timestamp())
            dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return int(dt.timestamp())
        except ValueError:
            pass
    raise SecureQRError(f"Invalid time value: {value!r}")


def build_cert(iss: str, sub: str, pub: bytes, nbf: Optional[str], exp: str) -> dict:
    if not iss or not sub:
        raise SecureQRError("Issuer and subject must not be empty")
    if len(pub) != PUB_LEN:
        raise SecureQRError("App public key must be a raw 32-byte Ed25519 key")
    cert = {"iss": iss, "sub": sub, "alg": "Ed25519", "pub": pub}
    if nbf:
        parse_time(nbf)
        cert["nbf"] = nbf
    parse_time(exp, end_of_day=True)
    cert["exp"] = exp
    return cert


# --------------------------------------------------------------------------
# Generation
# --------------------------------------------------------------------------

@dataclass
class Encoded:
    container: dict
    cbor: bytes          # serialized container
    data: bytes          # bytes placed in Base64 (compressed or not)
    compressed: bool
    text: str            # Base64 string stored in the QR code

    @property
    def sizes(self) -> dict:
        return {"cbor": len(self.cbor), "encoded": len(self.data), "base64": len(self.text)}


def build_container(payload: bytes, signing_key: ed25519.Ed25519PrivateKey,
                    cert: Optional[dict] = None, cert_sig: Optional[bytes] = None,
                    compress: str = "always") -> Encoded:
    """Signs and packs a payload. compress: 'always' (as in the paper), 'auto', 'never'."""
    if not isinstance(payload, bytes) or not payload:
        raise SecureQRError("Payload must be non-empty bytes")
    if (cert is None) != (cert_sig is None):
        raise SecureQRError("cert and cert_sig must be given together")
    context = payload_context(cert is not None)
    container = {"payload": payload, "payload_sig": signing_key.sign(context + payload)}
    if cert is not None:
        container["cert"] = cert
        container["cert_sig"] = cert_sig
    raw = cbor2.dumps(container)
    if compress == "never":
        data, compressed = raw, False
    else:
        packed = zlib.compress(raw, level=9)
        if compress == "auto" and len(packed) >= len(raw):
            data, compressed = raw, False
        else:
            data, compressed = packed, True
    return Encoded(container, raw, data, compressed, base64.b64encode(data).decode("ascii"))


def make_qr(text: str, min_ecc: str = "L", max_version: int = MAX_QR_VERSION):
    """Smallest QR version that fits; for equal versions the higher ECC level wins.

    Returns (segno.QRCode, ecc) or (None, None). min_ecc restricts the levels tried.
    """
    import segno

    if min_ecc not in ERROR_LEVELS:
        raise SecureQRError(f"Unknown error correction level: {min_ecc}")
    best, best_ec = None, None
    for ec in ERROR_LEVELS[ERROR_LEVELS.index(min_ecc):]:
        try:
            qr = segno.make_qr(text, error=ec)   # never a Micro QR
        except Exception:
            continue
        if qr.version > max_version:
            continue
        if best is None or qr.version < best.version or (
                qr.version == best.version and ERROR_LEVELS.index(ec) > ERROR_LEVELS.index(best_ec)):
            best, best_ec = qr, ec
    if best is not None:
        best_ec = best.error   # segno may boost the level without growing the version
    return best, best_ec


# --------------------------------------------------------------------------
# Reading and verification
# --------------------------------------------------------------------------

def decode_text(text: str) -> tuple[dict, dict]:
    """Base64 -> (optional) ZLIB -> CBOR with strict, bounded parsing.

    Returns (container, stats). stats also keeps the intermediate bytes
    ('encoded_bytes' after Base64, 'cbor_bytes' after ZLIB) for debug output.
    Raises SecureQRError on malformed data.
    """
    if not isinstance(text, str) or not text or len(text) > MAX_BASE64_CHARS:
        raise SecureQRError("QR text is empty or too long")
    try:
        data = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError) as e:
        raise SecureQRError(f"Invalid Base64: {e}")
    stats = {"base64": len(text), "encoded": len(data), "compressed": False}
    raw = data
    if data[:1] == b"\x78":   # ZLIB header
        try:
            d = zlib.decompressobj()
            raw = d.decompress(data, MAX_DECOMPRESSED)
            if d.unconsumed_tail:
                raise SecureQRError("Decompressed data exceeds limit")
            stats["compressed"] = True
        except zlib.error:
            raw = data
    try:
        container = cbor2.loads(raw)
    except Exception as e:
        raise SecureQRError(f"Invalid CBOR: {e}")
    stats["cbor"] = len(raw)
    stats["encoded_bytes"], stats["cbor_bytes"] = data, raw
    validate_container(container)
    stats["payload"] = len(container["payload"])
    return container, stats


def _require(cond: bool, msg: str):
    if not cond:
        raise SecureQRError(msg)


def validate_container(c) -> None:
    """Strict schema check (fail-fast, before any cryptography)."""
    _require(isinstance(c, dict), "Container is not a CBOR map")
    allowed = {"payload", "payload_sig", "cert", "cert_sig"}
    _require(set(c) <= allowed, f"Unexpected fields: {sorted(set(map(str, c)) - allowed)}")
    _require(isinstance(c.get("payload"), bytes) and c["payload"], "payload must be non-empty bytes")
    _require(isinstance(c.get("payload_sig"), bytes) and len(c["payload_sig"]) == SIG_LEN,
             "payload_sig must be 64 bytes")
    has_cert, has_sig = "cert" in c, "cert_sig" in c
    _require(has_cert == has_sig, "cert and cert_sig must appear together")
    if has_cert:
        cert = c["cert"]
        _require(isinstance(cert, dict), "cert must be a CBOR map")
        _require(isinstance(c["cert_sig"], bytes) and len(c["cert_sig"]) == SIG_LEN,
                 "cert_sig must be 64 bytes")
        for k in ("iss", "sub", "alg"):
            _require(isinstance(cert.get(k), str) and cert[k], f"cert.{k} must be a non-empty string")
        _require(isinstance(cert.get("pub"), bytes) and len(cert["pub"]) == PUB_LEN,
                 "cert.pub must be a 32-byte Ed25519 key")
        for k in ("nbf", "exp"):
            if k in cert:
                _require(isinstance(cert[k], (str, int)) and not isinstance(cert[k], bool),
                         f"cert.{k} must be a date string or an integer timestamp")


@dataclass
class Verification:
    ok: bool
    mode: str
    reason: str = ""
    checks: list = field(default_factory=list)   # (label, ok) in evaluation order


def _verify_any(keys: Iterable[ed25519.Ed25519PublicKey], sig: bytes, msg: bytes) -> bool:
    for k in keys:
        try:
            k.verify(sig, msg)
            return True
        except InvalidSignature:
            continue
    return False


def verify_container(c: dict, root_keys: list, now: Optional[int] = None,
                     require_chain: bool = False, legacy_v1: bool = False) -> Verification:
    """Verifies a validated container. Fail-fast: the first failing check stops."""
    import time as _time

    now = int(_time.time()) if now is None else now
    validate_container(c)
    payload_sig = c["payload_sig"]
    payload_msg = signed_payload_message(c, legacy_v1)

    if "cert" not in c:
        res = Verification(False, MODE_ROOT)
        if require_chain:
            res.reason = "Certificate chain required (--require-chain), but the code is Root-Only"
            return res
        ok = _verify_any(root_keys, payload_sig, payload_msg)
        res.checks.append(("Payload signature (Root)", ok))
        if not ok:
            res.reason = "Payload signature INVALID (does not match any trusted root)"
            return res
        res.ok = True
        return res

    res = Verification(False, MODE_CHAIN)
    cert, cert_sig = c["cert"], c["cert_sig"]

    ok = _verify_any(root_keys, cert_sig, signed_cert_message(cert, legacy_v1))
    res.checks.append(("Certificate signature (Root)", ok))
    if not ok:
        res.reason = "Certificate signature INVALID (does not match any trusted root)"
        return res

    ok = cert["alg"] == "Ed25519"
    res.checks.append(("Algorithm is Ed25519", ok))
    if not ok:
        res.reason = f"Unsupported algorithm: {cert['alg']}"
        return res

    try:
        if "exp" not in cert:
            raise SecureQRError("Certificate has no expiration date (exp)")
        exp = parse_time(cert["exp"], end_of_day=True)
        nbf = parse_time(cert["nbf"]) if "nbf" in cert else None
    except SecureQRError as e:
        res.checks.append(("Validity window (nbf/exp)", False))
        res.reason = str(e)
        return res
    if nbf is not None and now < nbf:
        res.checks.append(("Validity window (nbf/exp)", False))
        res.reason = f"Certificate is NOT YET valid (nbf {cert['nbf']})"
        return res
    if now > exp:
        res.checks.append(("Validity window (nbf/exp)", False))
        res.reason = f"Certificate has EXPIRED (exp {cert['exp']})"
        return res
    res.checks.append(("Validity window (nbf/exp)", True))

    app_key = ed25519.Ed25519PublicKey.from_public_bytes(cert["pub"])
    ok = _verify_any([app_key], payload_sig, payload_msg)
    res.checks.append(("Payload signature (App key from certificate)", ok))
    if not ok:
        res.reason = "Payload signature INVALID"
        return res
    res.ok = True
    return res


def decode_image(path: Path) -> tuple[str, Optional[int]]:
    """Reads a QR code image with OpenCV. Returns (text, estimated version or None).

    The classic cv2.QRCodeDetector misses a few percent of dense codes (about
    7% of version 13 codes in our tests), so cv2.QRCodeDetectorAruco
    (OpenCV >= 4.8) is used as a fallback.
    """
    import cv2

    img = cv2.imread(str(path))
    if img is None:
        raise SecureQRError(f"Cannot read image: {path}")
    text, _points, straight = cv2.QRCodeDetector().detectAndDecode(img)
    if not text and hasattr(cv2, "QRCodeDetectorAruco"):
        text, _points, straight = cv2.QRCodeDetectorAruco().detectAndDecode(img)
    if not text:
        raise SecureQRError("No QR code detected")
    version = None
    if straight is not None:
        width = straight.shape[0]
        if (width - 21) % 4 == 0 and 1 <= (width - 21) // 4 + 1 <= 40:
            version = (width - 21) // 4 + 1
    return text, version
