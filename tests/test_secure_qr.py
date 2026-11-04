"""
Tests for the Secure QR toolchain (v2). Standard library only:

    py -m unittest discover -s tests -v

Each test maps to a claim of the paper's threat model or to a reviewer concern.
"""

import base64
import os
import subprocess
import sys
import tempfile
import unittest
import zlib
from pathlib import Path

import cbor2
from cryptography.hazmat.primitives.asymmetric import ed25519

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))
import sqr_core as core  # noqa: E402

NOW = core.parse_time("2026-06-01")


def keypair():
    k = ed25519.Ed25519PrivateKey.generate()
    return k, k.public_key()


def chain(root, nbf="2025-10-01", exp="2030-12-31"):
    app, app_pub = keypair()
    cert = core.build_cert("PWr-Campus", "W4N-K34", core.raw_public_bytes(app_pub), nbf, exp)
    return app, cert, core.sign_cert(root, cert)


def roundtrip(enc):
    """What the reader sees: QR text -> container."""
    return core.decode_text(enc.text)[0]


class RootOnly(unittest.TestCase):
    def setUp(self):
        self.root, self.root_pub = keypair()

    def test_valid_code_verifies(self):
        c = roundtrip(core.build_container(b"Welcome", self.root))
        self.assertTrue(core.verify_container(c, [self.root_pub], now=NOW).ok)

    def test_tampered_payload_rejected(self):
        c = roundtrip(core.build_container(b"Pay to city", self.root))
        c["payload"] = b"Pay to attacker"
        self.assertFalse(core.verify_container(c, [self.root_pub], now=NOW).ok)

    def test_unknown_root_rejected(self):
        c = roundtrip(core.build_container(b"Welcome", self.root))
        _, other = keypair()
        self.assertFalse(core.verify_container(c, [other], now=NOW).ok)

    def test_require_chain_rejects_root_only(self):
        c = roundtrip(core.build_container(b"Welcome", self.root))
        self.assertFalse(core.verify_container(c, [self.root_pub], now=NOW, require_chain=True).ok)


class CertificateChain(unittest.TestCase):
    def setUp(self):
        self.root, self.root_pub = keypair()

    def code(self, payload=b"Access granted", **kw):
        app, cert, sig = chain(self.root, **kw)
        return roundtrip(core.build_container(payload, app, cert, sig)), app

    def test_valid_chain_verifies(self):
        c, _ = self.code()
        res = core.verify_container(c, [self.root_pub], now=NOW, require_chain=True)
        self.assertTrue(res.ok, res.reason)

    def test_tampered_certificate_rejected(self):
        c, _ = self.code()
        c["cert"]["sub"] = "Attacker-Device"
        self.assertIn("Certificate signature", core.verify_container(c, [self.root_pub], now=NOW).reason)

    def test_expired_certificate_rejected(self):
        c, _ = self.code(exp="2026-01-31")
        self.assertIn("EXPIRED", core.verify_container(c, [self.root_pub], now=NOW).reason)

    def test_date_only_exp_valid_through_that_day(self):
        c, _ = self.code(exp="2026-06-01")
        self.assertTrue(core.verify_container(c, [self.root_pub], now=NOW + 86399).ok)

    def test_not_yet_valid_rejected(self):
        c, _ = self.code(nbf="2027-01-01")
        self.assertIn("NOT YET", core.verify_container(c, [self.root_pub], now=NOW).reason)

    def test_missing_exp_rejected(self):
        app, app_pub = keypair()
        cert = {"iss": "PWr-Campus", "sub": "W4N-K34", "alg": "Ed25519", "pub": core.raw_public_bytes(app_pub)}
        c = roundtrip(core.build_container(b"x", app, cert, core.sign_cert(self.root, cert)))
        self.assertIn("no expiration", core.verify_container(c, [self.root_pub], now=NOW).reason)

    def test_unparseable_date_rejected(self):
        app, app_pub = keypair()
        cert = {"iss": "PWr-Campus", "sub": "W4N-K34", "alg": "Ed25519",
                "pub": core.raw_public_bytes(app_pub), "exp": "31/12/2030"}
        c = roundtrip(core.build_container(b"x", app, cert, core.sign_cert(self.root, cert)))
        self.assertFalse(core.verify_container(c, [self.root_pub], now=NOW).ok)

    def test_wrong_algorithm_rejected(self):
        app, app_pub = keypair()
        cert = {"iss": "PWr-Campus", "sub": "W4N-K34", "alg": "RSA", "pub": core.raw_public_bytes(app_pub),
                "exp": "2030-12-31"}
        c = roundtrip(core.build_container(b"x", app, cert, core.sign_cert(self.root, cert)))
        self.assertIn("algorithm", core.verify_container(c, [self.root_pub], now=NOW).reason)

    def test_certificate_signature_independent_of_key_order(self):
        """Deterministic CBOR: another implementation may serialise the map differently."""
        c, _ = self.code()
        c["cert"] = dict(reversed(list(c["cert"].items())))
        self.assertTrue(core.verify_container(c, [self.root_pub], now=NOW).ok)


class Downgrade(unittest.TestCase):
    """Threat model: downgrade attacks and signature reuse across contexts."""

    def setUp(self):
        self.root, self.root_pub = keypair()

    def test_stripped_certificate_with_app_key_in_trust_store(self):
        app, cert, sig = chain(self.root, exp="2026-01-31")   # expired certificate
        c = roundtrip(core.build_container(b"Pay here", app, cert, sig))
        del c["cert"], c["cert_sig"]                          # attacker forces Root-Only mode
        misconfigured_store = [self.root_pub, app.public_key()]
        self.assertFalse(core.verify_container(c, misconfigured_store, now=NOW).ok)

    def test_certificate_signature_cannot_be_replayed_as_payload(self):
        _, cert, sig = chain(self.root)
        forged = {"payload": core.encode_cert(cert), "payload_sig": sig}
        self.assertFalse(core.verify_container(forged, [self.root_pub], now=NOW).ok)

    def test_root_payload_signature_cannot_be_used_in_chain(self):
        app, cert, sig = chain(self.root)
        c = roundtrip(core.build_container(b"x", self.root))   # Root-signed
        c["cert"], c["cert_sig"] = cert, sig                  # attach a valid certificate
        self.assertFalse(core.verify_container(c, [self.root_pub], now=NOW).ok)


class MalformedInput(unittest.TestCase):
    """Fail-fast schema validation before any cryptography."""

    def text(self, obj, compress=True):
        raw = cbor2.dumps(obj)
        return base64.b64encode(zlib.compress(raw) if compress else raw).decode()

    def assertRejected(self, text):
        with self.assertRaises(core.SecureQRError):
            core.decode_text(text)

    def test_not_a_map(self):
        self.assertRejected(self.text([1, 2, 3]))

    def test_short_signature(self):
        self.assertRejected(self.text({"payload": b"x", "payload_sig": b"\x00" * 10}))

    def test_text_payload(self):
        self.assertRejected(self.text({"payload": "x", "payload_sig": b"\x00" * 64}))

    def test_unexpected_field(self):
        self.assertRejected(self.text({"payload": b"x", "payload_sig": b"\x00" * 64, "alg": "none"}))

    def test_cert_without_signature(self):
        self.assertRejected(self.text({"payload": b"x", "payload_sig": b"\x00" * 64, "cert": {}}))

    def test_invalid_base64(self):
        self.assertRejected("not*base64!")

    def test_decompression_bomb(self):
        bomb = base64.b64encode(zlib.compress(b"\x00" * (core.MAX_DECOMPRESSED * 4))).decode()
        self.assertRejected(bomb)

    def test_uncompressed_container_accepted(self):
        root, pub = keypair()
        enc = core.build_container(b"plain", root, compress="never")
        c, stats = core.decode_text(enc.text)
        self.assertFalse(stats["compressed"])
        self.assertTrue(core.verify_container(c, [pub], now=NOW).ok)


class Encoding(unittest.TestCase):
    def test_compress_auto_never_larger(self):
        root, _ = keypair()
        enc = core.build_container(b"short", root, compress="auto")
        self.assertLessEqual(len(enc.data), len(enc.cbor))

    def test_min_ecc_respected_and_no_micro_qr(self):
        root, _ = keypair()
        enc = core.build_container(b"Welcome", root)
        qr, ecc = core.make_qr(enc.text, min_ecc="Q")
        self.assertIn(ecc, ("Q", "H"))
        self.assertFalse(qr.is_micro)

    def test_sizes_match_paper_scenarios(self):
        """CBOR container sizes are deterministic (fixed-length keys and signatures)."""
        root, _ = keypair()
        s1 = core.build_container(b"Welcome to the PWrcampus (Direct Mode)!", root)
        app, cert, sig = chain(root)
        s2 = core.build_container(b"Access to laboratory W4N-K34 granted.", app, cert, sig)
        self.assertEqual((len(s1.cbor), len(s2.cbor)), (128, 314))
        self.assertEqual(core.make_qr(s1.text)[0].version, 8)
        self.assertEqual(core.make_qr(s2.text)[0].version, 13)


class LegacyV1(unittest.TestCase):
    """Codes from the v1 tools (the paper's figures) verify only with legacy_v1=True."""

    def test_v1_chain(self):
        root, root_pub = keypair()
        app, app_pub = keypair()
        cert = {"iss": "PWr-Campus", "sub": "W4N-K34", "alg": "Ed25519",
                "pub": core.raw_public_bytes(app_pub), "nbf": "2025-10-01", "exp": "2030-12-31"}
        payload = b"Access to laboratory W4N-K34 granted."
        c = {"payload": payload, "payload_sig": app.sign(payload),
             "cert": cert, "cert_sig": root.sign(cbor2.dumps(cert))}
        c = core.decode_text(base64.b64encode(zlib.compress(cbor2.dumps(c), 9)).decode())[0]
        self.assertTrue(core.verify_container(c, [root_pub], now=NOW, legacy_v1=True).ok)
        self.assertFalse(core.verify_container(c, [root_pub], now=NOW).ok)


class CommandLine(unittest.TestCase):
    """End-to-end: the documented commands, real PNG files, OpenCV decoding, exit codes."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.dir = Path(cls.tmp.name)
        cls.env = dict(os.environ, PYTHONIOENCODING="utf-8")
        (cls.dir / "trusted").mkdir()
        cls.cli(["cert_gen/gen_ed_keys.py", "--root-name", "Root", "--app-name", "App", "--out-dir",
                 str(cls.dir / "vault")])
        (cls.dir / "trusted" / "Root_pub.pem").write_bytes((cls.dir / "vault" / "Root_pub.pem").read_bytes())
        cls.cli(["cert_gen/create_cose_cert.py", "--root-priv", str(cls.dir / "vault" / "Root_priv.pem"),
                 "--iss", "Root", "--sub", "Device-1", "--pub", str(cls.dir / "vault" / "App_pub.pem"),
                 "--not-after", "2099-12-31", "--out", str(cls.dir / "vault" / "cert.cbor")])

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    @classmethod
    def cli(cls, args, expect=0):
        r = subprocess.run([sys.executable, *args], cwd=ROOT_DIR, capture_output=True, text=True,
                           encoding="utf-8", env=cls.env)
        if r.returncode != expect:
            raise AssertionError(f"{args} -> {r.returncode}\n{r.stdout}\n{r.stderr}")
        return r.stdout

    def test_root_only_cli(self):
        img = self.dir / "img" / "root"
        self.cli(["qr-create.py", "--payload", "Hello", "--root-priv", str(self.dir / "vault" / "Root_priv.pem"),
                  "--out", str(img)])
        out = self.cli(["qr-read.py", "--image", f"{img}.png", "--trusted-dir", str(self.dir / "trusted")])
        self.assertIn("Hello", out)

    def test_chain_cli_and_untrusted_root(self):
        img = self.dir / "img" / "chain"
        self.cli(["qr-create.py", "--payload", "Door 1", "--app-priv", str(self.dir / "vault" / "App_priv.pem"),
                  "--cert-cbor", str(self.dir / "vault" / "cert.cbor"), "--out", str(img)])
        self.cli(["qr-read.py", "--image", f"{img}.png", "--trusted-dir", str(self.dir / "trusted"),
                  "--require-chain"])
        # the App key is not a Root: verification must fail with exit code 2 and hide the payload
        out = self.cli(["qr-read.py", "--image", f"{img}.png", "--trusted-dir",
                        str(self.dir / "vault" / "App_pub.pem")], expect=2)
        self.assertNotIn("Door 1", out)

    def test_mismatched_app_key_refused_by_generator(self):
        self.cli(["qr-create.py", "--payload", "x", "--app-priv", str(self.dir / "vault" / "Root_priv.pem"),
                  "--cert-cbor", str(self.dir / "vault" / "cert.cbor"), "--out", str(self.dir / "img" / "bad")],
                 expect=1)

    def test_existing_keys_not_overwritten(self):
        self.cli(["cert_gen/gen_ed_keys.py", "--root-name", "Root", "--root-only", "--out-dir",
                  str(self.dir / "vault")], expect=1)

    def test_show_cert_checks_root_signature(self):
        cert = str(self.dir / "vault" / "cert.cbor")
        out = self.cli(["cert_gen/show_cert.py", "--cert", cert, "--root-pub", str(self.dir / "trusted")])
        self.assertIn("Root signature:    VALID", out)
        self.cli(["cert_gen/show_cert.py", "--cert", cert, "--root-pub",
                  str(self.dir / "vault" / "App_pub.pem")], expect=2)

    def test_reader_usage_error_is_exit_1(self):
        self.cli(["qr-read.py", "--trusted-dir", str(self.dir / "trusted")], expect=1)


if __name__ == "__main__":
    unittest.main()
