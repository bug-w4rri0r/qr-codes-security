"""Environment description printed with every benchmark result."""

import importlib.metadata as md
import os
import platform


def _version(pkg: str) -> str:
    try:
        return md.version(pkg)
    except md.PackageNotFoundError:
        return "not installed"


def environment() -> dict:
    return {
        "python": platform.python_version(),
        "implementation": platform.python_implementation(),
        "os": f"{platform.system()} {platform.release()}",
        "machine": platform.machine(),
        "processor": platform.processor() or "unknown",
        "cpu_count": os.cpu_count(),
        "cryptography": _version("cryptography"),
        "cbor2": _version("cbor2"),
        "segno": _version("segno"),
        "opencv-python": _version("opencv-python"),
        "numpy": _version("numpy"),
    }
