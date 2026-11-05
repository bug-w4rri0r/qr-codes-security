#!/usr/bin/env python3
"""Lightweight CBOR certificate issuer. Implementation: secureqr/cli/issue_cert.py (see README.md)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # repository root: works without installation

from secureqr.cli.issue_cert import main  # noqa: E402

if __name__ == "__main__":
    main()
