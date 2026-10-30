#!/usr/bin/env python3
"""Cross-platform pytest runner with an isolated per-run temp directory."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path


def main() -> int:
    project_dir = Path(__file__).resolve().parent
    base_temp = Path(tempfile.gettempdir()) / (
        f"secret-broker-pytest-{os.getpid()}-{uuid.uuid4().hex[:8]}"
    )
    base_temp.mkdir(parents=True, exist_ok=False)
    try:
        return subprocess.call(
            [
                sys.executable,
                "-m",
                "pytest",
                "tests/",
                "-q",
                "-p",
                "no:cacheprovider",
                "--basetemp",
                str(base_temp),
            ],
            cwd=project_dir,
        )
    finally:
        shutil.rmtree(base_temp, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
