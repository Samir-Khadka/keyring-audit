"""Shared test fixtures.

The scan fixture repo holds literal fake secrets, so it is never
committed (GitHub secret scanning blocks the push). It is generated
into a tmp dir once per test session instead.
"""
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent


@pytest.fixture(scope="session")
def fixture_repo(tmp_path_factory):
    dest = tmp_path_factory.mktemp("fixture-repo")
    subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "make_scan_fixtures.py"),
         str(dest)],
        check=True, capture_output=True, text=True)
    return dest
