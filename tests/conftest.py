from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest


@dataclass
class CliResult:
    returncode: int
    stdout: str
    stderr: str


@pytest.fixture()
def run_cli():
    """Run a console_scripts entry point as a subprocess."""

    def _run(entry_point: str, args: list[str]) -> CliResult:
        # Use python -c to call the entry point directly.
        if entry_point == "reg2es":
            code = "from reg2es.views.Reg2esView import entry_point; entry_point()"
        elif entry_point == "reg2json":
            code = "from reg2es.views.Reg2jsonView import entry_point; entry_point()"
        else:
            raise ValueError(f"Unknown entry point: {entry_point}")

        cmd = [sys.executable, "-c", code] + args
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
            cwd=str(Path(__file__).resolve().parent.parent),
        )
        return CliResult(
            returncode=result.returncode,
            stdout=result.stdout,
            stderr=result.stderr,
        )

    return _run
