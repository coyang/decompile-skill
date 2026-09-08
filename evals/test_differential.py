"""Black-box tests for the diagnostic-only differential sampler."""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest


SKILL_DIR = Path(__file__).resolve().parents[1]
DIFFERENTIAL = SKILL_DIR / "scripts" / "differential.py"
GCC = shutil.which("gcc") or "/usr/bin/gcc"


class DifferentialSamplerTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tempdir = tempfile.TemporaryDirectory(prefix="decompile-diff-test-")
        self.root = Path(self._tempdir.name)

    def tearDown(self) -> None:
        self._tempdir.cleanup()

    def _compile(self, name: str, source: str) -> Path:
        source_path = self.root / f"{name}.c"
        library_path = self.root / f"{name}.so"
        source_path.write_text(textwrap.dedent(source).lstrip(), encoding="utf-8")
        subprocess.run(
            [GCC, "-O0", "-fPIC", "-shared", str(source_path), "-o", str(library_path)],
            check=True,
            capture_output=True,
            text=True,
        )
        return library_path

    def _sample(self, original: Path, candidate: Path) -> tuple[subprocess.CompletedProcess[str], dict]:
        result = subprocess.run(
            [
                sys.executable,
                os.fspath(DIFFERENTIAL),
                os.fspath(original),
                os.fspath(candidate),
                "--function",
                "transform",
                "--values",
                "[-2,-1,0,1,2]",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        return result, json.loads(result.stdout)

    def test_equivalent_samples_are_reported_as_tested(self) -> None:
        original = self._compile("original", "int transform(int x) { return x + 1; }\n")
        candidate = self._compile(
            "candidate", "int transform(int x) { int y = x; return y + 1; }\n"
        )

        result, report = self._sample(original, candidate)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(report["correctness"], "TESTED")
        self.assertIs(report["replacement"]["approved"], False)

    def test_arithmetic_drift_reports_counterexample(self) -> None:
        original = self._compile("original", "int transform(int x) { return x + 1; }\n")
        candidate = self._compile("candidate", "int transform(int x) { return x + 2; }\n")

        result, report = self._sample(original, candidate)

        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(report["correctness"], "COUNTEREXAMPLE")
        self.assertIs(report["replacement"]["approved"], False)

    def test_constructor_side_effects_stay_inside_sandbox(self) -> None:
        sentinel = Path("/tmp") / f"decompile-diff-sentinel-{os.getpid()}-{id(self)}"
        self.assertFalse(sentinel.exists())
        source = f"""
            #include <stdio.h>
            __attribute__((constructor)) static void on_load(void) {{
                FILE *f = fopen("{sentinel}", "w");
                if (f) {{ fputs("executed", f); fclose(f); }}
            }}
            int transform(int x) {{ return x + 1; }}
        """
        original = self._compile("original", source)
        candidate = self._compile("candidate", source)

        result, report = self._sample(original, candidate)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(report["correctness"], "TESTED")
        self.assertFalse(sentinel.exists(), "target constructor wrote to host /tmp")


if __name__ == "__main__":
    unittest.main()
