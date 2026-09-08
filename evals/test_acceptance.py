"""Black-box acceptance tests for the fail-closed decompile verifier.

Legacy baseline captured before the verifier rewrite (GCC 12.3.0, ``-O0``):

* ``return x + 1`` reconstructed as ``return x + 2`` with the fake citation
  ``src:@0xdeadbeef`` passed V1--V7/V9 and exited 0.  V7 accepted the address
  because a relocatable ``.o`` has no executable LOAD range.
* ``if (x > 0) return 1; else return 2;`` reconstructed equivalently as
  ``if (x <= 0) return 2; else return 1;`` failed V5 and exited 1 because the
  conditional jump mnemonic changed.
* Both runs printed an uncaught V9 ``ValueError`` but continued to a verdict.

These observations document why the old V1--V9 scorecard was retired.  They
are deliberately not assertions: the new verifier must not preserve legacy
heuristic behavior.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest


SKILL_DIR = Path(__file__).resolve().parents[1]
VERIFY = SKILL_DIR / "scripts" / "verify.py"
VERIFY_SH = SKILL_DIR / "scripts" / "verify.sh"
GCC = Path(shutil.which("gcc") or "/usr/bin/gcc")
GCC_BYTES = GCC.resolve()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


class VerifyAcceptanceTests(unittest.TestCase):
    maxDiff = None

    def setUp(self) -> None:
        self._tempdir = tempfile.TemporaryDirectory(prefix="decompile-verify-")
        self.root = Path(self._tempdir.name)
        self.original = self.root / "original.so"
        self.tree = self.root / "reconstruction"
        (self.tree / "src").mkdir(parents=True)
        (self.tree / "include").mkdir()
        self.report_path = self.root / "report.json"

    def tearDown(self) -> None:
        self._tempdir.cleanup()

    def _write_tree(
        self, source: str, *, candidate: str = "rebuilt.so", ldflags: str = ""
    ) -> None:
        (self.tree / "src" / "library.c").write_text(
            textwrap.dedent(source).lstrip(), encoding="utf-8"
        )
        (self.tree / "Makefile").write_text(
            textwrap.dedent(
                f"""\
                .PHONY: all clean
                all: {candidate}

                {candidate}: src/library.c
                \t/usr/bin/gcc -O0 -fPIC -shared src/library.c -o {candidate} {ldflags}

                clean:
                \trm -f {candidate}
                """
            ),
            encoding="utf-8",
        )
        subprocess.run(
            ["make", "clean", "all"],
            cwd=self.tree,
            check=True,
            capture_output=True,
            text=True,
        )

    def _compile_original(self, source: str, *, ldflags: str = "") -> None:
        build_dir = self.root / "original-build"
        source_path = build_dir / "src" / "library.c"
        source_path.parent.mkdir(parents=True)
        source_path.write_text(textwrap.dedent(source).lstrip(), encoding="utf-8")
        command = [
            str(GCC),
            "-O0",
            "-fPIC",
            "-shared",
            "src/library.c",
            "-o",
            str(self.original),
        ]
        if ldflags:
            command.append(ldflags)
        subprocess.run(
            command,
            cwd=build_dir,
            check=True,
            capture_output=True,
            text=True,
        )

    def _invoke(
        self,
        *,
        candidate: str = "rebuilt.so",
        policy: Path | None = None,
        policy_sha256: str | None = None,
        original: Path | None = None,
        entrypoint: Path = VERIFY,
    ) -> tuple[subprocess.CompletedProcess[str], dict]:
        launcher = ["bash", os.fspath(entrypoint)] if entrypoint.suffix == ".sh" else [sys.executable, os.fspath(entrypoint)]
        command = launcher + [
            os.fspath(original or self.original),
            os.fspath(self.tree),
            "--candidate",
            candidate,
            "--json",
            os.fspath(self.report_path),
        ]
        if policy is not None:
            command.extend(["--policy", os.fspath(policy)])
        if policy_sha256 is not None:
            command.extend(["--policy-sha256", policy_sha256])
        result = subprocess.run(command, capture_output=True, text=True, timeout=45)
        self.assertTrue(
            self.report_path.is_file(),
            f"verifier did not write JSON report\nstdout={result.stdout}\nstderr={result.stderr}",
        )
        return result, json.loads(self.report_path.read_text(encoding="utf-8"))

    def _assert_denied(self, result: subprocess.CompletedProcess[str], report: dict) -> None:
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(report["schema_version"], 2)
        self.assertIs(report["replacement"]["approved"], False)

    def _valid_policy(self, source_sha256: str) -> Path:
        policy_path = self.root / "acceptance-policy.json"
        self.assertFalse(policy_path.is_relative_to(self.tree))
        _, pin_report = self._invoke()
        self.assertEqual(pin_report["sources"]["sha256"], source_sha256)
        policy = {
            "schema_version": 1,
            "original_sha256": sha256_file(self.original),
            "source_sha256": source_sha256,
            "tools": pin_report["tools"],
            "scope": {
                "id": "test",
                "observations": ["return"],
                "assumptions": ["same runtime"],
            },
            "environment": {
                "id": "local",
                "system": platform.system(),
                "machine": platform.machine(),
                "release": platform.release(),
                "files": {os.fspath(GCC): sha256_file(GCC_BYTES)},
            },
            "deployment": {
                "target": os.fspath(self.original.resolve()),
                "strategy": "cold-start",
                "rollback_sha256": sha256_file(self.original),
                "loader_context_unchanged": True,
            },
            "build": {
                "compiler": os.fspath(GCC),
                "compiler_sha256": sha256_file(GCC_BYTES),
                "sources": ["src/library.c"],
                "flags": ["-O0"],
                "timeout_seconds": 30,
            },
        }
        policy_path.write_text(json.dumps(policy, sort_keys=True), encoding="utf-8")
        return policy_path

    def _mutate_policy(self, policy_path: Path, mutation) -> str:
        policy = json.loads(policy_path.read_text(encoding="utf-8"))
        mutation(policy)
        policy_path.write_text(json.dumps(policy, sort_keys=True), encoding="utf-8")
        return sha256_file(policy_path)

    def _source_hash(self) -> str:
        _, report = self._invoke()
        return report["sources"]["sha256"]

    def _rewrite_makefile(self, *commands: str) -> None:
        recipes = "\n".join(f"\t{command}" for command in commands)
        (self.tree / "Makefile").write_text(
            f".PHONY: all clean\nall:\n{recipes}\nclean:\n\t/bin/true\n",
            encoding="utf-8",
        )

    def test_missing_policy_denies_replacement(self) -> None:
        source = "int transform(int x) { return x + 1; }\n"
        self._compile_original(source)
        self._write_tree(source)

        result, report = self._invoke()

        self._assert_denied(result, report)

    def test_no_policy_report_contains_canonical_source_hash(self) -> None:
        source = "int transform(int x) { return x + 1; }\n"
        self._compile_original(source)
        self._write_tree(source)

        _, report = self._invoke()

        self.assertRegex(report["sources"]["sha256"], r"^[0-9a-f]{64}$")

    def test_compatibility_wrapper_is_fail_closed_without_policy(self) -> None:
        source = "int transform(int x) { return x + 1; }\n"
        self._compile_original(source)
        self._write_tree(source)

        result, report = self._invoke(entrypoint=VERIFY_SH)

        self._assert_denied(result, report)

    def test_byte_equal_candidate_is_proved_identical_without_policy(self) -> None:
        source = "int transform(int x) { return x + 1; }\n"
        self._compile_original(source)
        self._write_tree(source)

        result, report = self._invoke()

        self._assert_denied(result, report)
        self.assertEqual(report["correctness"]["status"], "PROVED_IDENTICAL")

    def test_missing_candidate_denies_replacement(self) -> None:
        source = "int transform(int x) { return x + 1; }\n"
        self._compile_original(source)
        self._write_tree(source, candidate="actual.so")

        result, report = self._invoke(candidate="missing.so")

        self._assert_denied(result, report)

    def test_malformed_original_denies_replacement(self) -> None:
        self.original.write_text("this is not an ELF artifact\n", encoding="utf-8")
        self._write_tree("int transform(int x) { return x + 1; }\n")

        result, report = self._invoke()

        self._assert_denied(result, report)

    def test_malformed_candidate_denies_replacement(self) -> None:
        source = "int transform(int x) { return x + 1; }\n"
        self._compile_original(source)
        self._write_tree(source)
        (self.tree / "rebuilt.so").write_text("not an ELF artifact\n", encoding="utf-8")

        result, report = self._invoke()

        self._assert_denied(result, report)

    def test_arithmetic_drift_remains_unknown_without_proof(self) -> None:
        self._compile_original("int transform(int x) { return x + 1; }\n")
        self._write_tree("int transform(int x) { return x + 2; }\n")

        result, report = self._invoke()

        self._assert_denied(result, report)
        self.assertEqual(report["correctness"]["status"], "UNKNOWN")

    def test_equivalent_control_flow_inversion_is_not_declared_different(self) -> None:
        self._compile_original(
            "int classify(int x) { if (x > 0) return 1; else return 2; }\n"
        )
        self._write_tree(
            "int classify(int x) { if (x <= 0) return 2; else return 1; }\n"
        )

        result, report = self._invoke()

        self._assert_denied(result, report)
        self.assertEqual(report["correctness"]["status"], "UNKNOWN")

    def test_verification_does_not_execute_target_constructors(self) -> None:
        marker = self.root / "constructor-ran"
        source = f"""
            #include <stdio.h>
            __attribute__((constructor)) static void on_load(void) {{
                FILE *f = fopen("{marker}", "w");
                if (f) {{ fputs("executed", f); fclose(f); }}
            }}
            int transform(int x) {{ return x + 1; }}
        """
        self._compile_original(source)
        self._write_tree(source)

        result, report = self._invoke()

        self._assert_denied(result, report)
        self.assertFalse(marker.exists(), "the verifier loaded an untrusted target library")

    def test_policy_hash_mismatch_denies_replacement(self) -> None:
        source = "int transform(int x) { return x + 1; }\n"
        self._compile_original(source)
        self._write_tree(source)
        _, first_report = self._invoke()
        policy = self._valid_policy(first_report["sources"]["sha256"])

        result, report = self._invoke(policy=policy, policy_sha256="0" * 64)

        self._assert_denied(result, report)

    def test_source_pin_mismatch_denies_replacement(self) -> None:
        source = "int transform(int x) { return x + 1; }\n"
        self._compile_original(source)
        self._write_tree(source)
        policy = self._valid_policy(self._source_hash())
        policy_hash = self._mutate_policy(
            policy, lambda value: value.__setitem__("source_sha256", "0" * 64)
        )

        result, report = self._invoke(policy=policy, policy_sha256=policy_hash)

        self._assert_denied(result, report)

    def test_environment_pin_mismatch_denies_replacement(self) -> None:
        source = "int transform(int x) { return x + 1; }\n"
        self._compile_original(source)
        self._write_tree(source)
        policy = self._valid_policy(self._source_hash())
        policy_hash = self._mutate_policy(
            policy,
            lambda value: value["environment"].__setitem__("machine", "wrong-machine"),
        )

        result, report = self._invoke(policy=policy, policy_sha256=policy_hash)

        self._assert_denied(result, report)

    def test_target_hash_mismatch_denies_replacement(self) -> None:
        source = "int transform(int x) { return x + 1; }\n"
        self._compile_original(source)
        self._write_tree(source)
        wrong_target = self.root / "wrong-target.so"
        wrong_source = self.root / "wrong-target.c"
        wrong_source.write_text("int transform(int x) { return x + 9; }\n", encoding="utf-8")
        subprocess.run(
            [str(GCC), "-O0", "-fPIC", "-shared", str(wrong_source), "-o", str(wrong_target)],
            check=True,
            capture_output=True,
            text=True,
        )
        policy = self._valid_policy(self._source_hash())
        policy_hash = self._mutate_policy(
            policy,
            lambda value: value["deployment"].__setitem__(
                "target", os.fspath(wrong_target)
            ),
        )

        result, report = self._invoke(policy=policy, policy_sha256=policy_hash)

        self._assert_denied(result, report)

    def test_clean_build_must_reproduce_submitted_candidate(self) -> None:
        source = """
            int transform(int x) {
            #ifdef CHANGED
                return x + 2;
            #else
                return x + 1;
            #endif
            }
        """
        self._compile_original(source)
        self._write_tree(source)
        (self.tree / "src" / "library.c").write_text(
            textwrap.dedent(source).replace("#ifdef CHANGED", "#if 1").lstrip(),
            encoding="utf-8",
        )
        policy = self._valid_policy(self._source_hash())

        result, report = self._invoke(
            policy=policy, policy_sha256=sha256_file(policy)
        )

        self._assert_denied(result, report)

    def test_symlink_candidate_denies_replacement(self) -> None:
        source = "int transform(int x) { return x + 1; }\n"
        self._compile_original(source)
        self._write_tree(source)
        candidate = self.tree / "rebuilt.so"
        candidate.unlink()
        candidate.symlink_to(self.original)

        result, report = self._invoke()

        self._assert_denied(result, report)

    def test_symlink_source_denies_replacement(self) -> None:
        source = "int transform(int x) { return x + 1; }\n"
        self._compile_original(source)
        self._write_tree(source)
        external_header = self.root / "external.h"
        external_header.write_text("#define EXTERNAL 1\n", encoding="utf-8")
        (self.tree / "include" / "external.h").symlink_to(external_header)

        result, report = self._invoke()

        self._assert_denied(result, report)

    def test_binary_blob_in_source_tree_denies_replacement(self) -> None:
        source = "int transform(int x) { return x + 1; }\n"
        self._compile_original(source)
        self._write_tree(source)
        shutil.copy2(self.tree / "rebuilt.so", self.tree / "src" / "blob.so")

        result, report = self._invoke()

        self._assert_denied(result, report)

    def test_policy_inside_reconstruction_tree_denies_replacement(self) -> None:
        source = "int transform(int x) { return x + 1; }\n"
        self._compile_original(source)
        self._write_tree(source)
        outside_policy = self._valid_policy(self._source_hash())
        inside_policy = self.tree / "policy.json"
        shutil.copy2(outside_policy, inside_policy)

        result, report = self._invoke(
            policy=inside_policy, policy_sha256=sha256_file(inside_policy)
        )

        self._assert_denied(result, report)

    def test_nonidentical_library_without_proof_checker_remains_unknown(self) -> None:
        self._compile_original("int transform(int x) { return x + 1; }\n")
        self._write_tree("int transform(int x) { return x + 2; }\n")
        policy = self._valid_policy(self._source_hash())
        required_observations = [
            "return-values",
            "memory-and-global-state",
            "errors-and-exceptions",
            "external-effects",
            "initialization-and-finalization",
            "termination-and-divergence",
            "concurrency-and-atomics",
        ]
        policy_hash = self._mutate_policy(
            policy,
            lambda value: value["scope"].update(
                profile="elf-observational-equivalence-v1",
                observations=required_observations,
                consumers=["test-consumer"],
            ),
        )

        result, report = self._invoke(policy=policy, policy_sha256=policy_hash)

        self._assert_denied(result, report)
        self.assertEqual(report["correctness"]["status"], "UNKNOWN")
        self.assertIn("proof verifier missing", report["reason"])

    def test_exported_data_size_change_is_rejected(self) -> None:
        self._compile_original("int exported_data = 1;\n")
        self._write_tree("long exported_data = 1;\n")
        policy = self._valid_policy(self._source_hash())

        result, report = self._invoke(
            policy=policy, policy_sha256=sha256_file(policy)
        )

        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual(report["replacement"]["status"], "REJECTED")
        self.assertIs(report["replacement"]["approved"], False)

    def test_soname_change_is_rejected(self) -> None:
        source = "int transform(int x) { return x + 1; }\n"
        self._compile_original(source, ldflags="-Wl,-soname,liboriginal.so")
        self._write_tree(source, ldflags="-Wl,-soname,libcandidate.so")
        policy = self._valid_policy(self._source_hash())

        result, report = self._invoke(
            policy=policy, policy_sha256=sha256_file(policy)
        )

        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual(report["replacement"]["status"], "REJECTED")
        self.assertIs(report["replacement"]["approved"], False)

    def test_untrusted_makefile_is_not_executed_by_acceptance_gate(self) -> None:
        source = "int transform(int x) { return x + 1; }\n"
        self._compile_original(source)
        self._write_tree(source)
        sentinel = Path("/tmp") / f"decompile-host-sentinel-{os.getpid()}-{id(self)}"
        self.assertFalse(sentinel.exists())
        self._rewrite_makefile(
            f"/usr/bin/touch {sentinel}",
            "/usr/bin/false",
        )
        policy = self._valid_policy(self._source_hash())

        result, report = self._invoke(
            policy=policy, policy_sha256=sha256_file(policy)
        )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIs(report["replacement"]["approved"], True)
        self.assertFalse(sentinel.exists(), "sandboxed build wrote to the host filesystem")

    def test_approved_identity_does_not_execute_target_constructors(self) -> None:
        sentinel = Path("/tmp") / f"decompile-accept-sentinel-{os.getpid()}-{id(self)}"
        self.assertFalse(sentinel.exists())
        source = f"""
            #include <stdio.h>
            __attribute__((constructor)) static void on_load(void) {{
                FILE *f = fopen("{sentinel}", "w");
                if (f) {{ fputs("executed", f); fclose(f); }}
            }}
            int transform(int x) {{ return x + 1; }}
        """
        self._compile_original(source)
        self._write_tree(source)
        policy = self._valid_policy(self._source_hash())

        result, report = self._invoke(
            policy=policy, policy_sha256=sha256_file(policy)
        )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIs(report["replacement"]["approved"], True)
        self.assertFalse(sentinel.exists(), "acceptance gate loaded a target library")

    def test_json_path_inside_source_tree_is_not_overwritten(self) -> None:
        source = "int transform(int x) { return x + 1; }\n"
        self._compile_original(source)
        self._write_tree(source)
        source_path = self.tree / "src" / "library.c"
        before = source_path.read_bytes()
        command = [
            sys.executable,
            os.fspath(VERIFY),
            os.fspath(self.original),
            os.fspath(self.tree),
            "--candidate",
            "rebuilt.so",
            "--json",
            os.fspath(source_path),
        ]

        result = subprocess.run(command, capture_output=True, text=True, timeout=45)

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(source_path.read_bytes(), before)

    def test_json_path_equal_to_deployment_target_is_not_overwritten(self) -> None:
        source = "int transform(int x) { return x + 1; }\n"
        self._compile_original(source)
        self._write_tree(source)
        target = self.root / "deployed.so"
        shutil.copy2(self.original, target)
        before = target.read_bytes()
        policy = self._valid_policy(self._source_hash())
        policy_hash = self._mutate_policy(
            policy,
            lambda value: value["deployment"].__setitem__("target", os.fspath(target)),
        )
        command = [
            sys.executable,
            os.fspath(VERIFY),
            os.fspath(self.original),
            os.fspath(self.tree),
            "--candidate",
            "rebuilt.so",
            "--policy",
            os.fspath(policy),
            "--policy-sha256",
            policy_hash,
            "--json",
            os.fspath(target),
        ]

        result = subprocess.run(command, capture_output=True, text=True, timeout=45)

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(target.read_bytes(), before)

    def test_byte_identical_build_with_matching_policy_is_approved(self) -> None:
        source = "int transform(int x) { return x + 1; }\n"
        self._compile_original(source)
        self._write_tree(source)
        _, first_report = self._invoke()
        policy = self._valid_policy(first_report["sources"]["sha256"])

        result, report = self._invoke(
            policy=policy, policy_sha256=sha256_file(policy)
        )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(report["schema_version"], 2)
        self.assertEqual(report["correctness"]["status"], "PROVED_IDENTICAL")
        self.assertIs(report["replacement"]["approved"], True)


if __name__ == "__main__":
    unittest.main()
