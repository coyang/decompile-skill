#!/usr/bin/env python3
"""Regression tests for the Ghidra headless driver state machine."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import textwrap
import unittest


SKILL_DIR = Path(__file__).resolve().parents[1]


class GhidraDriverTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.skill = self.root / "decompile"
        (self.skill / "scripts").mkdir(parents=True)
        (self.skill / "ghidra_scripts").mkdir()
        for name in ("ghidra-decompile.sh", "ghidra_driver_manifest.py"):
            source = SKILL_DIR / "scripts" / name
            if source.exists():
                shutil.copy2(source, self.skill / "scripts" / name)
        for name in ("DumpFunctions.java", "ExportTypes.java"):
            shutil.copy2(SKILL_DIR / "ghidra_scripts" / name,
                         self.skill / "ghidra_scripts" / name)

        self.ghidra = self.root / "ghidra"
        (self.ghidra / "support").mkdir(parents=True)
        (self.ghidra / "Ghidra" / "application.properties").parent.mkdir(parents=True)
        (self.ghidra / "Ghidra" / "application.properties").write_text(
            "application.version=99.1-test\n", encoding="utf-8"
        )
        fake = self.ghidra / "support" / "analyzeHeadless"
        fake.write_text(textwrap.dedent("""\
            #!/bin/bash
            set -u
            project_dir="$1"; project_name="$2"; shift 2
            mkdir -p "$project_dir"
            touch "$project_dir/$project_name.gpr"
            mkdir -p "$project_dir/$project_name.rep"
            printf '%s\\n' "$*" >> "${FAKE_CALL_LOG:?}"
            program_dir="$GHIDRA_OUTPUT_DIR/70726f6772616d2e6f"
            mkdir -p "$program_dir"
            if [[ -n "${FAKE_STATUS_FILE:-}" ]]; then
              cp "$FAKE_STATUS_FILE" "$program_dir/export-status.json"
            else
              cat > "$program_dir/export-status.json" <<'JSON'
            {"complete":true,"requested":[],"matched":[],"unmatched":[],"failed":[],"dumped":1,"program":"input.o"}
            JSON
            fi
            exit "${FAKE_EXIT_CODE:-0}"
        """), encoding="utf-8")
        fake.chmod(0o755)
        self.artifact = self.root / "input.o"
        self.artifact.write_bytes(b"not important to the fake headless")
        self.work = self.root / "work"
        self.log = self.root / "calls.log"
        self.env = os.environ | {
            "GHIDRA_HOME": str(self.ghidra),
            "FAKE_CALL_LOG": str(self.log),
        }

    def tearDown(self):
        self.tmp.cleanup()

    @property
    def driver(self):
        return self.skill / "scripts" / "ghidra-decompile.sh"

    def run_driver(self, *extra, env=None):
        return subprocess.run(
            ["bash", str(self.driver), str(self.artifact), "--workdir", str(self.work), *extra],
            text=True, capture_output=True, env=env or self.env,
        )

    def manifests(self):
        return sorted((self.work / "ghidra" / "runs").glob("*/run-manifest.json"))

    def test_completed_matching_project_is_reused_and_runs_are_preserved(self):
        first = self.run_driver()
        second = self.run_driver()
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertIn("IMPORT mode", first.stdout)
        self.assertIn("REPROCESS mode", second.stdout)
        self.assertEqual(len(self.manifests()), 2)
        for path in self.manifests():
            manifest = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(manifest["status"], "complete")
            self.assertTrue(manifest["files"])
            self.assertTrue(all(len(item["sha256"]) == 64 for item in manifest["files"]))

    def test_failed_import_is_never_reused(self):
        failed_env = self.env | {"FAKE_EXIT_CODE": "124"}
        failed = self.run_driver(env=failed_env)
        retried = self.run_driver()
        self.assertNotEqual(failed.returncode, 0)
        self.assertEqual(retried.returncode, 0, retried.stderr)
        self.assertIn("IMPORT mode", retried.stdout)
        self.assertNotIn("REPROCESS mode", retried.stdout)
        states = [json.loads(path.read_text(encoding="utf-8"))["status"]
                  for path in self.manifests()]
        self.assertIn("headless-failed", states)

    def test_modified_project_is_not_reused(self):
        first = self.run_driver()
        self.assertEqual(first.returncode, 0, first.stderr)
        project = next((self.work / "ghproj").glob("*.gpr"))
        project.write_bytes(b"externally modified project")
        second = self.run_driver()
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertIn("IMPORT mode", second.stdout)
        self.assertNotIn("REPROCESS mode", second.stdout)

    def test_tool_script_change_invalidates_project_reuse(self):
        first = self.run_driver()
        self.assertEqual(first.returncode, 0, first.stderr)
        dump = self.skill / "ghidra_scripts" / "DumpFunctions.java"
        dump.write_text(dump.read_text(encoding="utf-8") + "\n// changed\n", encoding="utf-8")
        second = self.run_driver()
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertIn("IMPORT mode", second.stdout)

    def test_missing_or_effectively_empty_targets_are_rejected_before_ghidra(self):
        missing = self.run_driver("--targets", str(self.root / "missing.txt"))
        empty_file = self.root / "empty.targets"
        empty_file.write_text("# only a comment\n\n", encoding="utf-8")
        empty = self.run_driver("--targets", str(empty_file))
        self.assertEqual(missing.returncode, 2)
        self.assertEqual(empty.returncode, 2)
        self.assertFalse(self.log.exists())

    def test_unmatched_target_and_malformed_status_fail_closed(self):
        targets = self.root / "targets.txt"
        targets.write_text("wanted_function\n", encoding="utf-8")
        unmatched_status = self.root / "unmatched.json"
        unmatched_status.write_text(json.dumps({
            "complete": True, "requested": ["wanted_function"], "matched": [],
            "unmatched": ["wanted_function"], "failed": [], "dumped": 0,
            "program": "input.o",
        }), encoding="utf-8")
        unmatched = self.run_driver(
            "--targets", str(targets), env=self.env | {"FAKE_STATUS_FILE": str(unmatched_status)}
        )
        self.assertNotEqual(unmatched.returncode, 0)
        self.assertIn("were not found", unmatched.stderr)

        malformed_status = self.root / "malformed.json"
        malformed_status.write_text(json.dumps({
            "complete": "yes", "requested": [], "matched": [], "unmatched": [],
            "failed": [], "dumped": 1, "program": "input.o",
        }), encoding="utf-8")
        malformed = self.run_driver(env=self.env | {"FAKE_STATUS_FILE": str(malformed_status)})
        self.assertNotEqual(malformed.returncode, 0)
        self.assertIn("invalid export status", malformed.stderr)

    @unittest.skipUnless(shutil.which("ar") and shutil.which("cc"), "binutils/compiler required")
    def test_duplicate_archive_member_names_are_rejected_without_extraction(self):
        one = self.root / "one"
        two = self.root / "two"
        one.mkdir(); two.mkdir()
        (one / "same.c").write_text("int one(void){return 1;}\n", encoding="utf-8")
        (two / "same.c").write_text("int two(void){return 2;}\n", encoding="utf-8")
        subprocess.run(["cc", "-c", "same.c", "-o", "same.o"], cwd=one, check=True)
        subprocess.run(["cc", "-c", "same.c", "-o", "same.o"], cwd=two, check=True)
        archive = self.root / "duplicate.a"
        subprocess.run(["ar", "qc", archive, one / "same.o", two / "same.o"], check=True)
        self.artifact = archive
        result = self.run_driver()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("duplicate archive member", result.stderr)
        self.assertFalse(self.log.exists())

    @unittest.skipUnless(shutil.which("ar") and shutil.which("cc"), "binutils/compiler required")
    def test_archive_member_evidence_path_collision_is_rejected(self):
        source = self.root / "unit.c"
        source.write_text("int unit(void){return 1;}\n", encoding="utf-8")
        first = self.root / "a+b.o"
        second = self.root / "a_b.o"
        subprocess.run(["cc", "-c", source, "-o", first], check=True)
        shutil.copy2(first, second)
        archive = self.root / "collision.a"
        subprocess.run(["ar", "qc", archive, first, second], check=True)
        self.artifact = archive
        result = self.run_driver()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("collide after evidence-path sanitization", result.stderr)
        self.assertFalse(self.log.exists())


if __name__ == "__main__":
    unittest.main()
