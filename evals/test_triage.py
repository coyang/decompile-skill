#!/usr/bin/env python3
"""Regression tests for conservative ELF/archive triage reporting."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import textwrap
import unittest


SKILL_DIR = Path(__file__).resolve().parents[1]
TRIAGE = SKILL_DIR / "scripts" / "triage.sh"


class TriageRegressionTest(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)

    def tearDown(self):
        self.tempdir.cleanup()

    def compile_c(self, name="unit.o", source="int visible(void) { return 1; }\n"):
        source_path = self.root / f"{name}.c"
        object_path = self.root / name
        source_path.write_text(source)
        result = subprocess.run(
            ["cc", "-c", str(source_path), "-o", str(object_path)],
            text=True,
            capture_output=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return object_path

    def run_triage(self, artifact, output_name="out", env=None):
        output = self.root / output_name
        result = subprocess.run(
            ["bash", str(TRIAGE), str(artifact), "--out", str(output)],
            text=True,
            capture_output=True,
            env=env,
        )
        report_path = output / "triage.json"
        report = json.loads(report_path.read_text()) if report_path.exists() else None
        return result, report

    def test_duplicate_archive_members_are_explicitly_refused(self):
        first_dir = self.root / "first"
        second_dir = self.root / "second"
        first_dir.mkdir()
        second_dir.mkdir()
        first = self.compile_c("first.o", "int first(void) { return 1; }\n")
        second = self.compile_c("second.o", "int second(void) { return 2; }\n")
        first_named = first_dir / "same.o"
        second_named = second_dir / "same.o"
        shutil.copy2(first, first_named)
        shutil.copy2(second, second_named)
        archive = self.root / "duplicates.a"
        result = subprocess.run(
            ["ar", "q", str(archive), str(first_named), str(second_named)],
            text=True,
            capture_output=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

        triage_result, report = self.run_triage(archive)

        self.assertEqual(triage_result.returncode, 1)
        self.assertEqual(report["kind"], "archive")
        self.assertIn("duplicate", report["refuse_reason"].lower())
        self.assertEqual(report["archive_member_names"], ["same.o", "same.o"])

    def test_archive_member_order_is_preserved(self):
        first = self.compile_c("z-last.o", "int first(void) { return 1; }\n")
        second = self.compile_c("a-first.o", "int second(void) { return 2; }\n")
        archive = self.root / "ordered.a"
        result = subprocess.run(
            ["ar", "q", str(archive), str(first), str(second)],
            text=True,
            capture_output=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

        triage_result, report = self.run_triage(archive)

        self.assertEqual(triage_result.returncode, 0, triage_result.stderr)
        self.assertEqual(
            [member["name"] for member in report["members"]],
            ["z-last.o", "a-first.o"],
        )

    def test_non_cpp_input_language_is_unknown(self):
        artifact = self.compile_c()
        result, report = self.run_triage(artifact)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(report["lang"], "unknown")
        self.assertEqual(report["members"][0]["lang"], "unknown")

    def test_function_counts_describe_scope_and_completeness(self):
        artifact = self.compile_c()
        result, report = self.run_triage(artifact)

        self.assertEqual(result.returncode, 0, result.stderr)
        member = report["members"][0]
        self.assertEqual(member["fn_count_status"], "known")
        self.assertFalse(member["fn_count_complete"])
        self.assertIn("symbol", member["fn_count_basis"])
        self.assertIn("not an actual function count", member["fn_count_basis"])
        self.assertEqual(member["fn_count_scope"], "visible-symbol-count")
        self.assertEqual(report["fn_count_status"], "known")
        self.assertFalse(report["fn_count_complete"])

    def test_symbol_aliases_are_not_described_as_a_function_lower_bound(self):
        assembly = self.root / "aliases.s"
        artifact = self.root / "aliases.o"
        assembly.write_text(
            ".text\n.globl implementation, alias\n"
            "implementation:\nret\n.set alias, implementation\n"
        )
        build = subprocess.run(
            ["cc", "-c", str(assembly), "-o", str(artifact)],
            text=True,
            capture_output=True,
        )
        self.assertEqual(build.returncode, 0, build.stderr)

        result, report = self.run_triage(artifact)

        self.assertEqual(result.returncode, 0, result.stderr)
        member = report["members"][0]
        self.assertEqual(member["funcs"], 2)
        self.assertNotIn("lower bound", member["fn_count_basis"])
        self.assertIn("not an actual function count", member["fn_count_basis"])

    def test_zero_nm_symbols_with_symtab_reports_unknown_count(self):
        assembly = self.root / "unnamed.s"
        artifact = self.root / "unnamed.o"
        assembly.write_text(
            ".data\n.globl datum\ndatum:\n.long 1\n"
            ".text\n.byte 0x90, 0x90, 0x90\n"
        )
        build = subprocess.run(
            ["cc", "-c", str(assembly), "-o", str(artifact)],
            text=True,
            capture_output=True,
        )
        self.assertEqual(build.returncode, 0, build.stderr)

        result, report = self.run_triage(artifact)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(report["members"][0]["tier"], "SYMTAB")
        self.assertEqual(report["members"][0]["fn_count_status"], "unknown")

    def test_stripped_unit_without_census_reports_unknown_count(self):
        assembly = self.root / "unknown.s"
        artifact = self.root / "unknown.o"
        assembly.write_text(".text\n.byte 0x90, 0x90, 0x90\n")
        build = subprocess.run(
            ["cc", "-c", str(assembly), "-o", str(artifact)],
            text=True,
            capture_output=True,
        )
        self.assertEqual(build.returncode, 0, build.stderr)
        strip = subprocess.run(
            ["strip", "--strip-all", str(artifact)], text=True, capture_output=True
        )
        self.assertEqual(strip.returncode, 0, strip.stderr)

        result, report = self.run_triage(artifact)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(report["members"][0]["fn_count_status"], "unknown")
        self.assertEqual(report["fn_count_status"], "unknown")

    def test_instruction_census_is_labeled_estimated(self):
        assembly = self.root / "estimated.s"
        artifact = self.root / "estimated.o"
        assembly.write_text(
            textwrap.dedent(
                """
                .text
                .byte 0xf3, 0x0f, 0x1e, 0xfa
                ret
                """
            )
        )
        build = subprocess.run(
            ["cc", "-c", str(assembly), "-o", str(artifact)],
            text=True,
            capture_output=True,
        )
        self.assertEqual(build.returncode, 0, build.stderr)
        strip = subprocess.run(
            ["strip", "--strip-all", str(artifact)], text=True, capture_output=True
        )
        self.assertEqual(strip.returncode, 0, strip.stderr)

        result, report = self.run_triage(artifact)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(report["members"][0]["fn_count_status"], "estimated")
        self.assertEqual(report["fn_count_status"], "estimated")

    def test_json_escaping_handles_control_characters_in_names(self):
        artifact = self.compile_c()
        unusual = self.root / 'quote"backslash\\newline\n.o'
        shutil.copy2(artifact, unusual)

        result, report = self.run_triage(unusual)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(report["members"][0]["name"], unusual.name)

    def test_empty_and_non_code_archives_have_unknown_function_count(self):
        empty = self.root / "empty.a"
        create_empty = subprocess.run(
            ["ar", "cr", str(empty)], text=True, capture_output=True
        )
        self.assertEqual(create_empty.returncode, 0, create_empty.stderr)
        empty_result, empty_report = self.run_triage(empty, "empty-out")
        self.assertEqual(empty_result.returncode, 0, empty_result.stderr)
        self.assertEqual(empty_report["fn_count_status"], "unknown")

        text_member = self.root / "notes.txt"
        text_member.write_text("not object code\n")
        non_code = self.root / "non-code.a"
        create_non_code = subprocess.run(
            ["ar", "q", str(non_code), str(text_member)],
            text=True,
            capture_output=True,
        )
        self.assertEqual(create_non_code.returncode, 0, create_non_code.stderr)
        non_code_result, non_code_report = self.run_triage(non_code, "non-code-out")
        self.assertEqual(non_code_result.returncode, 0, non_code_result.stderr)
        self.assertEqual(non_code_report["fn_count_status"], "unknown")

    def test_member_named_like_temporary_archive_does_not_break_later_members(self):
        first = self.compile_c("first.o", "int first(void) { return 1; }\n")
        second = self.compile_c("second.o", "int second(void) { return 2; }\n")
        collision = self.root / "a.ar"
        shutil.copy2(first, collision)
        archive = self.root / "container.a"
        create = subprocess.run(
            ["ar", "q", str(archive), str(collision), str(second)],
            text=True,
            capture_output=True,
        )
        self.assertEqual(create.returncode, 0, create.stderr)

        result, report = self.run_triage(archive)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([item["name"] for item in report["members"]], ["a.ar", "second.o"])

    def test_lto_only_archive_has_unknown_function_count(self):
        source = self.root / "lto.c"
        artifact = self.root / "lto.o"
        source.write_text("int lto_function(void) { return 1; }\n")
        build = subprocess.run(
            ["cc", "-flto", "-c", str(source), "-o", str(artifact)],
            text=True,
            capture_output=True,
        )
        if build.returncode != 0:
            self.skipTest("compiler does not support -flto")
        archive = self.root / "lto.a"
        create = subprocess.run(
            ["ar", "q", str(archive), str(artifact)], text=True, capture_output=True
        )
        self.assertEqual(create.returncode, 0, create.stderr)

        result, report = self.run_triage(archive)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(report["members"][0]["kind"], "lto")
        self.assertEqual(report["fn_count_status"], "unknown")

    def test_failed_section_table_read_is_explicitly_refused(self):
        artifact = self.compile_c()
        real_readelf = shutil.which("readelf")
        self.assertIsNotNone(real_readelf)
        tools = self.root / "tools"
        tools.mkdir()
        wrapper = tools / "readelf"
        wrapper.write_text(
            "#!/bin/sh\n"
            'if [ "$1" = "-SW" ]; then exit 3; fi\n'
            f'exec "{real_readelf}" "$@"\n'
        )
        wrapper.chmod(0o755)
        env = os.environ.copy()
        env["PATH"] = str(tools) + os.pathsep + env["PATH"]

        result, report = self.run_triage(artifact, "readelf-failure", env)

        self.assertEqual(result.returncode, 1)
        self.assertEqual(report["kind"], "corrupt")
        self.assertIn("readelf failed", report["refuse_reason"])


if __name__ == "__main__":
    unittest.main()
