"""Exercise target selection and non-overwriting output against Ghidra's API."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from test_type_export import GHIDRA_HOME

SKILL = Path(__file__).resolve().parents[1]


class FunctionExportTest(unittest.TestCase):
    def test_targets_and_immutable_writer(self):
        jars = sorted((GHIDRA_HOME / 'Ghidra').rglob('*.jar'))
        if not jars:
            self.skipTest('Ghidra jars unavailable')
        cp = os.pathsep.join(map(str, jars))
        harness = r'''
import java.nio.file.*;
import java.io.*;
public class FunctionExportHarness {
    public static void main(String[] args) throws Exception {
        Path dir = Paths.get(args[0]);
        Path targets = dir.resolve("targets.txt");
        try { DumpFunctions.Targets.read(targets.toString()); throw new AssertionError("missing accepted"); }
        catch (IOException expected) {}
        Files.writeString(targets, "# nothing\n\n");
        try { DumpFunctions.Targets.read(targets.toString()); throw new AssertionError("empty accepted"); }
        catch (IllegalArgumentException expected) {}
        Files.writeString(targets, "add\n0x00004010\tlabel\ndead\nmissing\n");
        DumpFunctions.Targets t = DumpFunctions.Targets.read(targets.toString());
        if (!t.matches("add", "00005000")) throw new AssertionError("hex-like name");
        if (!t.matches("other", "00004010")) throw new AssertionError("padded address");
        if (!t.matches("dead", "00006000")) throw new AssertionError("name");
        if (t.matches("unselected", "00007000")) throw new AssertionError("expanded scope");
        if (t.unmatched().size() != 1 || !t.unmatched().contains("missing")) throw new AssertionError("missing target");
        File out = dir.resolve("evidence.txt").toFile();
        try (PrintWriter w = DumpFunctions.newEvidenceWriter(out)) { w.print("original"); }
        try { DumpFunctions.newEvidenceWriter(out); throw new AssertionError("overwrite accepted"); }
        catch (IOException expected) {}
        if (!Files.readString(out.toPath()).equals("original")) throw new AssertionError("evidence changed");
    }
}
'''
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p / 'FunctionExportHarness.java').write_text(harness)
            result = subprocess.run(['javac', '-proc:none', '-cp', cp, '-d', tmp,
                str(SKILL / 'ghidra_scripts/DumpFunctions.java'), str(p / 'FunctionExportHarness.java')],
                capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            result = subprocess.run(['java', '-cp', cp + os.pathsep + tmp,
                'FunctionExportHarness', tmp], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
