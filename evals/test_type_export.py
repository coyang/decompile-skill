#!/usr/bin/env python3
"""Regression tests for ExportTypes declaration and ABI guards."""

import os
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest


SKILL_DIR = Path(__file__).resolve().parents[1]
EXPORT_TYPES = SKILL_DIR / "ghidra_scripts" / "ExportTypes.java"


def locate_ghidra():
    configured = os.environ.get("GHIDRA_HOME")
    if configured:
        return Path(configured)
    candidates = sorted((Path.home() / "tools").glob("ghidra_*_PUBLIC"), reverse=True)
    candidates += [Path("/opt/ghidra"), Path("/usr/share/ghidra")]
    return next((path for path in candidates if (path / "Ghidra").is_dir()), Path("/nonexistent"))


GHIDRA_HOME = locate_ghidra()


class ExportTypesRegressionTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        jars = sorted((GHIDRA_HOME / "Ghidra").rglob("*.jar"))
        if not jars:
            raise unittest.SkipTest(f"Ghidra jars not found under {GHIDRA_HOME}")
        cls.classpath = os.pathsep.join(map(str, jars))

    def run_harness(self):
        harness = textwrap.dedent(
            """
            import ghidra.program.model.data.*;
            import java.lang.reflect.*;
            import java.util.*;

            public class ExportTypesHarness {
                private static Object call(ExportTypes exporter, String method,
                                           Class<?>[] signature, Object... args) throws Exception {
                    Method m = ExportTypes.class.getDeclaredMethod(method, signature);
                    m.setAccessible(true);
                    try {
                        return m.invoke(exporter, args);
                    } catch (InvocationTargetException e) {
                        throw (Exception) e.getCause();
                    }
                }

                public static void main(String[] args) throws Exception {
                    ExportTypes exporter = new ExportTypes();
                    Method decl = ExportTypes.class.getDeclaredMethod("decl", DataType.class, String.class);
                    decl.setAccessible(true);

                    System.out.println("undefined4=" + decl.invoke(exporter, new Undefined4DataType(), "raw"));
                    DataType threeInts = new ArrayDataType(new IntegerDataType(), 3);
                    System.out.println("ptr_array=" + decl.invoke(exporter,
                        new PointerDataType(threeInts, 8), "values"));

                    CategoryPath dwarf = new CategoryPath("/DWARF/test");
                    StructureDataType inner = new StructureDataType(dwarf, "Inner", 0);
                    inner.add(new IntegerDataType(), 4, "value", null);
                    StructureDataType outer = new StructureDataType(dwarf, "Outer", 0);
                    outer.add(inner, inner.getLength(), "inner", null);
                    @SuppressWarnings("unchecked")
                    List<DataType> ordered = (List<DataType>) call(exporter, "orderDefinitions",
                        new Class<?>[] { List.class }, Arrays.asList(outer, inner));
                    System.out.println("order=" + ordered.get(0).getName() + "," + ordered.get(1).getName());
                    System.out.print(call(exporter, "layoutAssertions",
                        new Class<?>[] { Composite.class }, outer));

                    StructureDataType packed = new StructureDataType(dwarf, "Packed", 0);
                    packed.add(new CharDataType(), 1, "tag", null);
                    packed.add(new IntegerDataType(), 4, "number", null);
                    packed.setExplicitPackingValue(1);
                    try {
                        call(exporter, "validateComposite", new Class<?>[] { Composite.class }, packed);
                        System.out.println("packed=accepted");
                    } catch (IllegalStateException expected) {
                        System.out.println("packed=rejected");
                    }

                    StructureDataType bits = new StructureDataType(dwarf, "Bits", 0);
                    bits.addBitField(new IntegerDataType(), 3, "flags", null);
                    try {
                        call(exporter, "validateComposite", new Class<?>[] { Composite.class }, bits);
                        System.out.println("bitfield=accepted");
                    } catch (IllegalStateException expected) {
                        System.out.println("bitfield=rejected");
                    }
                }
            }
            """
        )
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            harness_path = tmp_path / "ExportTypesHarness.java"
            harness_path.write_text(harness)
            compile_result = subprocess.run(
                ["javac", "-proc:none", "-cp", self.classpath, "-d", tmp,
                 str(EXPORT_TYPES), str(harness_path)],
                text=True, capture_output=True,
            )
            self.assertEqual(compile_result.returncode, 0, compile_result.stderr)
            run_result = subprocess.run(
                ["java", "-cp", self.classpath + os.pathsep + tmp, "ExportTypesHarness"],
                text=True, capture_output=True,
            )
            self.assertEqual(run_result.returncode, 0, run_result.stderr)
            return run_result.stdout

    def test_declarations_order_and_layout_guards(self):
        output = self.run_harness()
        self.assertIn("undefined4=uint8_t raw[4]", output)
        self.assertIn("ptr_array=int (*values)[3]", output)
        self.assertIn("order=Inner,Outer", output)
        self.assertIn("_Static_assert(sizeof(struct Outer) == 4", output)
        self.assertIn("_Static_assert(offsetof(struct Outer, inner) == 0", output)
        self.assertIn("packed=rejected", output)
        self.assertIn("bitfield=rejected", output)


if __name__ == "__main__":
    unittest.main()
