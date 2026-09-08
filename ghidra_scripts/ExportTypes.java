/* ###
 * Export the program's user data types (structs/unions/enums/typedefs under
 * the /DWARF and /Default categories) as COMPILABLE C declarations ->
 * $GHIDRA_OUTPUT_DIR/<program>/<program>_types.c.
 * When DWARF is present, Ghidra's analyzers populate these with ORIGINAL
 * struct/field names, so this becomes the deep-mode types header near
 * verbatim (verification-assisted reconstruction, not invention). Without
 * DWARF, it exports whatever analysis inferred — triage.json's tier tells
 * the reader which world they are in.
 * The export carries its own builtin-typedef prelude and forward
 * declarations (round-1 dim5: bare Ghidra output was not valid C — composite
 * members printed as bare tags, pads reused one member name, module-archive
 * types like FILE/_IO_* collided with system headers once compiled).
 * @category Export
 */

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.Union;

import java.io.File;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class ExportTypes extends GhidraScript {

    // C11 7.1.3 reserved identifier namespaces: everything glibc-internal
    // pulled in through #include (struct _IO_FILE, __off64_t, _G_fpos_t...)
    // lives there, and none of it is evidence about the program's own source.
    private static boolean reserved(String n) {
        return n.startsWith("__")
            || (n.length() > 1 && n.charAt(0) == '_' && Character.isUpperCase(n.charAt(1)));
    }

    private boolean exported(DataType dt) {
        // iter-1 F11, measured on Ghidra 11.x: DWARF-imported types land under
        // /DWARF/<source-file> (with the program's own file as source
        // archive), analysis-created types under /Default. The old
        // /Default-only filter exported 0 types on a DWARF-ful .so — losing
        // every original struct name.
        if (dt.isDeleted()) return false;
        String cat = dt.getCategoryPath().toString();
        if (!(cat.startsWith("/DWARF") || cat.startsWith("/Default"))) return false;
        // Round-1 dim5 smoke: the generic_clib module-archive idea was wrong —
        // system-internal types (FILE/_IO_*/__off64_t) arrive under the
        // PROGRAM's own archive, pulled in because the source #includes
        // <stdio.h>. Filter them by reserved name instead; a typedef whose
        // base is reserved goes too (typedef _IO_FILE FILE would otherwise
        // collide with the real <stdio.h> once compiled into the tree).
        if (reserved(dt.getName())) return false;
        if (dt instanceof TypeDef) {
            DataType base = ((TypeDef) dt).getDataType();
            while (base instanceof TypeDef) base = ((TypeDef) base).getDataType();
            if (reserved(base.getName())) return false;
        }
        return true;
    }

    // Render "TYPE VAR" handling pointer/array sugar so declarations compile.
    // Composite/Enum get their storage-class keyword (Ghidra's display name is
    // the bare tag, which is not a type name in C).
    private String decl(DataType dt, String var) {
        if (dt instanceof Pointer) {
            DataType target = ((Pointer) dt).getDataType();
            String pointer = target instanceof Array ? "(*" + var + ")" : "*" + var;
            return decl(target, pointer);
        }
        if (dt instanceof Array) {
            Array a = (Array) dt;
            return decl(a.getDataType(), var + "[" + a.getNumElements() + "]");
        }
        if (dt instanceof Composite)
            return (dt instanceof Union ? "union " : "struct ") + baseOf(dt) + " " + var;
        if (dt instanceof Enum) return "enum " + baseOf(dt) + " " + var;
        String name = dt.getDisplayName();
        if (name.startsWith("undefined")) {
            int width = dt.getLength();
            if (width <= 0)
                throw new IllegalStateException("unsupported unsized type " + name);
            return "uint8_t " + var + (width == 1 ? "" : "[" + width + "]");
        }
        return name + " " + var;
    }

    private String baseOf(DataType dt) {
        String n = cName(dt.getName());
        return n.isEmpty() ? "anon" : n;
    }

    private String cName(String name) {
        String n = name == null ? "" : name.replaceAll("[^A-Za-z0-9_]", "_");
        if (!n.isEmpty() && Character.isDigit(n.charAt(0))) n = "_" + n;
        return n;
    }

    private String typeKey(DataType dt) {
        if (dt instanceof Union) return "union:" + baseOf(dt);
        if (dt instanceof Composite) return "struct:" + baseOf(dt);
        if (dt instanceof Enum) return "enum:" + baseOf(dt);
        if (dt instanceof TypeDef) return "typedef:" + cName(dt.getName());
        return dt.getCategoryPath().toString() + "/" + dt.getName();
    }

    private void requireDefinition(DataType dt, boolean behindPointer, String owner,
            Map<String, DataType> available, Set<String> dependencies) {
        if (dt instanceof TypeDef) {
            String key = typeKey(dt);
            if (!key.equals(owner) && available.containsKey(key)) dependencies.add(key);
            return;
        }
        if (dt instanceof Pointer) {
            DataType target = ((Pointer) dt).getDataType();
            // A typedef name must already exist even when a pointer uses it.
            // Struct/union tags are covered by forward declarations, except
            // when an array declarator needs the element type to be complete.
            if (target instanceof TypeDef || target instanceof Enum || target instanceof Array)
                requireDefinition(target, true, owner, available, dependencies);
            return;
        }
        if (dt instanceof Array) {
            requireDefinition(((Array) dt).getDataType(), false, owner, available, dependencies);
            return;
        }
        if (dt instanceof Composite || dt instanceof Enum) {
            String key = typeKey(dt);
            if (behindPointer && dt instanceof Composite) return;
            if (key.equals(owner))
                throw new IllegalStateException("unsupported by-value recursive type " + owner);
            if (!available.containsKey(key))
                throw new IllegalStateException("unexported by-value dependency " + key
                    + " required by " + owner);
            dependencies.add(key);
        }
    }

    private Set<String> dependenciesOf(DataType dt, Map<String, DataType> available) {
        Set<String> dependencies = new HashSet<String>();
        String owner = typeKey(dt);
        if (dt instanceof TypeDef) {
            requireDefinition(((TypeDef) dt).getDataType(), false, owner, available, dependencies);
        } else if (dt instanceof Composite) {
            for (DataTypeComponent comp : ((Composite) dt).getDefinedComponents())
                requireDefinition(comp.getDataType(), false, owner, available, dependencies);
        }
        return dependencies;
    }

    private List<DataType> orderDefinitions(List<DataType> definitions) {
        Map<String, DataType> available = new HashMap<String, DataType>();
        List<DataType> unique = new ArrayList<DataType>();
        for (DataType dt : definitions) {
            String key = typeKey(dt);
            DataType previous = available.get(key);
            if (previous != null) {
                if (!previous.isEquivalent(dt))
                    throw new IllegalStateException("conflicting exported type " + key);
                continue;
            }
            available.put(key, dt);
            unique.add(dt);
        }

        List<DataType> pending = new ArrayList<DataType>(unique);
        List<DataType> ordered = new ArrayList<DataType>();
        Set<String> emitted = new HashSet<String>();
        while (!pending.isEmpty()) {
            boolean progressed = false;
            for (Iterator<DataType> it = pending.iterator(); it.hasNext();) {
                DataType dt = it.next();
                if (!emitted.containsAll(dependenciesOf(dt, available))) continue;
                ordered.add(dt);
                emitted.add(typeKey(dt));
                it.remove();
                progressed = true;
            }
            if (!progressed) {
                List<String> names = new ArrayList<String>();
                for (DataType dt : pending) names.add(typeKey(dt));
                Collections.sort(names);
                throw new IllegalStateException("unsupported by-value type dependency cycle: "
                    + String.join(", ", names));
            }
        }
        return ordered;
    }

    private void validateComposite(Composite c) {
        String type = typeKey(c);
        if (c.getLength() <= 0)
            throw new IllegalStateException("unsupported zero/unknown-size composite " + type);
        if (c.hasExplicitPackingValue() || c.hasExplicitMinimumAlignment() || c.isMachineAligned())
            throw new IllegalStateException("unsupported explicit packing/alignment on " + type);

        Set<String> fields = new HashSet<String>();
        int end = 0;
        for (DataTypeComponent comp : c.getDefinedComponents()) {
            if (comp.isBitFieldComponent())
                throw new IllegalStateException("unsupported bitfield in " + type + " at 0x"
                    + Integer.toHexString(comp.getOffset()));
            if (comp.getOffset() < 0 || comp.getLength() <= 0
                    || comp.getDataType().getLength() != comp.getLength())
                throw new IllegalStateException("unsupported variable or sliced field in " + type
                    + " at 0x" + Integer.toHexString(comp.getOffset()));
            String field = comp.getFieldName();
            if (field == null || field.isEmpty())
                field = "field_" + Integer.toHexString(comp.getOffset());
            field = cName(field);
            if (!fields.add(field))
                throw new IllegalStateException("duplicate C field name " + field + " in " + type);
            if (c instanceof Union) {
                if (comp.getOffset() != 0 || comp.getLength() > c.getLength())
                    throw new IllegalStateException("unsupported union layout in " + type);
            } else {
                if (comp.getOffset() < end || comp.getOffset() + comp.getLength() > c.getLength())
                    throw new IllegalStateException("unsupported overlapping/out-of-range layout in "
                        + type + " at 0x" + Integer.toHexString(comp.getOffset()));
                end = comp.getOffset() + comp.getLength();
            }
        }
    }

    private String layoutAssertions(Composite c) {
        String tag = c instanceof Union ? "union " : "struct ";
        String type = tag + baseOf(c);
        StringBuilder out = new StringBuilder();
        out.append("_Static_assert(sizeof(").append(type).append(") == ")
            .append(c.getLength()).append(", \"").append(baseOf(c))
            .append(" size mismatch\");\n");
        if (c.getAlignment() > 0) {
            out.append("_Static_assert(_Alignof(").append(type).append(") == ")
                .append(c.getAlignment()).append(", \"").append(baseOf(c))
                .append(" alignment mismatch\");\n");
        }
        for (DataTypeComponent comp : c.getDefinedComponents()) {
            String field = comp.getFieldName();
            if (field == null || field.isEmpty())
                field = "field_" + Integer.toHexString(comp.getOffset());
            out.append("_Static_assert(offsetof(").append(type).append(", ")
                .append(cName(field)).append(") == ").append(comp.getOffset())
                .append(", \"").append(baseOf(c)).append(".").append(cName(field))
                .append(" offset mismatch\");\n");
        }
        return out.toString();
    }

    private void validateDefinition(DataType dt) {
        if (dt instanceof Composite) {
            Composite c = (Composite) dt;
            validateComposite(c);
            for (DataTypeComponent comp : c.getDefinedComponents())
                decl(comp.getDataType(), cName(comp.getFieldName()));
        } else if (dt instanceof TypeDef) {
            if (dt.getLength() <= 0)
                throw new IllegalStateException("unsupported unsized typedef " + typeKey(dt));
            decl(((TypeDef) dt).getDataType(), cName(dt.getName()));
        } else if (dt instanceof Enum && dt.getLength() <= 0) {
            throw new IllegalStateException("unsupported unsized enum " + typeKey(dt));
        }
    }

    private void writeFailure(File outFile, IllegalStateException failure) throws Exception {
        String message = failure.getMessage().replace("\\", "\\\\").replace("\"", "\\\"");
        try (PrintWriter w = new PrintWriter(outFile)) {
            w.println("/* ExportTypes refused to emit ABI-unsafe declarations. */");
            w.println("#error \"ExportTypes: " + message + "\"");
        }
    }

    @Override
    public void run() throws Exception {
        String outputDir = System.getenv("GHIDRA_OUTPUT_DIR");
        if (outputDir == null || outputDir.isEmpty()) outputDir = ".";
        String program = currentProgram.getName().replaceAll("[^a-zA-Z0-9._-]", "_");
        File dir = new File(outputDir, program);
        dir.mkdirs();
        File outFile = new File(dir, program + "_types.c");

        DataTypeManager dtm = currentProgram.getDataTypeManager();
        List<DataType> keep = new ArrayList<DataType>();
        Iterator<DataType> all = dtm.getAllDataTypes();
        while (all.hasNext()) {
            DataType dt = all.next();
            if (!exported(dt)) continue;
            if (!(dt instanceof Structure || dt instanceof Union
                  || dt instanceof Enum || dt instanceof TypeDef)) continue;
            if (monitor.isCancelled()) break;
            keep.add(dt);
        }

        try {
            for (DataType dt : keep) validateDefinition(dt);
            keep = orderDefinitions(keep);
        } catch (IllegalStateException failure) {
            writeFailure(outFile, failure);
            throw failure;
        }

        try (PrintWriter w = new PrintWriter(outFile)) {
            w.println("/* Types exported from Ghidra program '" + currentProgram.getName() + "'");
            w.println("   by the decompile skill. Interpretation depends on fidelity tier in");
            w.println("   triage.json: DEBUG -> original names recovered from DWARF;");
            w.println("   SYMTAB/DYNSYM/STRIPPED -> analysis-inferred (offsets cited). */");
            // Self-compiling prelude: the builtin typedefs decl() can name,
            // plus the system headers the usual suspects come from.
            w.println("#ifndef GHIDRA_TYPES_PRELUDE");
            w.println("#define GHIDRA_TYPES_PRELUDE");
            w.println("#include <stdint.h>");
            w.println("#include <stddef.h>");
            w.println("typedef unsigned char byte, undefined;");
            w.println("typedef unsigned short word, ushort;");
            w.println("typedef unsigned int dword;");
            w.println("typedef unsigned long long qword, sqword, oword;");
            w.println("typedef unsigned long ulong;");
            w.println("#endif");
            // Composite tags can be referenced through pointers regardless of
            // the topological definition order established above.
            for (DataType dt : keep) {
                if (dt instanceof Composite)
                    w.println((dt instanceof Union ? "union " : "struct ") + baseOf(dt) + ";");
            }
            for (DataType dt : keep) {
                String tag = dt instanceof Union ? "union" : "struct";
                w.println();
                w.println("/* category: " + dt.getCategoryPath()
                    + " | size: " + dt.getLength() + " */");
                if (dt instanceof Enum) {
                    Enum e = (Enum) dt;
                    w.println("enum " + baseOf(e) + " {");
                    String[] names = e.getNames();
                    for (int i = 0; i < names.length; i++) {
                        long v = e.getValue(names[i]);
                        w.println("  " + names[i] + " = " + v + (i + 1 < names.length ? "," : ""));
                    }
                    w.println("};");
                } else if (dt instanceof TypeDef) {
                    TypeDef td = (TypeDef) dt;
                    String name = cName(td.getName());
                    w.println("typedef " + decl(td.getDataType(), name) + ";");
                    w.println("_Static_assert(sizeof(" + name + ") == " + td.getLength()
                        + ", \"" + name + " size mismatch\");");
                } else {
                    Composite c = (Composite) dt;
                    w.println(tag + " " + baseOf(dt) + " {");
                    DataTypeComponent[] comps = c.getDefinedComponents();
                    int off = 0;
                    for (DataTypeComponent comp : comps) {
                        while (!(c instanceof Union) && off < comp.getOffset()) {
                            // unique name per gap offset: char _pad_[1] x3 is
                            // a duplicate-member error in C
                            w.println("  char _pad_" + Integer.toHexString(off)
                                + "[1]; /* gap @0x" + Integer.toHexString(off) + " */");
                            off++;
                        }
                        String field = comp.getFieldName();
                        if (field == null || field.isEmpty()) field = "field_" + Integer.toHexString(comp.getOffset());
                        field = cName(field);
                        w.println("  " + decl(comp.getDataType(), field)
                            + "; /* @0x" + Integer.toHexString(comp.getOffset())
                            + " len " + comp.getLength() + " */");
                        off = comp.getOffset() + Math.max(1, comp.getLength());
                    }
                    w.println("};");
                    w.print(layoutAssertions(c));
                }
            }
            println("ExportTypes: " + keep.size() + " data types -> " + outFile);
        }
    }
}
