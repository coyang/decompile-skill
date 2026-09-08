/* ###
 * Dump decompiled C per function (one immutable evidence file each) plus
 * functions/calls JSON. Optional script arg: a targets file listing hex
 * addresses or exact function names, one per line (default: every function).
 * Output goes to $GHIDRA_OUTPUT_DIR/<program>/ — these raw dumps are the
 * traceable tool interpretations, not semantic ground truth.
 * @category Export
 */

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Parameter;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.charset.StandardCharsets;
import java.io.PrintWriter;
import java.util.LinkedHashSet;
import java.util.Set;

public class DumpFunctions extends GhidraScript {

    // An explicit selection must never silently become an unrestricted dump.
    static class Targets {
        final Set<String> requested = new LinkedHashSet<>();
        final Set<String> matched = new LinkedHashSet<>();
        static Targets read(String filename) throws IOException {
            Targets result = new Targets();
            for (String line : Files.readAllLines(Path.of(filename), StandardCharsets.UTF_8)) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#")) continue;
                String token = line.split("\\t", 2)[0].trim();
                if (token.isEmpty()) throw new IllegalArgumentException("Empty target");
                result.requested.add(token);
            }
            if (result.requested.isEmpty()) throw new IllegalArgumentException("Empty target selection");
            return result;
        }
        static String address(String value) {
            return value.toLowerCase().replaceFirst("^0x", "").replaceFirst("^0+(?!$)", "");
        }
        boolean matches(String name, String entry) {
            if (requested.isEmpty()) return true;
            boolean found = false;
            for (String token : requested) {
                boolean isAddress = token.matches("(?i)(0x)?[0-9a-f]+");
                if (token.equals(name) || (isAddress && address(token).equals(address(entry)))) {
                    matched.add(token);
                    found = true;
                }
            }
            return found;
        }
        Set<String> unmatched() {
            Set<String> result = new LinkedHashSet<>(requested);
            result.removeAll(matched);
            return result;
        }
    }

    static PrintWriter newEvidenceWriter(File file) throws IOException {
        return new PrintWriter(Files.newBufferedWriter(file.toPath(), StandardCharsets.UTF_8,
            StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE));
    }

    private String jsonArray(Set<String> values) {
        StringBuilder out = new StringBuilder("[");
        for (String value : values) {
            if (out.length() > 1) out.append(',');
            out.append('"').append(esc(value)).append('"');
        }
        return out.append(']').toString();
    }

    private String sanitize(String s) {
        return s.replaceAll("[^a-zA-Z0-9._-]", "_");
    }

    private String esc(String s) {
        if (s == null) return "";
        StringBuilder b = new StringBuilder();
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"': b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\n': b.append("\\n"); break;
                default: if (c < 32) b.append(String.format("\\u%04x", (int)c)); else b.append(c);
            }
        }
        return b.toString();
    }

    private String plainAddr(Function f) {
        String a = f.getEntryPoint().toString().replace("rom:", "");
        return a.toLowerCase();
    }

    @Override
    public void run() throws Exception {
        String outputDir = System.getenv("GHIDRA_OUTPUT_DIR");
        if (outputDir == null || outputDir.isEmpty()) outputDir = ".";
        String program = sanitize(currentProgram.getName());
        File dir = new File(outputDir, program);
        dir.mkdirs();

        String[] args = getScriptArgs();
        Targets targets = args.length > 0 ? Targets.read(args[0]) : new Targets();
        Set<String> failed = new LinkedHashSet<>();

        DecompInterface decomp = new DecompInterface();
        try {
        if (!decomp.openProgram(currentProgram)) throw new IOException("Cannot initialize decompiler");

        File listFile = new File(dir, "fnlist.txt");
        try (PrintWriter list = newEvidenceWriter(listFile);
             PrintWriter fns = newEvidenceWriter(new File(dir, program + "_functions.json"));
             PrintWriter calls = newEvidenceWriter(new File(dir, program + "_calls.json"))) {
        fns.println("{\"program\":\"" + esc(currentProgram.getName())
            + "\",\"language\":\"" + esc(currentProgram.getLanguage().getLanguageID().toString())
            + "\",\"functions\":[");
        calls.println("{\"program\":\"" + esc(currentProgram.getName()) + "\",\"edges\":[");

        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        boolean firstFn = true, firstEdge = true;
        int dumped = 0;

        while (it.hasNext() && !monitor.isCancelled()) {
            Function f = it.next();
            if (f.isExternal()) continue;
            String hex = plainAddr(f);
            if (!targets.matches(f.getName(), hex)) continue;
            DecompileResults res = decomp.decompileFunction(f, 60, monitor);
            boolean recovered = res != null && res.decompileCompleted() && res.getDecompiledFunction() != null;
            if (!recovered) failed.add(hex);
            String fname = sanitize(f.getName());

            // ---- functions.json entry
            if (!firstFn) fns.println(",");
            firstFn = false;
            fns.println("  {\"name\":\"" + esc(f.getName()) + "\",\"addr\":\"" + hex + "\""
                + ",\"size\":" + f.getBody().getNumAddresses()
                + ",\"signature\":\"" + esc(f.getPrototypeString(false, false)) + "\""
                + ",\"decompile_status\":\"" + (recovered ? "completed" : "failed") + "\""
                + ",\"thunk\":" + f.isThunk()
                + ",\"callingConvention\":\"" + esc(f.getCallingConventionName()) + "\""
                + ",\"params\":[");
            Parameter[] ps = f.getParameters();
            for (int i = 0; i < ps.length; i++) {
                fns.println("    {\"name\":\"" + esc(ps[i].getName()) + "\",\"type\":\""
                    + esc(ps[i].getDataType().getDisplayName()) + "\""
                    + ",\"ordinal\":" + i + "}"
                    + (i + 1 < ps.length ? "," : ""));
            }
            fns.println("  ],\"returns\":\"" + esc(f.getReturnType().getDisplayName()) + "\"}");

            // ---- Ghidra-resolved call edges; unresolved indirect dispatch remains a gap.
            for (Function callee : f.getCalledFunctions(monitor)) {
                if (!firstEdge) calls.println(",");
                firstEdge = false;
                calls.println("  {\"caller\":\"" + esc(f.getName()) + "\",\"callerAddr\":\"" + hex
                    + "\",\"callee\":\"" + esc(callee.getName()) + "\",\"calleeAddr\":\""
                    + plainAddr(callee) + "\"}");
            }

            // ---- per-function evidence file: disasm header + decompiler body
            File outFile = new File(dir, "fn_" + hex + "_" + fname + ".c");
            try (PrintWriter w = newEvidenceWriter(outFile)) {
                w.println("/* RAW Ghidra output - immutable evidence. program="
                    + currentProgram.getName() + " func=" + f.getName()
                    + " addr=" + hex + " size=" + f.getBody().getNumAddresses() + " */");
                w.println("/* --- disassembly --- */");
                InstructionIterator ins = currentProgram.getListing()
                    .getInstructions(f.getBody(), true);
                while (ins.hasNext() && !monitor.isCancelled()) {
                    Instruction in = ins.next();
                    w.println("/* " + in.getAddress() + " */  " + in.toString());
                }
                w.println("/* --- decompiler --- */");
                if (recovered) {
                    w.println(res.getDecompiledFunction().getC());
                } else {
                    w.println("/* DECOMPILE FAILED: "
                        + esc(res != null ? res.getErrorMessage() : "no result") + " */");
                }
                if (w.checkError()) throw new IOException("Failed writing " + outFile);
            }
            list.println(hex + "\t" + f.getName());
            dumped++;
        }

        fns.println("]\n}");
        calls.println("]\n}");
        boolean writeFailed = fns.checkError() || calls.checkError() || list.checkError();
        fns.close(); calls.close(); list.close();
        if (writeFailed) throw new IOException("Failed writing evidence inventory");
        try (PrintWriter status = newEvidenceWriter(new File(dir, "export-status.json"))) {
            status.println("{\"program\":\"" + esc(currentProgram.getName())
                + "\",\"complete\":" + (!monitor.isCancelled() && failed.isEmpty())
                + ",\"requested\":" + jsonArray(targets.requested)
                + ",\"matched\":" + jsonArray(targets.matched)
                + ",\"unmatched\":" + jsonArray(targets.unmatched())
                + ",\"failed\":" + jsonArray(failed) + ",\"dumped\":" + dumped + "}");
            if (status.checkError()) throw new IOException("Failed writing export status");
        }
        println("DumpFunctions: " + dumped + " functions -> " + dir);
        }
        } finally {
            decomp.dispose();
        }
    }
}
