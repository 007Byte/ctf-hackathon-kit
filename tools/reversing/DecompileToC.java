/* DecompileToC.java - Ghidra headless post-script: dump all functions to C
 * ===========================================================================
 * AUTHORIZED / EDUCATIONAL USE ONLY.
 *   For CTF challenges, hackathons, and binaries you own or are explicitly
 *   authorized to analyze. Do not use against software you lack permission to
 *   inspect.
 * ===========================================================================
 *
 * This GhidraScript is meant to be run as a -postScript by analyzeHeadless
 * (see ghidra-decompile.sh). It walks every function in the current program,
 * decompiles each one with the DecompInterface, and writes the resulting C to
 * a single output file.
 *
 * Output path resolution (in order):
 *   1. First script argument (getScriptArgs()[0])  -- preferred, set by wrapper
 *   2. Default: <executablePath>.decompiled.c next to the imported binary
 *   3. Final fallback: <user.home>/<programName>.decompiled.c
 *
 * API references (Ghidra 10.x / 11.x):
 *   ghidra.app.decompiler.DecompInterface
 *   DecompInterface.openProgram(Program)
 *   DecompInterface.decompileFunction(Function, int timeoutSecs, TaskMonitor)
 *   DecompileResults.decompileCompleted()
 *   DecompileResults.getDecompiledFunction().getC()
 *
 * @category CTF.Reversing
 */

import java.io.PrintWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.BufferedWriter;

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.util.task.ConsoleTaskMonitor;

public class DecompileToC extends GhidraScript {

    // Per-function decompiler timeout in seconds.
    private static final int DECOMPILE_TIMEOUT = 60;

    @Override
    public void run() throws Exception {

        if (currentProgram == null) {
            println("[DecompileToC] No current program - nothing to do.");
            return;
        }

        // -------------------------------------------------------------------
        // Resolve the output path.
        // -------------------------------------------------------------------
        String outPath = resolveOutputPath();
        println("[DecompileToC] Writing decompiled C to: " + outPath);

        // -------------------------------------------------------------------
        // Set up the decompiler interface.
        // -------------------------------------------------------------------
        DecompInterface decomp = new DecompInterface();
        try {
            // Apply sane default decompiler options for this program.
            DecompileOptions options = new DecompileOptions();
            decomp.setOptions(options);

            if (!decomp.openProgram(currentProgram)) {
                println("[DecompileToC] ERROR: failed to open program in the "
                        + "decompiler: " + decomp.getLastMessage());
                return;
            }

            ConsoleTaskMonitor monitor = new ConsoleTaskMonitor();
            FunctionManager fm = currentProgram.getFunctionManager();

            int total = 0;
            int ok = 0;
            int failed = 0;

            // BufferedWriter wrapping a FileWriter; PrintWriter for convenience.
            try (PrintWriter out = new PrintWriter(
                    new BufferedWriter(new FileWriter(new File(outPath))))) {

                // File header.
                out.println("/*");
                out.println(" * Ghidra headless decompilation");
                out.println(" * Program : " + currentProgram.getName());
                out.println(" * Image base: "
                        + currentProgram.getImageBase());
                out.println(" * Compiler : "
                        + currentProgram.getCompilerSpec()
                                .getCompilerSpecID());
                out.println(" * Language : "
                        + currentProgram.getLanguageID());
                out.println(" * AUTHORIZED / EDUCATIONAL USE ONLY.");
                out.println(" */");
                out.println();

                // Iterate every function (including external thunks=false).
                for (Function func : fm.getFunctions(true)) {
                    if (monitor.isCancelled()) {
                        break;
                    }
                    total++;

                    // Skip external functions (no body to decompile).
                    if (func.isExternal()) {
                        continue;
                    }

                    DecompileResults results =
                            decomp.decompileFunction(func,
                                    DECOMPILE_TIMEOUT, monitor);

                    if (results != null && results.decompileCompleted()
                            && results.getDecompiledFunction() != null) {
                        String cCode =
                                results.getDecompiledFunction().getC();
                        out.println("/* ---- " + func.getName()
                                + "  @ " + func.getEntryPoint() + " ---- */");
                        out.println(cCode);
                        out.println();
                        ok++;
                    } else {
                        String msg = (results != null)
                                ? results.getErrorMessage() : "null results";
                        out.println("/* ---- " + func.getName()
                                + "  @ " + func.getEntryPoint()
                                + "  (DECOMPILATION FAILED: " + msg + ") ---- */");
                        out.println();
                        failed++;
                    }
                }

                out.flush();
            }

            println("[DecompileToC] Done. Functions seen=" + total
                    + ", decompiled=" + ok + ", failed=" + failed);
            println("[DecompileToC] Output file: " + outPath);

        } finally {
            // Always release the decompiler process.
            decomp.dispose();
        }
    }

    /**
     * Determine the output .c path:
     *   1) first script argument, if provided;
     *   2) <binary path>.decompiled.c (next to the imported executable);
     *   3) <user.home>/<programName>.decompiled.c as a last resort.
     */
    private String resolveOutputPath() {
        String[] args = getScriptArgs();
        if (args != null && args.length > 0 && args[0] != null
                && !args[0].trim().isEmpty()) {
            return args[0].trim();
        }

        // Try next to the original executable.
        try {
            String exe = currentProgram.getExecutablePath();
            if (exe != null && !exe.trim().isEmpty()) {
                // Ghidra may prefix Windows paths with a leading '/'; tolerate it.
                File exeFile = new File(exe);
                return exeFile.getAbsolutePath() + ".decompiled.c";
            }
        } catch (Exception e) {
            // fall through to home-dir default
        }

        String home = System.getProperty("user.home", ".");
        return home + File.separator
                + currentProgram.getName() + ".decompiled.c";
    }
}
