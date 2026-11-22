/**
 * MalWeave opt-in unbounded counterpart of the RawByteClf Decompiler.
 * Original script attribution/license: README.md and LICENSE.RawByteClf.
 * Divergence: synchronous traversal and Ghidra's timeoutSecs=0 (no timeout).
 * Function errors remain explicit; they are never reclassified as successful C.
 */
import java.io.File;
import java.io.FileWriter;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

public class DecompilerUnlimited extends Lifter {
    private DecompInterface decompiler;

    private String getProgramName() {
        String name = currentProgram.getName();
        return name.contains(".") ? name.substring(0, name.lastIndexOf('.')) : name;
    }

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1 || !new File(args[0]).isDirectory()) {
            throw new IllegalArgumentException("An existing output directory is required");
        }
        decompiler = new DecompInterface();
        if (!decompiler.openProgram(getCurrentProgram())) {
            throw new IllegalStateException("Cannot initialize decompiler");
        }
        println("run: timeoutPolicy=unlimited");
        println("run: analysisTimeoutOccurred()=" + analysisTimeoutOccurred());
        try (FileWriter writer = new FileWriter(
                new File(args[0], getProgramName() + getFileExtension()))) {
            FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
            while (functions.hasNext()) {
                monitor.checkCancelled();
                writer.write(processFunction(functions.next()));
                writer.flush();
            }
        } finally {
            decompiler.dispose();
        }
        println("run: finished (success) <" + getProgramName() + ">");
    }

    @Override
    protected String getFileExtension() { return ".c"; }

    @Override
    protected String processFunction(Function function) throws Exception {
        DecompileResults result = decompiler.decompileFunction(function, 0, monitor);
        if (result.decompileCompleted() && result.getDecompiledFunction() != null) {
            return result.getDecompiledFunction().getC();
        }
        String reason = result.getErrorMessage();
        if (reason == null) { reason = "incomplete decompilation"; }
        reason = reason.replace("\n", "").replace("*/", "* /");
        println("decompileFunction: incomplete=" + reason);
        return function.getPrototypeString(FORMAL_SIGNATURE, INCLUDE_CALLING_CONVENTION)
            + "\n{\n\n/* WARNING: Decompilation incomplete: " + reason + " */\n}\n\n";
    }
}
