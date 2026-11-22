/**
 * MalWeave opt-in unbounded driver for the unchanged RawByteClf Disassembler.
 * Original script attribution/license: README.md and LICENSE.RawByteClf.
 * Divergence: no file/function deadline, synchronous traversal and per-function flush.
 */
import java.io.File;
import java.io.FileWriter;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

public class DisassemblerUnlimited extends Disassembler {
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
        this.bitSize = currentProgram.getLanguage().getDefaultSpace().getSize();
        this.bitMult = this.bitSize / 16;
        this.unknownAddressStr = "?".repeat(this.bitMult * 4);
        this.timeoutPerFile = -1;
        this.timeoutPerFunc = 0;
        println("run: timeoutPolicy=unlimited");
        println("run: analysisTimeoutOccurred()=" + analysisTimeoutOccurred());
        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
        try (FileWriter writer = new FileWriter(
                new File(args[0], getProgramName() + getFileExtension()))) {
            while (functions.hasNext()) {
                monitor.checkCancelled();
                writer.write(processFunction(functions.next()));
                writer.flush();
            }
        }
        println("run: finished (success) <" + getProgramName() + ">");
    }
}
