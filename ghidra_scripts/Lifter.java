/**
 * Lift binaries to intermediate representation.
*/

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.TimeUnit;

import ghidra.app.util.headless.HeadlessScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

public abstract class Lifter extends HeadlessScript {

    protected static final boolean SKIP_EXTERNAL_FUNCTIONS = false;
    protected static final boolean FORMAL_SIGNATURE = false;
    protected static final boolean INCLUDE_CALLING_CONVENTION = true;
    protected static final boolean REQUIRE_HEADLESS_ANALYSIS_COMPLETE = false;

    protected String outputDir = "./";
    protected int timeoutPerFile = -1;
    protected int timeoutPerFunc = -1;
    protected String programName;

    /**
     * Entry point.
    */
    @Override
    protected void run() throws Exception {
        println("run: SKIP_EXTERNAL_FUNCTIONS=" + SKIP_EXTERNAL_FUNCTIONS);
        println("run: FORMAL_SIGNATURE=" + FORMAL_SIGNATURE);
        println("run: INCLUDE_CALLING_CONVENTION=" + INCLUDE_CALLING_CONVENTION);
        println("run: REQUIRE_HEADLESS_ANALYSIS_COMPLETE=" + REQUIRE_HEADLESS_ANALYSIS_COMPLETE);
        println("run: analysisTimeoutOccurred()=" + analysisTimeoutOccurred());

        if (REQUIRE_HEADLESS_ANALYSIS_COMPLETE && !analysisTimeoutOccurred()) {
            println("run: skipped.");
            return;
        }

        String[] scriptArgs = getAndValidateScriptArgs();
        this.outputDir = scriptArgs[0];
        this.timeoutPerFile = Integer.parseInt(scriptArgs[1]);
        this.timeoutPerFunc = Integer.parseInt(scriptArgs[2]);
        this.programName = getProgramName();
        String outputFileName = getOutputFileName(this.outputDir, this.programName);

        println("run: outputDir=" + this.outputDir);
        println("run: timeoutPerFile=" + String.valueOf(this.timeoutPerFile));
        println("run: timeoutPerFunc=" + String.valueOf(this.timeoutPerFunc));
        println("run: programName=" + this.programName);
        println("run: outputFileName=" + outputFileName);

        FunctionIterator functions = getFunctions();
        runMainWorker(functions, outputFileName);
    }

    /**
     * Process a single function and write the output to a file.
    */
    protected abstract String processFunction(Function func) throws Exception;

    /**
     * Get the output file's extension, e.g., ".EXTENSION"
    */
    protected abstract String getFileExtension();

    /**
     * Get the command line arguments passed to the instance.
    */
    private String[] getAndValidateScriptArgs() {
        String[] scriptArgs = getScriptArgs();
        if (scriptArgs == null || scriptArgs.length < 3) {
            println("getAndValidateScriptArgs: scriptArgs=" + String.join(", ", scriptArgs));
            throw new IllegalArgumentException("Error: outputDir, timeoutPerFile, timeoutPerFunc required.");
        }
        return scriptArgs;
    }

    /**
     * Get the name of this file, excluding the extension, i.e., the SHA-256.
    */
    private String getProgramName() {
        String programName = currentProgram.getName();
        if (programName.contains(".")) {
            programName = programName.substring(0, programName.lastIndexOf('.'));
        }
        return programName;
    }

    /**
     * Get the name of the output file for this file.
    */
    private String getOutputFileName(String outputDir, String programName) {
        File dir = new File(outputDir);
        if (!dir.exists()) {
            println("getOutputFileName: outputDir=" + String.valueOf(outputDir));
            throw new IllegalArgumentException("Error: output directory does not exist.");
        }
        String outputFileName = outputDir + File.separator + programName + getFileExtension();
        return outputFileName;
    }

    /**
     * Get an iterator of functions to process.
    */
    private FunctionIterator getFunctions() {
        if (SKIP_EXTERNAL_FUNCTIONS) {
            return currentProgram.getFunctionManager().getFunctions(true);
        } else {
            return currentProgram.getListing().getFunctions(true);
        }
    }

    /**
     * Wraps processFunctions in a timeout construct.
    */
    private void runMainWorker(FunctionIterator functions, String outputFileName) throws Exception {
        ExecutorService executor = Executors.newSingleThreadExecutor();
        Callable<Void> task = () -> {
            processFunctions(functions, outputFileName);
            return null;
        };
        Future<Void> future = executor.submit(task);
        try {
            future.get(this.timeoutPerFile, TimeUnit.SECONDS);
            println("run: finished (success) <" + this.programName + ">");
        } catch (TimeoutException e) {
            println("run: finished (timeout) <" + this.programName + ">");
            future.cancel(true);
        } catch (InterruptedException | ExecutionException e) {
            println("run: finished (crash) <" + this.programName + ">");
            e.printStackTrace();
        } finally {
            executor.shutdown();
        }
    }

    /**
     * Process every function and write the output of processing to a file.
    */
    private void processFunctions(FunctionIterator functions, String outputFileName) throws Exception {
String processedFunc;
        try (FileWriter writer = new FileWriter(outputFileName)) {
            for (Function func : functions) {
                processedFunc = processFunction(func);
        writer.write(processedFunc);
            }
        } catch (IOException e) {
            throw e;
        }
    }
}
