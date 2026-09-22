/**
 * Lift binaries to disassembly.
*/

import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Iterator;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.MemoryAccessException;

public class Disassembler extends Lifter {

    public int bitSize;
    public int bitMult;
    public String unknownAddressStr;

    @Override
    protected void run() throws Exception {

        this.bitSize = currentProgram.getLanguage().getDefaultSpace().getSize();
        this.bitMult = (int) (this.bitSize / 16);
        this.unknownAddressStr = "?".repeat(this.bitMult * 4);
        println("run: bitSize=" + String.valueOf(this.bitSize));
        println("run: bitMult=" + String.valueOf(this.bitMult));
        println("run: unknownAddressStr=" + String.valueOf(this.unknownAddressStr));
        super.run();
    }

    @Override
    protected String processFunction(Function func) throws Exception {
        return disassembleFunction(func);
    }

    @Override
    protected String getFileExtension() {
        return ".asm";
    }

    /**
     * Disassemble a function.
    */
    private String disassembleFunction(Function func) throws MemoryAccessException, IllegalArgumentException {

        Address funcAddr = func.getEntryPoint();
        InstructionIterator instructions = currentProgram.getListing().getInstructions(funcAddr, true);
        FunctionManager funcManager = currentProgram.getFunctionManager();

        String signature = func.getPrototypeString(FORMAL_SIGNATURE, INCLUDE_CALLING_CONVENTION);
        String disassembledCode = "\n" + signature + "\n";

        while (instructions.hasNext()) {
            Instruction inst = instructions.next();
            if (funcManager.getFunctionContaining(inst.getAddress()) != func) {
                break;
            }
            String sectionName = getSectionName(inst);
            String physAddr = getPhysicalAddress(inst);
            String virtAddr = getVirtualAddress(inst);
            String bytes = getBytes(inst);
            String instruction = getInstruction(inst);
            String line = formatInstruction(sectionName, physAddr, virtAddr, bytes, instruction);
            disassembledCode = disassembledCode + line;
        }

        return disassembledCode;
    }

    /**
     * Get the section name an instruction lies in.
    */
    private String getSectionName(Instruction inst) {
        return inst.getAddressString(true, true).split(":")[0];
    }

    /**
     * Get the physical address of an instruction.
    */
    private String getPhysicalAddress(Instruction inst) {
        Address virtAddr = inst.getAddress();
        long physAddr;
        try {
            physAddr = virtualAddressToPhysicalAddress(virtAddr);
        } catch (ArithmeticException e) {
            return this.unknownAddressStr;
        }

        if (physAddr > 4294967295L) {
            return this.unknownAddressStr;
        }
        return String.format("%08x", physAddr);
    }

    /**
     * Get the virtual address of an instruction.
    */
    private String getVirtualAddress(Instruction inst) {
        return inst.getAddressString(true, true).split(":")[1];
    }

    /**
     * Get the bytes of an instruction.
    */
    private String getBytes(Instruction inst) throws MemoryAccessException {
        byte[] bytes = inst.getBytes();
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x ", b & 0xff));
        }
        return sb.toString().trim();
    }

    /**
     * Get the instructions of an instruction.
    */
    private String getInstruction(Instruction inst) {
        return inst.toString();
    }

    /**
     * Format the components of an instruction into a single string.
    */
    private String formatInstruction(String sectionName, String physAddr, String virtAddr, String bytes, String instruction) throws IllegalArgumentException {

        // 8 characters for the section name.
        if (sectionName.length() > 8) {
            sectionName = sectionName.substring(0, 8);
        }
        // Maximum for `size`-bit address space.
        if (physAddr.length() > this.bitMult * 4) {
            println("formatInstruction: physAddr=" + physAddr);
            throw new IllegalArgumentException("StringTooLong");
        }
        // Maximum for `size`-bit address space.
        if (virtAddr.length() > this.bitMult * 4) {
            println("formatInstruction: virtAddr=" + virtAddr);
            throw new IllegalArgumentException("StringTooLong");
        }
        // 48 characters for up to 15 bytes per instruction.
        if (bytes.length() > 48) {
            println("formatInstruction: bytes=" + bytes);
            throw new IllegalArgumentException("StringTooLong");
        }

        String format = "%-8s\t%-"
                      + String.valueOf(this.bitMult * 4)
                      + "s\t%-"
                      + String.valueOf(this.bitMult * 4)
                      + "s\t%-48s\t%s\n";

        return String.format(format, sectionName,  physAddr, virtAddr, bytes, instruction);
    }

    /**
     * Convert a virtual address to a physical one.
    */
    private long virtualAddressToPhysicalAddress(Address addr) throws ArithmeticException {

        Memory memory = currentProgram.getMemory();
        MemoryBlock block = memory.getBlock(addr);

        String blockInfo = "("
                         + "isExecute=" + String.valueOf(block.isExecute()) + ","
                         + "isInitialized=" + String.valueOf(block.isInitialized()) + ","
                         + "isLoaded=" + String.valueOf(block.isLoaded()) + ","
                         + "isMapped=" + String.valueOf(block.isMapped()) + ","
                         + "isVolatile=" + String.valueOf(block.isVolatile()) + ","
                         + ")";

        if (block.getSourceInfos().isEmpty()) {
            println("virtualAddressToPhysicalAddress: blockInfo=" + blockInfo);
            throw new ArithmeticException("No source information available.");
        }

        BigInteger addrOffset = addr.getOffsetAsBigInteger();
        BigInteger blockStart = block.getStart().getOffsetAsBigInteger();
        if (addrOffset.compareTo(blockStart) < 0) {
            println("virtualAddressToPhysicalAddress: blockInfo=" + blockInfo);
            println("virtualAddressToPhysicalAddress: addrOffset=" + addrOffset.toString());
            println("virtualAddressToPhysicalAddress: blockStart=" + blockStart.toString());
            throw new ArithmeticException("The address's offset should be larger than the start of its block.");
        }

        long sectionOffset = addrOffset.subtract(blockStart).longValueExact();
        long blockOffset = block.getSourceInfos().get(0).getFileBytesOffset();
        long physAddr = blockOffset + sectionOffset;
        if (sectionOffset < 0 || blockOffset < 0 || physAddr < 0) {
            println("virtualAddressToPhysicalAddress: blockInfo=" + blockInfo);
            println("virtualAddressToPhysicalAddress: addrOffset=" + addrOffset.toString());
            println("virtualAddressToPhysicalAddress: blockStart=" + blockStart.toString());
            println("virtualAddressToPhysicalAddress: sectionOffset=" + String.valueOf(sectionOffset));
            println("virtualAddressToPhysicalAddress: blockOffset=" + String.valueOf(blockOffset));
            println("virtualAddressToPhysicalAddress: physAddr=" + String.valueOf(physAddr));
            throw new ArithmeticException("physAddr cannot be less than zero.");
        }
        return physAddr;
    }
}
