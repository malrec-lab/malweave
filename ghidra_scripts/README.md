# Ghidra lifting scripts

`Lifter.java`, `Disassembler.java`, `Decompiler.java`, and
`SetAnalysisOptionsForDisassembly.java` are verbatim ports of the Ghidra scripts from
RawByteClf commit `2502450e40ac00363e168106662aac29821d4a93`, the accompanying code release
for *Beyond Raw Bytes: Towards Large Malware Language Models*. They remain under the upstream MIT
license reproduced in `LICENSE.RawByteClf`.

MalWeave's Python runner is separate: it selects the documented RanDS metadata cohort, supplies
per-source isolation and durable state, and applies the upstream `dis_func` and `dec_func`
normalizers after the scripts finish. Do not edit a script in place during a job: its content digest
is part of the resumable extraction contract.
