# Ghidra lifting scripts

> DIS/DEC extraction tooling. The researcher approved a separate RanDS extraction pool;
> see the maintained [data workflow](../docs/mkdocs/docs/workflows/data-preparation.md).

`Lifter.java`, `Disassembler.java`, `Decompiler.java`, and
`SetAnalysisOptionsForDisassembly.java` are verbatim ports of the Ghidra scripts from
RawByteClf commit `2502450e40ac00363e168106662aac29821d4a93`, the accompanying code release
for *Beyond Raw Bytes: Towards Large Malware Language Models*. They remain under the upstream MIT
license reproduced in `LICENSE.RawByteClf`.

MalWeave's Python runner is separate: it selects the documented RanDS metadata cohort, supplies
per-source isolation and durable state, and applies the upstream `dis_func` and `dec_func`
normalizers after the scripts finish. Do not edit a script in place during a job: its content digest
is part of the resumable extraction contract.

`DisassemblerUnlimited.java` and `DecompilerUnlimited.java` are separate opt-in
MalWeave drivers for the researcher-requested no-deadline benchmark. They leave
the upstream scripts unchanged. The DIS driver reuses upstream function rendering;
the DEC driver retains upstream formatting/constants but uses Ghidra's documented
`timeoutSecs=0` and reports incomplete functions explicitly. They do not use the
upstream whole-file timed Future. The Python adapter also omits the analysis
deadline and does not kill a parser merely because elapsed time is large.
This is an intentional timeout-protocol extension, not the unchanged paper
protocol. Synthetic DIS/DEC parity must pass before deployment. Platform shutdown,
memory exhaustion and actual parser errors remain possible.

The discarded local implementation included a MalWeave-authored `LiftCheckpointed.java`, chaining
the unchanged DIS/DEC scripts after one analysis, as in upstream `run/liftMini.sh`, with independent
completion markers and without DIS-only analysis options. It is **not present in this branch**;
the retained [operator notes](../docs/mkdocs/docs/workflows/ghidra-s3-rolling.md) are historical,
not a runnable installation or extraction contract.
