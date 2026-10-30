# Data preparation

RanDS is the downstream dataset shared by the two [research directions](research-protocol.md).
Existing RanDS audit/conversion evidence is retained. Additional SOREL/Assemblage processing
belongs to the **paused self-pretraining direction**.

## RanDS and the checkpoint direction

RanDS EXE has already been converted and uploaded to S3. The
[dataset card](../datasets/rands.md) documents release counts and the metadata-header issue.
Execution notes in the research workspace retain conversion, duplicate and conflicting-label
findings, including 73 conflicting-label EXE groups.

The [checkpoint plan](lmlm-checkpoints.md) must establish input/tokenizer compatibility
and cohort/split policy before reuse. Existing scratch preparation choices do not
automatically define checkpoint evaluation. Do not repeat conversion merely because an
older guide starts with data preparation.

## Retained self-pretraining workflow — paused

- [SOREL run guide](sorel-conversion.md): existing setup, continuation, publication and resume commands.
- [SOREL protocol](sorel-protocol.md): approved conversion rules and unresolved unknown-ISA policy.
- [Assemblage card](../datasets/assemblage.md): retained source revision, archive and metadata requirements.
- [Self-pretraining plan](self-pretraining.md): external overlap checks, representation/project grouping,
  external-training-only BPE and proposed downstream comparisons.

If this direction resumes, audit Assemblage metadata before writing an adapter; retain
project/build/license provenance and explicit failures. Assemblage is background software,
not AV-certified benign ground truth. Audit external-to-RanDS overlap before fitting BPE,
and preserve complete EXE files, source records and extraction evidence.
