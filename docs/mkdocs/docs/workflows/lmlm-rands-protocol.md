# RanDS Research Protocol

MalWeave adapts LMLM methods to the RanDS ransomware corpus. It does not reproduce the paper's
dataset or claim its reported scores. The binary task is ransomware versus benign, not general
malware detection.

## Stable Data Decisions

| Topic | Decision |
| --- | --- |
| Corpus | The complete available RanDS `2026-09-02` release after its audit contract passes. |
| Source identity | Canonical SHA-256 and snapshot. Every representation records both. |
| RAW | Verified reference to original source bytes; never copied into a second corpus. |
| EXE | Concatenate executable-or-code PE raw ranges in section-table order, clipping invalid ranges and recording warnings. |
| EXE parser | LIEF `0.15.1`, following RawByteClf's default static extraction behavior. |
| Representation identity | SHA-256 of derived bytes. Exact equal representations form one leakage group. |
| Failures | Missing, changed, malformed, and non-extractable sources remain explicit rows; no replacement or silent filtering. |

The metadata-derived `I386` and `Packed=0` view remains available as a named audit protocol. It is
not a data-preparation gate and is not silently substituted for the full corpus.

## Decisions Belonging To An Experiment

An experiment config, created only when there is a concrete research question, declares its
product manifest, active representation, architecture, tokenizer, loss, optimizer, schedule,
epochs, seed, metrics, and evaluation policy. For a comparison it freezes a group-safe split before
fitting a tokenizer or any other learned transform. The run artifact then preserves the resolved
config and all input digests.

DIS and DEC are separate full-corpus representation workstreams. Their parser versions, failure
contract, output format, and tool isolation must be defined before they are added to an experiment.
