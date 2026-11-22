# Assemblage RAW Acquisition — 2026-11-12

These measured execution notes are retained separately from the
[dataset source and preparation plan](../datasets/assemblage.md).
The acquisition does not freeze a VERA cohort or authorize model training.

## Source and Integrity

| Field | Recorded value |
| --- | --- |
| Provider | Hugging Face, `changliu8541/Assemblage_PE` |
| Pinned source revision | `19a8f947f5a04d03edea78e61790226b55f92ac2` |
| Original archive | `binaries.tar.xz` |
| Download | [Pinned archive URL](https://huggingface.co/datasets/changliu8541/Assemblage_PE/resolve/19a8f947f5a04d03edea78e61790226b55f92ac2/binaries.tar.xz) |
| Download dates | 2026-11-11–12 |
| Full audit date | 2026-11-12 |
| Archive size | 33,827,018,671 bytes (33.83 decimal GB) |
| Detected compression | Zstandard, not XZ; the provider suffix is misleading |
| Acquisition integrity | Whole-archive SHA-256 matched the provider LFS digest; the full stream audit also validated Zstandard frame integrity |
| Intended role | Benign-source candidates for PE research; not a frozen benchmark cohort |

The archive was retained locally and unchanged through RAW/EXE publication, then **deleted locally
at the researcher's explicit request on 2026-11-12**, reclaiming 33,827,018,671 bytes. It was not
uploaded as an archive. Selected unique original PE files remain on S3; successful EXEs remain
both locally and on S3. PDBs and the eight structurally rejected inputs were not uploaded.
No binary was executed. The separate `winpe.sqlite.tar.xz` metadata database and per-project
build/license mappings have not been acquired and verified by this audit. Each binary retains its
source-project license; private storage does not grant redistribution rights. The benign label is
provider/open-source-build provenance, not individually verified benign ground truth.

## Full-archive Structural Audit

The earlier 200-file prefix check was a feasibility sample, not a population estimate.
The full archive produced these counts:

| Outcome | Archive entries |
| --- | ---: |
| All regular files | 256,064 |
| PDB debug files, not uploaded as PE | 167,624 |
| PE files passing structural-header/range checks | 88,432 |
| Files with declared raw-section ranges extending beyond the file | 8 |
| Exact duplicate PE entries beyond the first copy | 1,847 |
| **Unique original PE files selected for upload** | **86,585** |

Selected unique PE payloads total **24,082,705,049 bytes (24.08 decimal GB)**. This is an
uncompressed, deduplicated PE-only total, not the compressed archive size including PDBs.
Full structural inventory runtime was approximately **287.68 seconds**, excluding the preceding
archive SHA-256 verification and subsequent uploads.

The bounded structural check validates PE signatures, optional-header/section-table bounds and
declared raw-section ranges. It does not certify LIEF EXE extraction, DiE-negative eligibility,
antivirus status or safety. The eight failures remain accounted for in the private inventory;
they are not asserted to be malicious. Every regular entry has a recorded outcome. Files over
the 512 MiB per-source safety limit would have an explicit outcome; none were reported here.

## Architecture and CLR Coverage

These original-byte counts precede DiE filtering, EXE deduplication and checkpoint-overlap checks:

| Machine | CLR directory present | PE entries | Unique original PE files |
| --- | --- | ---: | ---: |
| I386 (`0x14c`) | No | 31,934 | **31,277** |
| I386 (`0x14c`) | Yes | 810 | 670 |
| AMD64 (`0x8664`) | No | 55,316 | 54,277 |
| AMD64 (`0x8664`) | Yes | 372 | 361 |
| **Total** | | **88,432** | **86,585** |

CLR-directory presence is a managed-code indicator, not a complete native/managed classification.
**31,277 is the candidate upper bound for an I386/no-CLR selection**, not a final native-I386
EXE/DiE/overlap-eligible count. This source alone is not proven to provide 38,285 eligible
native-I386 benign samples. The target depends on VERA counts after the same eligibility policy.

## Timestamp Audit

COFF fields are retained as **`pe_coff_unverified`**, with first-seen missing. Of the 88,432
structurally accepted entries, 84,755 have COFF years 2023–2024 and 151 have years 2030–2105.
Overall years range from 1970 to 2105. These are entry counts, including duplicates.

Future-dated values rule out blindly treating the field as validated first-seen. Archive mtime,
download date, source commit date, build date and first-seen are not interchangeable.
Comparable trustworthy per-sample temporal metadata across VERA and Assemblage remains unverified.

## RAW Publication and Traceability

Publication completed on **2026-11-12**: **86,585 original PE objects / 24,082,705,049 bytes**,
each verified against its original-file SHA-256 and byte length. The final manifest, upload summary
and state snapshot were published after exact verified coverage.

```text
<private-assemblage-bucket>/
  raw/<sha256[:2]>/<source_sha256>
  main/samples.csv
  main/source.json
  details/audit-summary.json
  details/upload-summary.json
  details/state.sqlite
```

This follows RawMal-style storage, with no `releases/` layer. `raw/` contains complete original PE
bytes, not section-only EXE representations or a complete mirror of the provider archive.
No headers, debug directories, signatures, sections or padding were stripped from retained PEs.
PDBs and the eight structural failures were not uploaded as RAW PE. Identical payloads map to one
object; archive paths and duplicate provenance remain in the inventory. Active/Latent or experiment
branches do not cause extra binary copies.

The operator used eight workers, bounded temporary storage, durable per-source SQLite progress,
conditional non-overwriting writes, and server-validated full-object SHA-256/length checks before
removing only its temporary upload copies. Multipart ETag and user metadata alone were not accepted
as integrity checks. The original archive was subsequently removed as recorded above. Public access is blocked and default
encryption enabled; this is not a complete IAM audit. Historical percentages are not completion
evidence: use the final upload summary and verified per-source state.

Private evidence remains outside Git:

| Local artifact | Role |
| --- | --- |
| `data/external/assemblage/download-state.json` | Pinned source, expected archive digest, download chunks, acquisition verification |
| `work/assemblage-download/PROVENANCE.md` | Private acquisition/publication record and destination |
| `work/assemblage-download/upload/source.json` | Provider/revision, integrity, label evidence and handling policy |
| `work/assemblage-download/upload/audit-summary.json` | Full structural counts, exclusions, runtime and bytes |
| `work/assemblage-download/upload/additional-audit.json` | Unique architecture/CLR and COFF-year counts; its progress snapshot is not a completion certificate |
| `work/assemblage-download/upload/state.sqlite` | Original paths, digests, statuses, duplicate provenance and verified/failed uploads |
| `work/assemblage-download/upload/upload-summary.json` | Final verified publication coverage |
| `work/assemblage-download/upload.log` | Progress/failures and terminal completion |
| `work/assemblage-download/SUITABILITY-AUDIT.md` | Bounded audit followed by full-inventory corrections |

Bucket identifiers, individual sample hashes, inventories, credentials and payloads must not enter
public documentation or Git. The archive digest remains in private evidence. The source revision
above identifies a provider repository revision, not a sample.

## Unresolved Experiment Gates

- Extract EXE with the actual checkpoint-compatible LIEF contract and retain per-source evidence.
  The earlier prefix pilot succeeded for 78/78 sampled PE files, not necessarily the full corpus.
- Apply the actual architecture and fixed DiE policy; do not infer eligibility from filename.
- Deduplicate EXE, resolve label/status contradictions, and check file/EXE overlap with RanDS and
  earlier checkpoint ancestry. Original LMLM used Assemblage; a new dataset name does not establish
  independent test data.
- Acquire source/build/license mapping and control related builds across splits. Exact file
  deduplication alone does not prevent project leakage.
- Verify temporal metadata on both classes before freezing time-ordered splits; preserve missing
  status rather than substituting download/archive times.
- Freeze balancing and report final eligible counts per split; RAW availability does not establish
  sufficient benign samples for every temporal interval.

This is an authorized dataset-preparation extension, not a reproduction of the LMLM cohort or
proof of ransomware-specific semantics. Any VERA Active/Latent experiment needs its own checkpoint
provenance, unchanged-checkpoint baseline, training-size controls and approved evaluation policy.
