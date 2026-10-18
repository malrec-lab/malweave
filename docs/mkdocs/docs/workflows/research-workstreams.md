# Research Workstreams

Data preparation, model components and experiment design proceed independently and meet at a
configured run. Follow the [research protocol](research-protocol.md) for the study design.

## Progress — 2026-10-18

| Area | Current status | Next deliverable |
| --- | --- | --- |
| RanDS data | **Converted to EXE and uploaded to S3.** 215,404 sources accounted for; 215,040 successes, 364 failures. | Full-corpus EXE experiment view, duplicate/conflicting-label policy and frozen split. |
| SOREL + Assemblage | Dataset cards and shared PE extractor available. | Source adapters, snapshot inventories, extraction pilots and coverage reports. |
| Data interfaces | Product validation, exact grouping and RAW/EXE comparison code available. | EXE-only manifest/storage input and cross-source overlap/project grouping. |
| Tokenization + backbones | Byte/BPE utilities, Mamba/HRRFormer classifiers and supervised runner available. | Target-runtime feasibility and integration with common experiment inputs. |
| MLM + transfer | To implement. | MLM head, masked loss, checkpoint transfer and synthetic end-to-end smoke test. |
| Base experiment | Planned. | Scratch vs pretrained at 10%, 25%, 100% training labels, then main runs across seeds. |
| Span masking | Planned after base. | Controlled comparison against random-token MLM. |

## Work Order

1. **Prepare both pretraining sources:** SOREL uses `meta.db` and selected S3 objects; Assemblage
   Windows PE uses the published SQLite and binary archives. Implement both readers, test roughly
   100 sources each, choose scope from measured resources and convert through the shared extractor.
   Follow the [data workflow](data-preparation.md).
2. **Develop components alongside data preparation:** complete MLM, transfer and the synthetic
   smoke path described in [model components](model-components.md).
3. **Prepare experiment inputs:** expose EXE storage/manifest access, audit overlap and grouping,
   resolve RanDS conflicting labels and freeze cohorts/splits/tokenizer fit scope.
4. **Run the compute pilot:** measure token lengths, truncation, VRAM, throughput and learning
   behavior; select model/context and pretraining budget.
5. **Run the base comparison:** same architecture, tokenizer and label subsets across initialization
   conditions; fixed validation/test and checkpoint-selection rules.
6. **Evaluate span masking:** keep corpus, backbone, mask rate and compute comparable.

## Responsibilities And Outputs

- Data work produces EXE bytes, manifests, annotations, durable state and quality reports.
- Components supply tokenization, backbone, objective, metrics and checkpoint handling, tested with
  synthetic inputs.
- Experiment configs select cohorts, groups, splits, label subsets, training and evaluation policy.

Every run retains resolved config, manifest/split/tokenizer digests, source/lock revisions, seeds,
environment, checkpoint, predictions and metrics in a private run directory. Report completed
preparation, pilot measurements and research results distinctly.
