# Notebooks

Notebooks support exploration, review, and figures. Name them `<order>-<initials>-<topic>.ipynb` so their intended reading order is clear. Run them from the uv-locked project environment, keep inputs and outputs parameterized, avoid embedding credentials or sample contents, and promote reusable logic into the `malweave` package with tests.

## Model Checks

`01-mw-e2-kaggle-smoke.ipynb` is the synthetic-only E2 capacity/resume notebook.
It calls the shared MalWeave CLI from a uv-locked environment, has no outputs or
credentials, and does not acquire RanDS. Follow the maintained
[E2 guide](../docs/mkdocs/docs/workflows/lmlm-checkpoints.md#e2-on-kaggle-synthetic-capacity-and-recovery)
for its feasibility settings, restoration steps and limits.

`02-mw-a-kaggle-probe.ipynb` measures the intact released detector in FP32 with
native Mamba kernels on one Kaggle GPU. It verifies a private source/checkpoint
bundle, uses synthetic bytes and a maximum-length token capacity case, and exports
logs/memory/timing reports. It has no stored outputs, credentials or RanDS samples.
It does not train or run the full RanDS test. Follow the maintained
[A guide](../docs/mkdocs/docs/workflows/lmlm-checkpoints.md#a-on-kaggle-intact-detector-and-test-only-evaluation)
for bundle parameters, the separate test evaluator and recovery requirements.

## Full Dataset Audits

| Audit | Notebooks |
| --- | --- |
| Native/.NET | [VERA](04-mw-vera-audit-full.ipynb), [RanDS](05-mw-rands-audit.ipynb), [Assemblage](06-mw-assemblage-audit.ipynb), [RawMal-TF](07-mw-rawmal-audit.ipynb) |
| DiE 3.21 packing | [VERA](08-mw-vera-die.ipynb), [RawMal-TF](09-mw-rawmal-die.ipynb) |

Run on CPU in a private Kaggle notebook with Internet enabled. Bundle the
same committed source revision used locally with the repository at `repo/`.

```bash
git archive --format=tar.gz --prefix=repo/ -o /tmp/malweave-audit-source.tar.gz HEAD
aws s3 cp /tmp/malweave-audit-source.tar.gz "$PRIVATE_BUNDLE_URI" --profile malweave-worker
```

The notebook's dataset-specific `MALWEAVE_*_INPUTS` secret holds a JSON receipt
for that bundle. Fill `bucket` and `key` from `PRIVATE_BUNDLE_URI`. Fill `bytes`
from `wc -c < /tmp/malweave-audit-source.tar.gz` and `sha256` from
`shasum -a 256 /tmp/malweave-audit-source.tar.gz`. The templates name the
specific secret they read.

In **Add-ons → Secrets** of each new notebook, attach the bundle receipt,
`MALWEAVE_S3_ACCOUNT_ID`, `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`.
Also attach `AWS_SESSION_TOKEN` for temporary credentials. The runner fetches
the inventory and publication receipt from the
[common S3 layout](../docs/mkdocs/docs/datasets/s3-layout.md) and fetches task
labels for RawMal-TF packing.

Use **Save Version → Save & Run All**. The runner requests a controlled stop after
10 hours by default and writes `state.sqlite3`, `summary.json` and `console.log`
under the notebook's configured directory in `/kaggle/working/` after the CLI
returns. DiE jobs also copy available release and tool metadata.

To resume, attach the saved output and set `RESUME_DB` to its `state.sqlite3` path.
Use a checkpoint created with the same published inventory, source selection and
audit settings. Reuse the same bundled source revision. Check `summary.json` for
`pending` and `process_exit_code`. An interrupted job can have a usable SQLite
checkpoint. A hard stop before the backup can leave the new version without one.
The final `native-dotnet.csv` or `packing.csv` is written when `pending` reaches zero.

Use the [job publication command](../docs/mkdocs/docs/workflows/data-preparation.md#save-a-completed-audit-on-s3)
with the downloaded SQLite output to store completed evidence in the dataset bucket.
