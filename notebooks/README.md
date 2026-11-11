# Notebooks

Notebooks support exploration, review, and figures. Name them `<order>-<initials>-<topic>.ipynb` so their intended reading order is clear. Run them from the uv-locked project environment, keep inputs and outputs parameterized, avoid embedding credentials or sample contents, and promote reusable logic into the `malweave` package with tests.


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
