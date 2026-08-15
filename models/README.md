# Model Artifacts

`models/` is for local checkpoints, tokenizers, prediction files, and run summaries. Its contents are ignored because they can be large, restricted, or recreated. Use a distinct run directory containing the resolved configuration, dataset release identifier, Git commit, random seed, metrics, and checkpoint metadata. Store any artifact that needs access control outside the repository by setting `MALWEAVE_MODELS_DIR`.
