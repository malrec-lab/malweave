# MalWeave Research Documentation

The study evaluates **external PE/EXE pretraining and label-efficient RanDS fine-tuning**.
Pretraining uses SOREL malware and Assemblage Windows PE background software. Downstream evaluation
starts with ransomware-versus-benign detection using a small bidirectional Mamba.

The data pipeline is **PE → executable/code sections (EXE) → byte mapping → BPE**. Compare
random-token MLM pretraining against random model initialization at 10%, 25% and 100% training-label
budgets, then evaluate span masking as a separate extension.

**Current data progress:** RanDS has been converted to EXE and uploaded to S3. Extraction produced
215,040 successful representations from 215,404 sources, with 364 recorded failures. SOREL/Assemblage
preparation and MLM integration are the next implementation tasks.

Read in this order:

1. [Research protocol](workflows/research-protocol.md): scope, comparisons and evaluation.
2. [Data preparation](workflows/data-preparation.md): sources, representations and quality checks.
3. [Research workstreams](workflows/research-workstreams.md): progress and task order.
4. [Getting started](getting-started.md) and [model components](workflows/model-components.md).
5. [Dataset catalog](datasets/index.md) for schema, identity and access conditions.

Use [project structure](project-structure.md), [onboarding](onboarding.md) and the
[environment guide](development/environment.md) when implementing a task.
