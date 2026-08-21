#!/bin/bash
set -e

cd "$(dirname "$0")/../.."
source .venv/bin/activate

python -m malweave.data.executable_sections \
  --inarchives data/ranDS/raw \
  --outfile data/ranDS/processed/executable_sections/exe_bounds.json \
  --num_workers 1
