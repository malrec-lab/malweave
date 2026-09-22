# MalWeave

MalWeave is an independent research codebase for reproducing and extending malware language
modeling methods. It adapts the Large Malware Language Model (LMLM) data and model ideas to the
RanDS ransomware corpus; it is not the paper's official implementation.

Raw PE files may be live malware. The repository only performs static reads and analysis. Never
execute, preview, upload, commit, or redistribute raw samples. Keep raw data, private manifests,
representations, checkpoints, and reports outside Git.

## Start Here

From the repository root:

```bash
uv sync --locked
make check
make docs-serve
```

`make docs-serve` starts the documentation site with live reload at
`http://127.0.0.1:8000`. Stop it with `Ctrl-C`. To build the site without serving it, use
`make docs`.

If `uv` or a system tool is missing, follow [Getting started](docs/mkdocs/docs/getting-started.md)
and [Environment and dependencies](docs/mkdocs/docs/development/environment.md). `uv sync` does
not install Java, Ghidra, `diec`, raw datasets, GPU drivers, or other system tools.

## Documentation Map

| Need | Read |
| --- | --- |
| Install the Python environment and external tools | [Getting started](docs/mkdocs/docs/getting-started.md), [Environment guide](docs/mkdocs/docs/development/environment.md) |
| Understand what the project is doing | [Research workstreams](docs/mkdocs/docs/workflows/research-workstreams.md) |
| Understand the paper protocol and intentional divergences | [RanDS protocol](docs/mkdocs/docs/workflows/lmlm-rands-protocol.md) |
| Audit RanDS and prepare RAW/EXE/DIS/DEC | [RanDS workflow](docs/mkdocs/docs/workflows/lmlm-rands.md) |
| Understand RanDS labels, layout, and safety constraints | [RanDS dataset card](docs/mkdocs/docs/datasets/rands.md) |
| Add or modify code safely | [Onboarding a research task](docs/mkdocs/docs/onboarding.md), [Project structure](docs/mkdocs/docs/project-structure.md), [AGENTS.md](AGENTS.md) |
| Read the source paper and upstream reference | [Paper](references/papers/lmlm/2026-s103-paper.md), `RawByteClf/` if checked out beside this repository |

## Repository Architecture

```text
malweave/
├── malweave/
│   ├── cli.py                 # `malweave data ...` and `malweave experiment ...`
│   ├── data/                  # audits, PE extraction, Ghidra jobs, products
│   ├── models/                # MalConvGCT, HRRFormer, Mamba ports
│   ├── training/              # supervised runner and artifact writing
│   └── experiments/           # cohort, duplicate-group, and split logic
├── configs/                   # committed dataset and experiment contracts
├── ghidra_scripts/            # attributed RawByteClf-compatible Java scripts
├── tests/                     # synthetic fixtures only; never real malware
├── references/papers/         # local paper text and research references
├── docs/mkdocs/docs/          # team documentation
├── data/                      # ignored local data and representations
├── reports/                   # ignored aggregate reports
├── models/                    # ignored checkpoints
├── pyproject.toml             # Python requirements and tool configuration
├── uv.lock                    # exact Python dependency resolution
└── Makefile                   # stable developer commands
```

The main data flow is:

```text
RanDS raw + metadata
        ↓
release audit
        ↓
RAW reference + LIEF EXE extraction
        ↓
metadata-I386 Ghidra DIS/DEC extraction
        ↓
duplicate groups and private manifests
        ↓
experiment split → tokenizer/model training → checkpoints and metrics
```

The current Ghidra path uses RanDS metadata `Arch=I386` and retains both `Packed=0` and `Packed=1`
for comparison. The optional DiE assessment remains available for corpora without trustworthy
architecture/packing metadata; it is not required for the current RanDS Ghidra run.

## Technology Stack

| Layer | Technology | Role |
| --- | --- | --- |
| Runtime | CPython 3.12.12, `uv` 0.11.9 | Reproducible Python environment |
| PE parsing | LIEF 0.15.1 | Static executable-section extraction |
| Models | PyTorch, Transformers, Tokenizers | Model components and tokenization |
| Ghidra views | Ghidra headless + supported JDK | Static DIS/DEC extraction; installed outside the repo |
| Optional PE assessment | Linux/macOS `file`, Detect-It-Easy `diec` | Architecture/packing validation for other corpora |
| Documentation | MkDocs | Local web documentation and strict build |
| Quality | pytest, Ruff, `make check` | Tests, lint, formatting, and docs validation |

## Quick Commands

```bash
# Environment and quality
uv sync --locked
make check
make test
make docs              # strict static docs build
make docs-serve        # local docs web server with live reload
make e2e-ghidra        # clean Linux bootstrap + synthetic benign PE EXE/DIS/DEC flow

# Inspect the RanDS release
uv run --locked malweave data inspect --dataset rands

# Extract the full LIEF EXE representation
uv run --locked malweave data extract-exe \
  --dataset rands \
  --representation-dir data/processed/rands/exe \
  --state-db data/processed/rands/exe/extraction.sqlite \
  --manifest data/processed/rands/exe/manifest.csv \
  --summary reports/rands/exe-extraction.json

# Resume an interrupted EXE job
uv run --locked malweave data extract-exe \
  --dataset rands \
  --representation-dir data/processed/rands/exe \
  --state-db data/processed/rands/exe/extraction.sqlite \
  --manifest data/processed/rands/exe/manifest.csv \
  --summary reports/rands/exe-extraction.json \
  --resume
```

For Ghidra, set `GHIDRA_ROOT` to an external Ghidra installation and start with a ten-file pilot:

```bash
# macOS: find a locally extracted or app-bundled Ghidra launcher, then derive its root.
GHIDRA_LAUNCHER="$(find /Applications "$HOME/ghidra" "$HOME/Downloads" \
  -type f -path '*/support/analyzeHeadless' -perm -111 -print -quit 2>/dev/null)"
test -n "$GHIDRA_LAUNCHER" || { echo "Ghidra analyzeHeadless was not found" >&2; exit 1; }
export GHIDRA_ROOT="${GHIDRA_LAUNCHER%/support/analyzeHeadless}"

java -version
echo "$GHIDRA_ROOT"
test -x "$GHIDRA_ROOT/support/analyzeHeadless"
"$GHIDRA_ROOT/support/analyzeHeadless" -help

uv run --locked malweave data extract-ghidra \
  --dataset rands \
  --representations dis dec \
  --analyze-headless "$GHIDRA_ROOT/support/analyzeHeadless" \
  --dis-representation-dir data/processed/rands/dis \
  --dec-representation-dir data/processed/rands/dec \
  --state-db data/processed/rands/ghidra/extraction.sqlite \
  --work-dir data/processed/rands/ghidra-work \
  --dis-manifest data/processed/rands/ghidra/dis-manifest.csv \
  --dec-manifest data/processed/rands/ghidra/dec-manifest.csv \
  --summary reports/rands/ghidra-extraction.json \
  --workers 1 \
  --limit 10
```

Remove `--limit 10` and add `--resume` to continue that exact unified job. It retains a completed
view if the sibling view is pending or failed. Full timeout and resume details are in the [RanDS
workflow](docs/mkdocs/docs/workflows/lmlm-rands.md).

## Fast Setup By Platform

### macOS

```bash
# Python environment
brew install uv
uv sync --locked

# Ghidra's JDK (use the version required by the Ghidra release you downloaded)
brew install openjdk@21
sudo ln -sfn "$(brew --prefix openjdk@21)/libexec/openjdk.jdk" \
  /Library/Java/JavaVirtualMachines/openjdk-21.jdk
export JAVA_HOME=$(/usr/libexec/java_home -v 21)
java -version
```

Download/extract Ghidra outside the repository, then verify
`$GHIDRA_ROOT/support/analyzeHeadless -h`. If the release was installed as an application, locate
the launcher with `find /Applications -type f -name analyzeHeadless 2>/dev/null`. `brew install --cask ghidra` may be used when the
Homebrew cask is available, but the selected release and launcher path must still be recorded.
`diec` is not needed for the current metadata-selected RanDS Ghidra workflow.

### Linux (Ubuntu/Debian example)

```bash
sudo apt-get update
sudo apt-get install -y openjdk-21-jdk unzip
curl -LsSf https://astral.sh/uv/0.11.9/install.sh | sh
uv sync --locked
java -version
```

Download and extract the Ghidra release outside the repository, then verify
`$GHIDRA_ROOT/support/analyzeHeadless -h`. Keep raw data on an isolated local disk or mounted
volume. Install `file` from the distribution package only when using the optional PE assessment.
Install `diec` separately from its official Detect-It-Easy release if that assessment is required;
the current RanDS path does not need it.

## Safety And Reproducibility

Every full-corpus job keeps durable per-source state, verifies source SHA-256 before static parsing,
records failures, and writes private manifests. Use `--resume` only with the same state database and
extraction contract. Do not copy raw samples into tests; tests use synthetic PE fixtures. Read
`AGENTS.md` before making data or model changes.
