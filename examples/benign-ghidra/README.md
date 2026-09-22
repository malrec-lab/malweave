# Benign Ghidra E2E Fixture

This directory contains source code for a deterministic, synthetic PE fixture used only by the
Docker e2e worker test. It never contains a downloaded or executable third-party sample.

`create_fixture.py` writes three minimal x86 PE files with `NOP; RET` entry points, their private
RanDS-shaped metadata, and a matching local dataset config. Two rows are benign and one is labelled
`ransomware` solely because the RanDS loader requires both metadata files to contain a record; all
three inputs are synthetic, harmless bytes. `assert_e2e.py` verifies that EXE, DIS, and DEC
extraction all produced successful, non-empty representations.

Run the full isolated flow from the repository root:

```bash
docker compose -f docker-compose.e2e.yml up --build --abort-on-container-exit \
  --exit-code-from ghidra-e2e
```

The container first invokes `scripts/setup-ghidra-worker.sh`; it then creates the fixture under
`/tmp`, so no test representation or SQLite state enters the repository.
