FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
WORKDIR /workspace

COPY . .

RUN chmod +x scripts/setup-ghidra-worker.sh \
    scripts/run-ghidra-section.sh \
    scripts/merge-ghidra-sections.sh \
    docker/e2e/run.sh

CMD ["bash", "docker/e2e/run.sh"]
