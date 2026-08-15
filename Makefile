PYTHON ?= python

.PHONY: help test lint format docs

help:
	@printf '%s\n' \
	  'make test   - run the dependency-free unit tests' \
	  'make lint   - lint source and tests (requires the dev extra)' \
	  'make format - format source and tests (requires the dev extra)' \
	  'make docs   - build MkDocs documentation (requires the docs extra)'

test:
	$(PYTHON) -m unittest discover -s tests -v

lint:
	$(PYTHON) -m ruff check malweave tests

format:
	$(PYTHON) -m ruff check --fix malweave tests
	$(PYTHON) -m ruff format malweave tests

docs:
	$(PYTHON) -m mkdocs build --strict --config-file docs/mkdocs/mkdocs.yml
