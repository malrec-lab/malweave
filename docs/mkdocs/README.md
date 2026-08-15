# Documentation Site

This is the MkDocs source for project guidance, research-process decisions, and dataset cards. Build it after installing the `docs` optional dependency:

```bash
python -m pip install -e ".[docs]"
python -m mkdocs serve --config-file docs/mkdocs/mkdocs.yml
```

Use `make docs` in CI or before publishing to build the site strictly. Keep the source Markdown under `docs/mkdocs/docs/`; generated output is ignored.
