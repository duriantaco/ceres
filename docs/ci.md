# CI And GitHub Pages

## CI Scan

```yaml
name: Ceres
on: [pull_request, push]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - run: pip install -e .
      - run: ceres scan . --sarif-out ceres.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: ceres.sarif
```

## GitHub Pages Docs

This repository includes a Pages workflow at `.github/workflows/docs.yml`.

It builds with:

```bash
python -m mkdocs build --strict --site-dir site
```

Deployment uses GitHub’s first-party Pages actions:

- `actions/upload-pages-artifact`
- `actions/deploy-pages`

In repository settings, set Pages source to **GitHub Actions**. Pushes to
`main` will build and deploy the docs site.

## Local Docs Preview

```bash
python -m pip install mkdocs mkdocs-material
python -m mkdocs serve
```

The generated site uses MkDocs Material, but the Ceres docs have their own nav,
logo, structured data, and teal/green palette.
