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
        with:
          fetch-depth: 0
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - run: pip install -e .
      - run: ceres scan . --diff-base origin/${{ github.base_ref || 'main' }} --sarif-out ceres.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: ceres.sarif
```

`--diff-base` is recommended for pull requests because it keeps existing
repository debt out of the review and gates only findings introduced by the
branch. For scheduled or release scans, run `ceres scan .` without diff mode to
review the whole repository.

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

## Real-World Validation

This repository also includes `.github/workflows/real-world-validation.yml`.
It runs nightly and through `workflow_dispatch`, installs Ceres, runs the
real-world harness unit tests, scans the public corpus in
`examples/real-world-corpus.yml`, and uploads `report.json` as a workflow
artifact.
