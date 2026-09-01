# Building the documentation site

This directory contains the source for the
[Material for MkDocs](https://squidfunk.github.io/mkdocs-material/) site.

## Preview locally

```bash
pip install -r requirements.txt
mkdocs serve
# → http://127.0.0.1:8000
```

## Build static site

```bash
mkdocs build
# → site/  (deploy to GitHub Pages, Netlify, S3, etc.)
```

## Deploy to GitHub Pages

```bash
mkdocs gh-deploy
```

## Structure

- `mkdocs.yml` — site config
- `index.md` — landing page
- `QUICKSTART.md` — 5-minute walkthrough
- `DESIGN-V4-*.md` — architecture documents
- `../sdk/*/README.md` — SDK docs (auto-included via nav)
- `../deploy/helm/broker/README.md` — Helm docs
- `../deploy/grafana/README.md` — Grafana docs
