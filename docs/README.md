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
- `EXTENDING.md` — how to add a new secret type / service template
- `FAQ.md` — frequently asked questions
- `SDK-REFERENCE.md` — all 3 official SDKs (Python, Go, VSCode)
- `SSH-PROXY.md` / `WEBSOCKET.md` / `WORKLOAD-IDENTITY.md` — feature docs
- `THREAT-MODEL.md` — security model
- `../sdk/*/README.md` — SDK docs (auto-included via nav)
