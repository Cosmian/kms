## TL;DR

The main documentation for the KMS is in [docs/index.md](./docs/index.md)

The documentation is deployed automatically on `docs.cosmian.com` when you add a new tag on this repo. However you need to adapt manually [the public documentation nav bar](http://gitlab.cosmian.com/core/public_documentation/-/blob/master/mkdocs.yml) to make it visible.

## TODO

- add examples using Rust in the doc
- better document the KMIP lib

## Installing Rendering Tools

You **do not need these tools** to author the doc and should probably **not** install LaTeX.
Vs-code has all the necessary support for it.

However, if you want to see how it looks like fully rendered, you must install `mkdocs`

### Installing mkdocs

```sh
# MKdocs
sudo apt-get install fonts-noto-mono fonts-noto pandoc-citeproc librsvg2-bin
pip install pydoc-markdown git+https://github.com/twardoch/mkdocs-combine.git mkdocs-kroki-plugin mkdocs-material pandoc-latex-admonition install markdown-katex git+https://gitlab.com/myriacore/pandoc-kroki-filter.git
```

### Using mkdocs

From the root of the project, run

```bash
cd documentation/
mkdocs serve
```

Open a browser window at <http://127.0.0.1:8003>

The doc is live rendered when editing the markdown files.

### Installing Pandoc to generated PDFS

```sh
# Pandoc (for pdfs)
wget https://github.com/jgm/pandoc/releases/download/2.17.1.1/pandoc-2.17.1.1-1-amd64.deb
sudo dpkg -i pandoc-2.17.1.1-1-amd64.deb

# pandoc-latex - if you want to render Latex content in PDF (requires Latex)
cargo install pandoc-katex
```

### Generating a PDF

Run

```sh
./build_pdf.sh
```

Warning: you need a LaTeX install , if some content is written in LaTeX

### Installing Latex

WARNING: this is a BIG install

```sh
# LateX
sudo apt-get install texlive-full
```
