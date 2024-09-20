## TL;DR

The main documentation of the KMS is in [docs/index.md](./docs/index.md)

## Installing Rendering Tools

You **do not need these tools** to author the doc and should probably **not** install LaTeX.
Vs-code has all the necessary support for it.

However, if you want to see how it looks fully rendered, you must install `mkdocs`

### Installing mkdocs

#### Ubuntu pre-requisites

```sh
## Ubuntu 22.04
sudo apt-get install fonts-noto-mono fonts-noto pandoc-citeproc librsvg2-bin

## Ubuntu 23.10
sudo apt-get install fonts-noto-mono fonts-noto pandoc librsvg2-bin
```

#### MacOS pre requisites

```sh
brew install pandoc librsvg
brew install --cask homebrew/cask-fonts/font-noto-mono
```

#### mkdocs

```sh
cd documentation
python3 -m venv venv

source venv/bin/activate

pip3 install pydoc-markdown git+https://github.com/twardoch/mkdocs-combine.git \
mkdocs-kroki-plugin mkdocs-meta-descriptions-plugin mkdocs-material mkdocs-mermaid2-plugin \
pandoc-latex-admonition markdown-katex git+https://gitlab.com/myriacore/pandoc-kroki-filter.git
```

### Using mkdocs

From the root of the project, run

```bash
cd documentation/

# Run the server on all interfaces
source venv/bin/activate
mkdocs serve -a 0.0.0.0:8003
```

Open a browser window at `http://[MACHINE_IP / LOCALHOST]:8003`

The doc is live rendered when editing the Markdown files.

### Installing Pandoc to generate PDFs

```sh
# Pandoc (for pdfs)
wget https://github.com/jgm/pandoc/releases/download/2.17.1.1/pandoc-2.17.1.1-1-amd64.deb
sudo dpkg -i pandoc-2.17.1.1-1-amd64.deb

# pandoc-latex - if you want to render Latex content in PDF (requires Latex)
cargo install pandoc-katex
```

### Generating a PDF

Run
Warning: You need a LaTeX installation if some content is written in LaTeX

### Installing Latex

WARNING: This is a BIG installation

```sh
# LateX
sudo apt-get install texlive-full
```
