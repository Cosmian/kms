# TL;DR

The main documentation of the KMS is in [docs/index.md](./docs/index.md)

## Installing Rendering Tools

You do not need these tools to author the documentation and should probably not install LaTeX.
VS Code has all the necessary support for it.

However, if you want to see how it looks fully rendered, you must install `mkdocs`

### Installing mkdocs

#### Ubuntu pre-requisites

```sh
## Ubuntu 22.04
sudo apt-get install fonts-noto-mono fonts-noto pandoc-citeproc librsvg2-bin

## Ubuntu 23.10
sudo apt-get install fonts-noto-mono fonts-noto pandoc librsvg2-bin
```

#### MacOS pre-requisites

```sh
brew install pandoc librsvg
brew install font-noto-mono
```

#### mkdocs

```sh
cd documentation
python3 -m venv .venv

source .venv/bin/activate

pip3 install pydoc-markdown git+https://github.com/twardoch/mkdocs-combine.git \
mkdocs-kroki-plugin mkdocs-meta-descriptions-plugin mkdocs-enumerate-headings-plugin \
mkdocs-material mkdocs-mermaid2-plugin pandoc-latex-admonition markdown-katex \
git+https://gitlab.com/myriacore/pandoc-kroki-filter.git
```

### Using mkdocs

From the root of the project, run:

```bash
cd documentation/

# Run the server on all interfaces
source .venv/bin/activate
mkdocs serve -a 0.0.0.0:8003
```

Open a browser window at `http://[MACHINE_IP / LOCALHOST]:8003`

The doc is live-rendered when editing the Markdown files.
