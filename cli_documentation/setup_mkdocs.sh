#!/bin/bash

python3 -m venv .venv

source .venv/bin/activate

pip3 install pydoc-markdown git+https://github.com/twardoch/mkdocs-combine.git \
mkdocs-kroki-plugin mkdocs-meta-descriptions-plugin mkdocs-enumerate-headings-plugin \
mkdocs-material mkdocs-mermaid2-plugin pandoc-latex-admonition markdown-katex \
git+https://gitlab.com/myriacore/pandoc-kroki-filter.git
