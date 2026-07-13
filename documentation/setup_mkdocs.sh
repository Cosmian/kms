#!/bin/bash

virtualenv env

source env/bin/activate

# Pinned versions live in requirements.txt so that local (dev) and production
# builds of the documentation use the exact same mkdocs / mkdocs-material
# release. See requirements.txt for why this matters.
pip3 install -r "$(dirname "${BASH_SOURCE[0]}")/requirements.txt" \
  git+https://github.com/twardoch/mkdocs-combine.git \
  pandoc-latex-admonition \
  git+https://gitlab.com/myriacore/pandoc-kroki-filter.git
