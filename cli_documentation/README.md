# Cosmian KMS Clients Documentation

This directory contains the documentation for Cosmian KMS client tools:

- **Command Line Interface (CLI)** - `cosmian` / `ckms` command-line tool
- **PKCS#11 Provider** - PKCS#11 module for HSM integration

## Building the documentation

### Prerequisites

Install the required Python packages:

```bash
pip install mkdocs mkdocs-material mkdocs-kroki-plugin pymdown-extensions markdown-include mkdocs-meta-descriptions-plugin markdown-katex
```

### Building locally

To build and serve the documentation locally:

```bash
cd cli_documentation
mkdocs serve
```

The documentation will be available at `http://localhost:8004`

### Building static site

To build the static HTML site:

```bash
cd cli_documentation
mkdocs build
```

The static site will be generated in the `site/` directory.

## Directory Structure

```text
cli_documentation/
├── mkdocs.yml              # MkDocs configuration
├── includes.yml            # Pandoc includes for PDF generation
├── README.md               # This file
├── docs/                   # Documentation source files
│   ├── index.md           # Getting started
│   ├── installation.md    # Installation guide
│   ├── authentication.md  # Authentication configuration
│   ├── configuration.md   # Configuration examples
│   ├── usage.md          # CLI usage guide
│   ├── authorization.md   # Access rights management
│   ├── smime_gmail.md    # S/MIME Gmail integration
│   ├── cli/              # CLI reference documentation
│   │   └── main_commands.md
│   ├── pkcs11/           # PKCS#11 documentation
│   │   ├── veracrypt.md
│   │   ├── luks.md
│   │   ├── cryhod.md
│   │   ├── oracle/
│   │   │   └── tde.md
│   │   └── images/
│   ├── images/           # Shared images
│   └── favicon.png       # Site favicon
└── theme_overrides/      # Custom theme files
    └── main.html
```

## Publishing

This documentation can be:

1. Merged into the main KMS documentation site
2. Published as a standalone site
3. Generated as PDF using Pandoc

## Integration with Main Documentation

To integrate with the main KMS documentation, this structure can be merged by:

1. Copying `docs/` content to `../documentation/docs/kms_clients/`
2. Merging navigation entries into `../documentation/mkdocs.yml`
