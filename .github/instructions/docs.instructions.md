---
name: 'Documentation'
description: 'MkDocs documentation conventions (Diátaxis framework)'
applyTo: '{documentation,cli_documentation}/**/*.md'
---

# Documentation rules

## Framework: Diátaxis

Organize content into four types:

| Type | Purpose | Tone |
|------|---------|------|
| **Tutorial** | Learning-oriented, guided walkthrough | "Follow along…" |
| **How-to guide** | Task-oriented, solve a specific problem | "To do X, run…" |
| **Reference** | Information-oriented, technical description | Factual, complete |
| **Explanation** | Understanding-oriented, discuss concepts | "This works because…" |

## Navigation

- `documentation/mkdocs.yml` is the **source of truth** for page navigation.
- When adding a new page, update `mkdocs.yml` nav — do not rely on auto-discovery.
- Integrations require: doc file in `documentation/docs/integrations/`, nav entry in `mkdocs.yml`, row in `README.md`.

## Examples

- **First choice**: copy from test `assert_eq!` output or test vector manifests.
- **Second choice**: live KMS output (paste actual command + response).
- **Never** invent examples — they may contain incorrect values.

## Specification references

Always verify spec citations against authoritative sources:

| Domain | Source |
|--------|--------|
| IETF RFCs | rfc-editor.org |
| KMIP | OASIS KMIP spec (HTML files in `kmip/`) |
| FIPS/NIST | csrc.nist.gov |
| ASN.1 OIDs | oidref.com |

Do not rely on training-data recall for spec section numbers or OID values.

## Style

- Use ATX headings (`#`, `##`, `###`).
- Code blocks with language specifier (` ```bash `, ` ```json `, etc.).
- One sentence per line (for clean git diffs).

> For deeper guidance on documentation pages, run `/docs-writer`.
