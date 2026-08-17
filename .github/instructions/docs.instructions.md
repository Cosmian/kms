---
name: 'Documentation'
description: 'mdBook documentation conventions (Diátaxis framework)'
applyTo: 'documentation/**/*.md, README.md'
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

- `documentation/docs/SUMMARY.md` (mdBook) and `documentation/nav.yml` are the **two navigation sources** — keep both in sync.
- When adding or removing a page, update **both** `SUMMARY.md` and `nav.yml` — do not rely on auto-discovery.
- Integrations require: doc file in `documentation/docs/integrations/`, nav entry in `SUMMARY.md` + `nav.yml`, row in `README.md`.

## Examples

- **First choice**: copy from test `assert_eq!` output or test vector manifests.
- **Second choice**: live KMS output (paste actual command + response).
- **Never** invent examples — they may contain incorrect values.

## Specification references

Always verify spec citations against authoritative sources before writing them.
Load `.github/skills/shared/anti-hallucination.md` rules when writing documentation
that cites standards.

| Domain | Source | Verification method |
|--------|--------|---------------------|
| IETF RFCs | rfc-editor.org | Fetch `https://www.rfc-editor.org/rfc/rfcNNNN` and confirm the section heading exists |
| KMIP | OASIS KMIP spec (HTML files in `kmip/`) | Read `kmip/v2.1/kmip-spec-v2.1-os.html` locally; grep for the exact section heading |
| FIPS/NIST | csrc.nist.gov | Fetch the canonical `csrc.nist.gov/pubs/` URL and verify the section |
| ASN.1 OIDs | oidref.com | Verify OID value before writing — never recall from training data |
| BSI | bsi.bund.de | Cite document + section only if the PDF was fetched |
| ANSSI | cyber.gouv.fr | Cite document + section only if the page was fetched |
| PKCS | See RFC mappings | PKCS#1→RFC 8017, PKCS#5→RFC 8018, PKCS#8→RFC 5958, PKCS#12→RFC 7292 |
| Academic papers | `documentation/pandoc/cryptobib/crypto.bib` | Grep for the exact bib key before citing |

### Citation format

Use this format for inline standard references:

```text
[Standard-ID], Section N.N.N, "Exact Section Heading"
```

Examples:

- `[RFC 5280], Section 4.2.1.2, "Subject Key Identifier"`
- `[FIPS 197], Section 5, "Algorithm Specification"`
- `[KMIP 2.1], Section 4.3, "Create"`

### Anti-hallucination rules for documentation

1. **Never write a section number** without verifying it via local file read or URL fetch in this session.
2. **Never paraphrase a standard as a quote** — use explicit `[Paraphrase]` label or quote verbatim with attribution.
3. **When a section cannot be verified** (fetch failed, PDF not parseable): cite at document level only (`[FIPS 203]` not `[FIPS 203, §4.1]`).
4. **Never invent OID values** — verify against oidref.com or the governing RFC before writing.
5. **Never invent algorithm parameters** (key sizes, iteration counts, salt lengths) — verify against the governing standard.
6. **Academic paper citations** must use bib keys found via grep in `documentation/pandoc/cryptobib/crypto.bib` — never invent a citation key.

> For the full standards index (FIPS, NIST SP, RFC, KMIP, BSI, ANSSI, OWASP, PKCS, SEC/SECG),
> see `.github/skills/standards-review/references/standards-index.md`.
> For the full citation discipline, see `.github/skills/standards-review/references/citation-rules.md`.

Do not rely on training-data recall for spec section numbers or OID values.

## Style

- Use ATX headings (`#`, `##`, `###`).
- Code blocks with language specifier (` ```bash `, ` ```json `, etc.).
- One sentence per line (for clean git diffs).

> For deeper guidance on documentation pages, run `/docs-writer`.
