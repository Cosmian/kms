# Citation Rules

Mandatory rules for citing standards in any skill output. These rules supplement
the general anti-hallucination discipline in `.github/skills/shared/anti-hallucination.md`.

---

## Rule 1 — Verify before citing

Never write a section number, paragraph reference, or requirement text without first
verifying it exists in the source document during this session.

Verification methods (in order of preference):

1. **Local file read**: for KMIP specs (`kmip/v2.1/kmip-spec-v2.1-os.html`) — grep for the section heading
2. **URL fetch**: for RFCs, NIST publications, BSI/ANSSI guides — fetch the canonical URL and search for the section
3. **Bibliography grep**: for academic papers — grep `documentation/pandoc/cryptobib/crypto.bib` for the bib key

If none of these methods succeeds, the section number is **unverified** and must not be cited.

## Rule 2 — Citation format

Use this exact format for all standard citations:

```text
[Standard-ID], Section N.N.N, "Exact Section Heading"
```

Examples:

- `[RFC 5280], Section 4.2.1.2, "Subject Key Identifier"`
- `[FIPS 197], Section 5, "Algorithm Specification"`
- `[KMIP 2.1], Section 4.3, "Create"`
- `[BSI TR-02102-1], Section 3.2` (PDFs — heading verification may not be possible)

## Rule 3 — Fallback to document-level citation

When a section number cannot be verified (fetch failed, PDF not parseable, section
not found in grep), cite at **document level only**:

```text
[FIPS 203]                    ← acceptable when section unverifiable
[FIPS 203, §4.1]              ← FORBIDDEN if §4.1 was not verified
```

## Rule 4 — Never paraphrase requirements as quotes

When citing a standard's requirement:

- **Exact quote**: wrap in quotation marks and cite source:
  `"The signature algorithm MUST be one of..." — [RFC 5280], Section 4.1.1.2`
- **Paraphrase**: explicitly label as paraphrase:
  `[Paraphrase] RFC 5280 requires the signature algorithm to be from an approved list.`

Never present a paraphrase as if it were a direct quote.

## Rule 5 — KMIP local verification procedure

For KMIP citations, the spec is available locally. Use this procedure:

1. Read `kmip/v2.1/kmip-spec-v2.1-os.html`
2. Search for the section heading (e.g., search for "Create" to find the Create operation section)
3. Extract the exact section number from the heading found
4. Quote the relevant requirement verbatim

Do not rely on training-data knowledge of KMIP section numbers — always verify locally.

## Rule 6 — RFC verification procedure

For RFC citations:

1. Fetch `https://www.rfc-editor.org/rfc/rfcNNNN` (the canonical text URL)
2. Search the fetched content for the section heading
3. Confirm the section number matches
4. Quote the requirement if needed

If the fetch fails (timeout, 404), cite at document level only.

## Rule 7 — Academic paper citation procedure

For academic paper citations:

1. Search `documentation/pandoc/cryptobib/crypto.bib` for the bib key
2. Only cite papers whose bib key was **found** in the search results
3. Use the bib key as the citation: `[Bleichenbacher98]`, `[Vaudenay02]`
4. Never invent a bib key — if the search returns no results, do not cite the paper

## Rule 8 — Contradiction between standards

When two standards disagree on a requirement (e.g., FIPS approves RSA-2048 but BSI
recommends RSA-3072+):

1. Report both positions with citations
2. Do not pick a winner — present the conflict
3. Note which standard takes precedence in the deployment context (if known)

```markdown
**Multi-standard divergence**: RSA-2048 is approved by [FIPS 140-3] but deprecated
by [BSI TR-02102-1] (2024) which recommends 3072+ bits. The applicable standard
depends on the deployment jurisdiction.
```
