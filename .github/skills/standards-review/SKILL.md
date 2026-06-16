---
name: standards-review
description: 'Verify code and protocol implementations against the exact text of applicable standards (FIPS, NIST SP, RFC, KMIP, PKCS, BSI, ANSSI, OWASP). Every citation is URL-verified — no hallucinated section numbers. Use when checking standards compliance or before a compliance audit.'
---

# Standards Compliance Review

Verify that code, documentation, and protocol implementations conform to the **exact text**
of applicable standards. This skill enforces citation-level accuracy: every section number
and requirement is verified against the source document before being written.

## When to Use

- Before a compliance audit (FIPS, Common Criteria, BSI certification)
- When implementing or modifying a KMIP operation — verify against KMIP 2.1 spec
- When implementing cryptographic protocols — verify against RFC / NIST SP requirements
- When adding key management features — verify against SP 800-57 requirements
- When writing documentation that references standards — verify section citations
- Any request like "is this compliant with RFC X?", "check KMIP spec", "verify FIPS conformance"

## Step 0 — Load Anti-Hallucination Discipline

Read `.github/skills/shared/anti-hallucination.md` **before any analysis**. All rules in
that file are mandatory. Do not proceed to Step 1 until you have read it.

Then read `.github/skills/standards-review/references/citation-rules.md` — these citation-specific
rules supplement the general anti-hallucination discipline.

---

## Step 1 — Scope Resolution

If a path was provided (e.g. `/standards-review crate/server/src/core/operations/create.rs`),
scope the review to that path. Otherwise, review the entire workspace.

Identify what the scoped code does:

- KMIP operations → OASIS KMIP spec applies
- Cryptographic primitives → FIPS, NIST SP, RFC, BSI, ANSSI apply
- Key management → SP 800-57, SP 800-133 apply
- TLS / authentication → RFC 8446, BSI TR-02102-2, ANSSI TLS guide apply
- X.509 / PKI → RFC 5280, RFC 5480 apply
- JOSE / JWT → RFC 7515–7519 apply
- PKCS#11 / HSM → PKCS#11 v3.1 applies

## Step 2 — Applicability Matrix

Load `.github/skills/standards-review/references/standards-index.md`.

For each standard in the index, determine if it applies to the scoped code. Produce the
applicability matrix:

```markdown
| Standard | Applies? | Reason |
|----------|----------|--------|
| FIPS 197 (AES) | ✅ Yes | AES encryption used in `crate/crypto/src/crypto/symmetric/` |
| RFC 5280 (X.509) | ✅ Yes | Certificate operations in `crate/crypto/src/openssl/` |
| KMIP 2.1 | ❌ No | No KMIP operation code in scope |
| ... | ... | ... |
```

Only proceed with standards marked "✅ Yes".

## Step 3 — Standard-by-Standard Conformance Check

For each applicable standard, perform a conformance review:

### For locally available standards (KMIP)

KMIP specifications are available locally:

- `kmip/v2.1/kmip-spec-v2.1-os.html` — KMIP 2.1 Official Specification
- `kmip/v1.4/` — KMIP 1.4
- `kmip/v3.0/` — KMIP 3.0 (draft)

**Method**: Read the local HTML file. Search (grep) for the exact section heading before
citing any section. Quote the relevant requirement verbatim from the spec.

### For IETF RFCs

**Method**: Fetch `https://www.rfc-editor.org/rfc/rfcNNNN` and verify the section heading
exists before citing. If the fetch fails, cite at document level only.

### For NIST FIPS / SP publications

**Method**: Fetch the canonical `csrc.nist.gov` URL from the standards index and verify
the section heading. If the fetch fails, cite at document level only.

### For BSI / ANSSI guidelines

**Method**: These are PDF documents. Cite at document-and-section level only if you can
verify the section heading via fetch. Otherwise cite at document level.

### For academic papers

**Method**: Search `documentation/pandoc/cryptobib/crypto.bib` for the exact bib key.
Only cite papers whose bib key was found via grep in this session.

## Step 4 — Conformance Findings

For each gap between the code and a standard requirement, produce a finding:

```markdown
#### [GAP/DEVIATION/VIOLATION] — [Short title]

- **Standard**: [Standard-ID], Section N.N, "Exact Section Heading" (verified via [local read / URL fetch])
- **Requirement**: "[Exact quote from the standard or clearly marked paraphrase]"
- **Code**: `file:line` — [verbatim code snippet from file read]
- **Gap**: [What the code does vs. what the standard requires]
- **Severity**: 🔴 Violation / 🟠 Deviation / 🟡 Advisory / 🔵 Informational
- **Recommendation**: [Specific fix to achieve conformance]
```

Severity guide:

- 🔴 **Violation**: code contradicts a MUST/SHALL requirement in the standard
- 🟠 **Deviation**: code does not follow a SHOULD/RECOMMENDED requirement
- 🟡 **Advisory**: standard allows the current approach but a better practice exists
- 🔵 **Informational**: standard is silent on this point; noted for awareness

## Step 5 — Compliance Checklist Cross-Reference

Load `.github/skills/standards-review/references/compliance-checklist.md`.

For each algorithm used in the scoped code, verify its status in the checklist table.
Flag any algorithm that is:

- **Forbidden** by any applicable standard
- **Deprecated** with an approaching sunset date
- **Not covered** by a standard that the deployment context requires

## Step 6 — Self-Verification Pass

Before emitting the report, run the anti-hallucination verification checklist:

1. For every standard citation: was the section number verified via fetch or local file read in this session?
2. For every code snippet: is it verbatim from a file read, not reconstructed?
3. For every finding: does the `file:line` reference exist and was it read?
4. Remove or downgrade any finding that cannot be verified

## Step 7 — Generate Report

```markdown
## Standards Compliance Review: [scope]

### Applicability Matrix
[Table from Step 2]

### Summary
| Standard | Conformance | Violations | Deviations | Advisory |
|----------|-------------|------------|------------|----------|
| KMIP 2.1 | ✅ Conformant / ⚠️ N gaps | N | N | N |
| FIPS 197 | ✅ Conformant / ⚠️ N gaps | N | N | N |
| ... | ... | ... | ... | ... |

### Findings
[Ordered by severity: Violations first, then Deviations, Advisory, Informational]

### Unverified Items
[Items where the standard section could not be fetched or verified —
marked "⚠️ REQUIRES MANUAL VERIFICATION" per anti-hallucination rules]

### Standards Not Assessed
[Standards from the index that were applicable but could not be reviewed
due to fetch failures or scope limitations — listed for completeness]
```

## Output Rules

- **Never** auto-apply fixes — present findings for human review
- **Never** cite a section number without verification
- **Always** distinguish between MUST/SHALL violations and SHOULD/RECOMMENDED deviations
- **Always** include the verification method (local read / URL fetch) for each citation
- **Group** findings by standard, then by severity within each standard
