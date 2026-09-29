# Anti-Hallucination Discipline

**Load this file at the start of every skill before performing any analysis.**

These rules are mandatory and non-negotiable. Violations invalidate the entire report.

---

## Rules

### 1. Evidence-first

Every finding **must** cite `file:line` obtained by actually reading or searching the file
during this session. Findings based on training-data recall alone are forbidden.

### 2. Search before stating

Run a grep or search tool **before** claiming:

- An algorithm is used or absent
- A function exists or is missing
- A pattern is present or violated
- A dependency is included

Never state a fact about the codebase without tool-verified evidence from this session.

### 3. Binary findings only

Every finding is either:

- **CONFIRMED** — with quoted code evidence from the file read
- **NOT RAISED** — insufficient evidence; do not mention it

Words like "probably", "likely", "appears to", "seems to", "might" are **forbidden** in
findings. If you cannot confirm it, do not raise it.

### 4. Standard citation discipline

Before citing any section number, paragraph, or requirement from a standard:

1. **Verify** the section exists via local file read or URL fetch in this session
2. If the section cannot be verified: cite at **document level only**
   (`[FIPS 203]` not `[FIPS 203, §4.1]`)
3. Training-data recall of section numbers is **forbidden** until verified

### 5. No reconstructed code snippets

All code shown in findings must be **verbatim text** from a file read during this session.
Never reconstruct code from memory or paraphrase it. Copy-paste only.

### 6. Scope discipline

Only report on files **actually read or searched** during this skill run. Do not report
on files assumed to exist based on naming conventions or directory structures unless
you have listed or read them.

### 7. Uncertainty escalation

If a finding cannot be confirmed with the tools available:

- Mark it: `⚠️ REQUIRES MANUAL VERIFICATION — location: file:line`
- Do **not** raise it as a confirmed finding
- Do **not** assign it a severity rating
- List it in a separate "Unverified" section at the end of the report

### 8. Contradiction surfacing

If two pieces of evidence conflict (e.g., a comment says one thing but the code does
another), surface the contradiction **explicitly**:

> **Contradiction detected**: `file_a.rs:42` states X, but `file_b.rs:17` implements Y.
> Manual review required.

Never resolve contradictions silently by picking one interpretation.

---

## Verification checklist (run before emitting the report)

- [ ] Every finding cites a `file:line` I actually read in this session
- [ ] Every standard section number was verified via fetch or local file read
- [ ] Every code snippet is verbatim from a file read — not reconstructed
- [ ] No finding uses "probably", "likely", "appears to", or "seems to"
- [ ] Unverifiable items are in the "Unverified" section, not in main findings
- [ ] Contradictions are surfaced, not silently resolved
