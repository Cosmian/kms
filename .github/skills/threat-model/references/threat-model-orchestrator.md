# Threat Model Orchestrator

Complete 10-step workflow for performing a STRIDE-A threat model analysis of the Eviden KMS. Follow every step in order.

## Mandatory Rules (apply to every analysis)

1. **Evidence-first**: Every threat must cite a specific file, function, or data flow path as evidence.
2. **No hallucinated findings**: If you cannot find evidence of a threat, mark it as "no evidence" rather than speculating.
3. **Verify before flagging**: Re-read the relevant code before listing a finding as confirmed.
4. **Scope discipline**: Stay within the requested scope; do not analyze components the user did not ask about.
5. **Severity calibration**: Use CVSS 4.0 base score ranges: CRITICAL ≥9.0, HIGH 7.0–8.9, MEDIUM 4.0–6.9, LOW 0.1–3.9.
6. **CWE mapping**: Every finding must have at least one CWE identifier.
7. **OWASP mapping**: Map findings to OWASP Top 10:2025 where applicable.
8. **No auto-remediation**: Propose fixes for review; do not apply them.
9. **Diagrams**: All Mermaid diagrams must follow `.github/skills/threat-model/references/threat-model-diagrams.md` conventions.
10. **Output format**: Follow `.github/skills/threat-model/references/threat-model-output-formats.md` templates exactly.

## Incremental Mode Trigger

If the user mentions "update", "refresh", "re-run", "what changed", or "incremental":

- Look for an existing `threat-model-*` directory with a `threat-inventory.json`
- If found: run the **Incremental Workflow** (steps 1–10 below, but comparing against the baseline)
- If not found: fall back to Single Analysis Mode

## Single Analysis Mode — 10-Step Workflow

### Step 1 — Codebase Discovery

```bash
# Understand the project structure
find . -name "Cargo.toml" -not -path "*/target/*" | head -20
ls crate/server/src/routes/
ls crate/server/src/middlewares/
ls crate/server/src/core/operations/
ls crate/hsm/
```

Read `AGENTS.md` sections 3 (repository map) and the KMIP request flow diagram to understand the overall architecture before proceeding.

### Step 2 — Asset Inventory

List all assets that require protection:

- **Primary**: Private key material, encrypted key blobs, KMIP object metadata
- **Secondary**: Authentication credentials (JWT secrets, API tokens, mTLS CAs), session state
- **Tertiary**: Audit logs, database contents, server configuration

### Step 3 — Component Inventory

For each component in the trust boundary map (from `threat-model.prompt.md`), identify:

- Inbound data flows (what data enters this component)
- Outbound data flows (what data exits this component)
- Privileges and credentials held
- External interfaces (network, filesystem, IPC)

### Step 4 — Data Flow Diagram (DFD)

Generate a DFD using Mermaid. Load `.github/skills/threat-model/references/threat-model-diagrams.md` for shape and color conventions.

Save as `threat-model-YYYYMMDD/1-dfd.md`.

### Step 5 — STRIDE-A Analysis

For each component and data flow, systematically apply STRIDE-A:

| Threat | Question |
|--------|----------|
| **S**poofing | Can an attacker impersonate another user/component? |
| **T**ampering | Can an attacker modify data in transit or at rest? |
| **R**epudiation | Can an attacker deny performing an action? |
| **I**information Disclosure | Can an attacker read data they should not? |
| **D**enial of Service | Can an attacker degrade or block availability? |
| **E**levation of Privilege | Can an attacker gain higher permissions? |
| **A**buse | Can an authorized user misuse the system? |

KMS-specific STRIDE focus areas:

- **S**: JWT/mTLS spoofing; API token reuse; user impersonation in multi-tenant mode
- **T**: Key material tampering in the database; TTLV message tampering in transit
- **I**: Unauthorized key material access (missing `is_allowed()` check); key metadata leakage via `Locate`; error messages revealing internal structure
- **D**: Unbounded KMIP batch requests; expensive crypto operations without rate limiting; HSM exhaustion
- **E**: Grant operation without ownership check; admin bypass via `insecure` feature flag in production
- **A**: Legitimate user exporting all their keys for exfiltration; `Locate` returning too many results

### Step 6 — HSM Trust Boundary Analysis

For deployments using HSMs (`crate/hsm/`):

- Is PKCS#11 communication over a network socket or local Unix socket?
- Is the HSM PIN/slot protected? (check `crate/server/src/config/wizard/hsm_wizard.rs`)
- Are HSM operations audited separately from software key operations?
- What happens on HSM unavailability — does the server fail open or fail closed?

### Step 7 — Cloud Provider Route Analysis

For each enabled cloud provider route (`crate/server/src/routes/aws_xks/`, `azure_ekm/`, `google_cse/`, `ms_dke/`):

- Is the cloud provider-specific authentication properly enforced?
- Are the provider's required headers validated?
- Is SSRF possible in the provider callback URLs?
- Are provider-specific key wrapping operations isolated from the main KMIP stack?

### Step 8 — Dependency Analysis

```bash
# Check for known vulnerabilities
cargo audit 2>/dev/null || echo "cargo-audit not installed"

# Review crypto dependencies specifically
grep -E "openssl|ring|rustls|hyper|actix" Cargo.toml crate/*/Cargo.toml
```

Flag: unpinned major versions of security-critical crates, deprecated crates, crates with active CVEs.

### Step 9 — Findings Prioritization

Rank findings by:

1. CVSS 4.0 base score (primary)
2. Exploitability (is the attack vector network-accessible?)
3. Business impact (does it affect FIPS compliance? key confidentiality? availability?)

Group into:

- 🔴 CRITICAL: Exploit leads to key material exposure or full auth bypass
- 🟠 HIGH: Serious exploit path exists with conditions
- 🟡 MEDIUM: Exploitable with chaining or specific conditions
- 🔵 LOW: Defense-in-depth gaps
- ⚪ INFO: Hardening opportunities

### Step 10 — Output Generation

Generate the following files in `threat-model-YYYYMMDD-HHMMSS/`:

1. `0-architecture.md` — system overview, component inventory, asset list
2. `1-dfd.md` — Mermaid data flow diagrams
3. `2-stride-analysis.md` — complete STRIDE-A table with evidence
4. `3-findings.md` — prioritized findings with CVSS/CWE/OWASP mappings and patch proposals
5. `0-assessment.md` — executive summary (1 page)
6. `threat-inventory.json` — machine-readable finding list for incremental updates

Load `.github/skills/threat-model/references/threat-model-output-formats.md` for exact templates before writing each file.

## Incremental Workflow (Delta Analysis)

When a `threat-inventory.json` baseline exists:

1. Load the baseline inventory
2. Checkout/read the current code at HEAD
3. For each existing threat: re-verify evidence still exists in current code
   - Evidence found: mark "still-present"
   - Evidence gone: mark "resolved (verify manually)"
4. Scan for new threats introduced since the baseline
5. Produce a new `threat-model-YYYYMMDD/` folder with:
   - Full report (same structure as single analysis)
   - `DELTA.md` — what's new, resolved, and still-present
   - Updated `threat-inventory.json`
6. Embed a comparison table at the top of `0-assessment.md`
