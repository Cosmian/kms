# Threat Model Output Formats

Templates for every output file. Copy the skeleton, fill in `[FILL]` placeholders. Never invent data — mark missing evidence as "not determined."

---

## 0-architecture.md

```markdown
# Architecture Overview — Eviden KMS

**Analysis date**: [FILL: YYYY-MM-DD]
**Scope**: [FILL: full repo | specific subsystem]
**Analyst**: AI Threat Model Analyst

## System Description

[FILL: 2–3 sentences describing what the system does and who uses it]

## Component Inventory

| Component | Location | Purpose | Trust Level |
|-----------|----------|---------|-------------|
| Actix-web HTTP layer | `crate/server/src/routes/` | HTTP/TLS termination, request routing | Untrusted boundary |
| Auth middleware | `crate/server/src/middlewares/` | JWT/mTLS/API token validation | Semi-trusted |
| KMIP dispatcher | `crate/server/src/core/operations/dispatch.rs` | Operation routing | Trusted |
| KMS struct | `crate/server/src/core/kms/mod.rs` | Core KMS logic | Trusted |
| Database backend | `crate/server_database/src/` | Key/object persistence | Trusted (local) |
| Crypto oracles | `crate/crypto/src/` | Cryptographic operations via OpenSSL | Trusted |
| HSM (optional) | `crate/hsm/` | Hardware key operations via PKCS#11 | Trusted (external) |
| [FILL: additional components] | | | |

## Asset Inventory

| Asset | Location | Sensitivity | Protection |
|-------|----------|-------------|-----------|
| Private key material | Database / HSM | CRITICAL | Encrypted at rest; access-controlled |
| KMIP object metadata | Database | HIGH | Access-controlled |
| Auth credentials (JWT keys, API tokens) | Config / env | CRITICAL | Not persisted in DB |
| Audit logs | Server logs | MEDIUM | Append-only (no tamper protection by default) |
| [FILL: additional assets] | | | |

## Trust Boundary Summary

[FILL: list each trust boundary and what crosses it]
```

---

## 1-dfd.md (Data Flow Diagram)

```markdown
# Data Flow Diagram — Eviden KMS

## Level 0 — System Context

[Include Mermaid diagram from threat-model-diagrams.md conventions]

## Level 1 — KMIP Request Flow

[Include detailed DFD of KMIP request processing]

## Notes

- [FILL: any unusual data flows or trust boundary crossings worth explaining]
```

---

## 2-stride-analysis.md

```markdown
# STRIDE-A Analysis — Eviden KMS

## Analysis Matrix

| ID | Component / Data Flow | Threat Type | Threat Description | Evidence | CVSS 4.0 | CWE | Status |
|----|----------------------|-------------|-------------------|----------|----------|-----|--------|
| T-001 | Auth middleware | Spoofing | [FILL] | `crate/server/src/middlewares/...` | [FILL] | CWE-287 | [Confirmed/Not confirmed/No evidence] |
| T-002 | KMIP Get operation | Information Disclosure | [FILL] | `crate/server/src/core/operations/get.rs:L42` | [FILL] | CWE-284 | |
| [FILL: additional rows] | | | | | | | |

## Threat Narrative

For each CRITICAL and HIGH threat, provide a detailed narrative:

### T-001: [Title]
**Attack scenario**: [How would an attacker exploit this?]
**Pre-conditions**: [What does the attacker need?]
**Impact**: [What is compromised?]
**Evidence**: [Specific code location]
**Mitigations present**: [What controls exist today?]
**Gaps**: [What is missing?]
```

---

## 3-findings.md

```markdown
# Security Findings — Eviden KMS

## Summary

| Severity | Count |
|----------|-------|
| 🔴 CRITICAL | [N] |
| 🟠 HIGH | [N] |
| 🟡 MEDIUM | [N] |
| 🔵 LOW | [N] |
| ⚪ INFO | [N] |

---

## Finding Cards

### [F-001] 🔴 CRITICAL — [Title]

| Field | Value |
|-------|-------|
| **STRIDE** | [S/T/R/I/D/E/A] |
| **CWE** | [CWE-XXX: Name] |
| **OWASP** | [A0X:2025 — Name] |
| **CVSS 4.0** | [score] — [vector string] |
| **Component** | [component name] |
| **File** | `path/to/file.rs:L42` |

**Description**

[Detailed description of the vulnerability]

**Evidence**

    // Vulnerable code snippet
    fn get_object(uid: &str, db: &dyn Database) -> KResult<KmipObject> {
        // missing access control check before returning key material
        db.get(uid).await
    }

#### Attack Scenario

[Step-by-step: how an attacker exploits this]

**Proposed Fix** (review before applying)

    // Fixed code snippet
    async fn get_object(uid: &str, caller: &UserId, db: &dyn Database) -> KResult<KmipObject> {
        db.is_allowed(uid, caller, OperationType::Get).await?;
        db.get(uid).await
    }

---

[Repeat for each finding]

```markdown

---

## 0-assessment.md (Executive Summary)

```markdown
# Threat Model Assessment — Eviden KMS

**Date**: [FILL]
**Scope**: [FILL]
**Overall Risk Posture**: [CRITICAL / HIGH / MEDIUM / LOW]

## Key Findings

[3–5 bullet points summarizing the most important findings]

## Risk Summary

| Category | Risk Level | Notes |
|----------|------------|-------|
| Authentication & Authorization | [FILL] | [FILL] |
| KMIP Protocol Security | [FILL] | [FILL] |
| Cryptographic Implementation | [FILL] | [FILL] |
| HSM Trust Boundary | [FILL] | [FILL] |
| Dependency Supply Chain | [FILL] | [FILL] |

## Recommended Actions (Priority Order)

1. [Highest priority — CRITICAL finding]
2. [Next — HIGH finding]
3. ...

## Scope Limitations

[What was NOT analyzed, and why. What assumptions were made.]

---
*Generated by AI Threat Model Analyst. All findings require human review before remediation.*
```

---

## threat-inventory.json (Machine-Readable)

```json
{
  "analysis_date": "YYYY-MM-DD",
  "scope": "full-repo",
  "commit": "abc1234",
  "findings": [
    {
      "id": "F-001",
      "title": "Missing access control in Get operation",
      "stride": "I",
      "severity": "CRITICAL",
      "cvss_score": 9.1,
      "cwe": "CWE-284",
      "owasp": "A01:2025",
      "component": "KMIP operations",
      "file": "crate/server/src/core/operations/get.rs",
      "line": 42,
      "status": "confirmed",
      "evidence": "db.get() called without is_allowed() check"
    }
  ],
  "summary": {
    "critical": 1,
    "high": 0,
    "medium": 3,
    "low": 2,
    "info": 1
  }
}
```
