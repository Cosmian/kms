---
name: adr
description: 'Create an Architectural Decision Record (ADR) under documentation/docs/adr/. Use when making or documenting an architectural decision.'
---

# Architectural Decision Record Generator

Create an ADR document for the Cosmian KMS repository.

## ADR Storage

Save ADRs at: `documentation/docs/adr/adr-YYYY-MM-DD-[title-slug].md`

Where `YYYY-MM-DD` is the current date.

If the `documentation/docs/adr/` directory doesn't exist yet, create it and add a nav entry in `documentation/mkdocs.yml`.

## Required Inputs

Ask the user for:

1. **Decision Title** — short, imperative phrase (e.g. "Use SQLite as default database backend")
2. **Context** — problem statement, constraints, and why a decision was needed
3. **Decision** — the chosen solution
4. **Alternatives** — other options considered and why they were rejected
5. **Stakeholders** — roles affected (e.g. "operators, security auditors, contributors")

If any required input is missing, ask before proceeding.

## ADR Template

```markdown
---
title: "ADR-YYYY-MM-DD: [Decision Title]"
status: "Proposed"
date: "YYYY-MM-DD"
authors: "[Stakeholder Names/Roles]"
tags: ["architecture", "decision"]
supersedes: ""
superseded_by: ""
---

# ADR-YYYY-MM-DD: [Decision Title]

## Status

**Proposed** | Accepted | Rejected | Superseded | Deprecated

## Context

[Problem statement, technical constraints, business requirements, and environmental factors requiring this decision.]

## Decision

[Chosen solution with clear rationale for selection.]

## Consequences

### Positive

- **POS-001**: [Beneficial outcome]
- **POS-002**: [Performance, maintainability, or security improvement]

### Negative

- **NEG-001**: [Trade-off or limitation]
- **NEG-002**: [Technical debt or complexity introduced]

## Alternatives Considered

### [Alternative 1 Name]

- **ALT-001 Description**: [Brief technical description]
- **ALT-002 Rejection Reason**: [Why this option was not selected]

### [Alternative 2 Name]

- **ALT-003 Description**: [Brief technical description]
- **ALT-004 Rejection Reason**: [Why this option was not selected]

## Implementation Notes

- **IMP-001**: [Key implementation consideration]
- **IMP-002**: [Migration or rollout strategy if applicable]
- **IMP-003**: [Monitoring and success criteria]

## References

- **REF-001**: [Related ADRs or prior decisions]
- **REF-002**: [External documentation, RFCs, specifications]
- **REF-003**: [Relevant codebase files: e.g. `crate/server_database/src/`, `crate/server/src/config/`]
```
