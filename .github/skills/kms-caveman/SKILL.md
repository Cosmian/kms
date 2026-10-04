---
name: kms-caveman
description: 'Performs concise, read-only mechanical Rust triage for panic/exit patterns, new lint suppressions, and structural candidates. Use before deeper Rust audits or for a quick scoped scan; it does not replace semantic, security, crypto, or protocol review.'
---

# KMS Caveman

One scoped, read-only scan. Keep output terse; preserve exact technical evidence.

## Scope

- Supplied path: inspect Rust files under that path only.
- No path: collect branch Rust changes, staged/unstaged files, and untracked Rust files. Use the available base; state any fallback.
- Failed or empty diff is not proof of a clean scan. If scope cannot be established, report `INCOMPLETE`.
- Exclude generated/vendor code only when identified; state exclusions.

## Rules

1. Scan for `panic!`, `todo!`, `unimplemented!`, `unreachable!`, `.unwrap()`, `.expect(`, `process::exit`, and `process::abort`.
2. Treat searches as candidates. Confirm executable code, source context, `#[cfg(test)]`, bounds checks, and documented exceptions.
3. Check changed Rust lines for new `#[allow(...)]` / `#[expect(...)]`; verify repository policy and justification.
4. Flag structural candidates: functions >60 lines, nesting ≥5, multiple bool parameters, or repeated blocks ≥5 lines. Verify boundaries; do not report style as correctness defects.
5. Report dead/unused code only with workspace-wide evidence accounting for callers, macros, and generated uses.

Do not edit code, perform semantic refactors, or invoke sub-skills. Escalate reasoning-dependent findings to the applicable review skill.

## Report

Pattern: `[SEVERITY] path:line — finding. Evidence: <code>. Risk: <impact>. Fix: <minimal change>.`

- Rank verified findings; mark uncertain observations as candidates.
- **BLOCK** on confirmed CRITICAL/HIGH findings.
- **PASS** means no confirmed CRITICAL/HIGH finding in the verified scope; not a full quality or security verdict.
- Use `NOT APPLICABLE` when no Rust files are in scope and `INCOMPLETE` when scope/context is missing. Neither means PASS.
- Do not claim detection rates, model choice, latency, or token savings without measured evidence.
- If an orchestrator writes reports, use `./review/kms-caveman.md`; otherwise return the concise ranked list.

## Credit-saving style

- Drop articles, filler, pleasantries, and hedging. Fragments and arrows are fine; technical terms stay exact.
- Keep code blocks and error text unchanged. Include enough evidence to preserve meaning; brevity never outranks correctness.

### Auto-clarity exception

Expand security/protocol findings, ambiguous scope, or multi-step skip reasoning whenever compression could obscure risk. Resume terse output after clarity is restored.

## Examples

Illustrative only; not findings from this repository.

**Confirmed production panic:**

```rust
let object = database.retrieve_object(uid).await.unwrap();
```

```text
[HIGH] crate/example/src/handler.rs:42 — `.unwrap()` in production
Evidence: `database.retrieve_object(uid).await.unwrap()`
Risk: error becomes panic. Fix: propagate/map with the enclosing error type.
Verdict: BLOCK
```

Do not flag the line if source context places it inside `#[cfg(test)]`.

**Structural candidate, no blocker:**

```text
[MEDIUM] crate/example/src/worker.rs:81-151 — function exceeds 60 lines; review candidate only.
Verdict: PASS — no confirmed CRITICAL/HIGH finding in inspected scope.
```

**Non-Rust scope:**

```text
Scope: ui/src/theme.css
Rust: NOT APPLICABLE
```

For an explicitly incremental CSS-only review, skip `/cryptography-review` only after confirming no crypto, algorithm,
key-lifecycle, provider, or FIPS-gate change. Never infer a security-review skip from the path alone; verify no dynamic data,
auth/session, API, or sensitive-data behavior. Full `/meta-security` and `/pre-release` gates still run required reviews.
