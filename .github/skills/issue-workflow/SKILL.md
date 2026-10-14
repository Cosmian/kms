---
name: issue-workflow
description: 'Deterministic end-to-end procedure for resolving a GitHub issue: fetch and scope, reproduce (bugs), branch, implement, run the mandatory AGENTS.md §5 execution workflow (including auto-fixing /kms-pr-review self-review), open the PR. Use whenever given a GitHub issue number or URL to resolve.'
---

# Issue → PR workflow

Every step is mandatory and runs in order. Do not ask whether to run a step. Only Steps 1 and 8 contain stop conditions.

This skill is a thin router: every post-implementation step points to `AGENTS.md` §5 instead of restating it.

## 1. Fetch and scope

- Run `GH_PAGER=cat gh issue view <N> --repo Cosmian/kms --comments`.
- Category: `bug` if the issue carries the `bug` label, otherwise `enhancement` (`CONTRIBUTING.md` "Issue Lifecycle").
- Extract the acceptance criteria. For bugs, also extract the reproduction steps.
- Stop and ask the reporter if an enhancement has no acceptance criteria, or a bug has no reproduction steps, and neither can be derived from linked code or tests.

## 2. Reproduce (bugs only)

Write a failing test, or run the reporter's steps. Record the result: confirmed with code path / not reproduced / insufficient detail.

## 3. Branch

- Bug: `git switch -c fix/<slug> origin/develop`. Enhancement: `git switch -c feat/<slug> origin/develop`.
- `<slug>`: lowercase kebab-case of the issue title, at most 5 words, followed by `-<N>`.

## 4. Rollout order

If the change touches `crate/server/` or `crate/kmip/` **and** `crate/clients/` or `ui/`, follow `AGENTS.md` "Feature rollout order & PR cascade".

## 5. Implement

- Per-file instruction files in `.github/instructions/` auto-apply by path.
- For a new KMIP operation, REST endpoint, test vector, or `ckms` subcommand, run the matching skill: `/kmip-compliance`, `/openapi-endpoint`, `/kms-test-vector`, `/ckms-subcommand-test`.

## 6. Execution workflow

Run `AGENTS.md` §5 steps 1–7 exactly as written there. Step 6 is the auto-fixing `/kms-pr-review`.

## 7. Open the PR

- Base `develop`. The body contains `Fixes #<N>` and what/how/why (`CONTRIBUTING.md` "Pull Requests").
- Confirm that `CHANGELOG/<branch with / replaced by _>.md` exists.
- Never force-push.

## 8. Stop conditions

Report to the user instead of continuing when:

- Step 1 scope is unresolved;
- `/kms-pr-review` ends NO-GO or has `needs-human` findings after 2 fix cycles;
- the issue carries both `wontfix` and an active-work label.
