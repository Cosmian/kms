---
name: issue-workflow
description: 'Deterministic end-to-end procedure for resolving a GitHub issue: scope, reproduce (bugs), plan, branch (stacked when required), test-first implementation, variant/backend/UI testing, documentation, the mandatory AGENTS.md §5 execution workflow (including auto-fixing /kms-pr-review), Conventional Commits, PR creation, a one-shot CI status report, and review-feedback handling. Never waits for CI to finish and never merges. Use whenever given a GitHub issue number or URL to resolve.'
---

# Issue → PR workflow

Every step is mandatory and runs in order. Do not ask whether to run a step. Stop only on a condition listed in step 13.

This skill is a router: post-implementation checks point to `AGENTS.md` §5 instead of restating it. Coding rules are in `AGENTS.md` §4 and the per-file instruction files in `.github/instructions/`, which apply automatically by path.

## 1. Fetch and scope

- Run `GH_PAGER=cat gh issue view <N> --repo Cosmian/kms --json title,body,labels,assignees,comments,closedByPullRequestsReferences`. Do not use `--comments` alone: it omits the issue body.
- Run `GH_PAGER=cat gh pr list --repo Cosmian/kms --state open --search "<N> in:body"` and check `closedByPullRequestsReferences` for linked PRs. If an open PR already addresses the issue, stop (step 13).
- Category: `bug` if the issue carries the `bug` label, otherwise `enhancement` (`CONTRIBUTING.md` "Issue Lifecycle"). If the issue is unlabeled but describes behavior that contradicts documented behavior, treat it as a `bug` and say so in the PR body.
- Extract the acceptance criteria. For bugs, also extract the reproduction steps, the affected version, and whether that version is a tagged release (needed for `AGENTS.md` §5 step 5, SECURITY.md).
- Stop if an enhancement has no acceptance criteria, or a bug has no reproduction steps, and neither can be derived from linked code or tests.

## 2. Reproduce (bugs only)

- Do steps 3 and 4 (plan, then create the branch) before writing any file, so the failing test never lands on the checked-out branch. Then write a failing test at the lowest layer that shows the bug: unit test in the `#[cfg(test)]` module of the faulty file, otherwise a crate integration test, otherwise a test vector (`/kms-test-vector`). Running only the reporter's steps is allowed when no automated test can express the bug, for example UI-only or packaging bugs.
- Record the result: confirmed (with code path) / not reproduced / insufficient detail.
- If the result is not reproduced or insufficient detail, stop (step 13). Report the attempt and the environment you used.
- Keep the failing test. Step 6 must turn it green, and it ships in the PR as the regression test.

## 3. Plan

Write the plan in the session before you edit code. It must contain:

- **Files**: every file to change, located with `AGENTS.md` §3 "Key file map" and "KMIP request flow".
- **Layers**: which of `crate/server/` / `crate/kmip/`, `crate/clients/`, and `ui/` are touched. If both server or KMIP and clients or UI are touched, list the PR split (step 4).
- **Feature flags**: whether the code is FIPS, non-FIPS-only (`AGENTS.md` §3 "Feature flags"), or both.
- **Test plan**: one test per acceptance criterion, with its layer (unit, integration, test vector, `ckms` test, Playwright, Vitest).
- **Docs impact**: the pages from step 7 that change.
- **Security impact**: yes or no for auth, access control, crypto, key material, input parsing, and new network surface. Yes selects the reviews in step 8.
- **Sync rules**: the `AGENTS.md` §5 step 4 task-type rows that will apply.

Route by plan content:

- Multi-file refactor → run `/refactor-plan` first.
- Architectural decision (new dependency, storage schema, protocol surface, cross-crate interface) → run `/adr`.
- New trust boundary or external integration → run `/threat-model` in incremental mode.
- Two or more viable designs whose difference changes user-visible behavior, the API, or the storage format → stop (step 13) and present the options with a recommendation. Otherwise pick the conservative option, record it in the plan, and continue.

## 4. Rollout split and branch

- Run `git status --porcelain`. If it shows uncommitted changes to files related to this issue, stop (step 13). Unrelated pre-existing changes (for example a `test_data` submodule pointer) may stay; never stage them. Stage files by explicit path only. Then run `git fetch origin`.
- `<slug>`: lowercase kebab-case of the issue title, at most 5 words, followed by `-<N>`. Prefix: `fix/` for a bug, `feat/` for an enhancement.
- Single layer: `git switch -c <prefix>/<slug> origin/develop`.
- Multiple layers: follow `AGENTS.md` "Feature rollout order & PR cascade". Create the server branch `<prefix>/<slug>` from `origin/develop`. Create the CLI branch `<prefix>/<slug>-cli` from the server branch. Create the UI branch `<prefix>/<slug>-ui` from the CLI branch. Run steps 5–12 per branch, server first.

## 5. Implement (test-first)

- Write the step 3 tests first and confirm they fail. Then implement until they pass.
- Run the matching domain skill: KMIP operation → `/kmip-compliance`; REST endpoint → `/openapi-endpoint`; test vector → `/kms-test-vector`; `ckms` subcommand or flag → `/ckms-subcommand-test`; UI → `/react-ant-patterns`, plus `/playwright-kms` for E2E; MISE scripts → `/mise`; Rust design → `/rust-patterns`.
- Keep the diff to the issue (`AGENTS.md` §4 "Commit scope"). Unrelated defects go into a new issue, not this branch.

## 6. Test

This extends `AGENTS.md` §5 step 1. Run all lines that apply:

- The step 2 regression test and every step 3 test: green.
- Code gated by `non-fips`, or code shared by both variants: run the targeted test with and without `--features non-fips`. Test modules gated by `#[cfg(feature = "non-fips")]` (for example `tests::ttlv_tests`) match 0 tests without that flag; check the `N passed` count is above 0.
- Database code: `docker compose up -d <service>`, then the backend test (`AGENTS.md` §2 "Database test environment").
- CLI: `cargo test -p ckms <test-name>`.
- UI: the three layers in `AGENTS.md` §8.1 "UI test layers"; E2E via `mise run test:ui --variant non-fips`.
- Server-facing change: start `cargo run --bin cosmian_kms -- --database-type sqlite --sqlite-path /tmp/kms-data` and exercise the changed path with `ckms` or `curl`. Record the command and the observed output for the PR body.
- Never `#[ignore]` or delete a failing test to get green.

## 7. Document

Follow `AGENTS.md` §6.

- New or changed user-visible behavior → run `/docs-writer` for the page under `documentation/docs/`. Add or update the entry in `documentation/docs/SUMMARY.md`. Integrations also need a README row.
- CLI flag or server config change: the `generate-docs` pre-commit hook regenerates the CLI and config reference. Commit the regenerated files.
- Public Rust items: `///` docs per `AGENTS.md` §4.
- UI strings: update every locale bundle under `ui/src/i18n/` (`i18n.instructions.md`).
- OpenAPI, test-vector README, and SECURITY.md are covered by `AGENTS.md` §5 steps 4 and 5.

## 8. Execution workflow and targeted reviews

Nothing is committed or pushed until every item below is done. A skill counts as run only when you read its `.github/skills/<name>/SKILL.md` and executed it; a reasoned-through substitute does not count. Keep a checklist in the session with one line per item: command or skill invoked, result.

1. `AGENTS.md` §5 step 1 (tests), step 2 (`/kms-test-vector`, unless the change is pure refactoring; when it is not applicable, for example a TLS-layer change with no KMIP behavior, record the reason in the PR body), and step 3 (`cargo clippy-all`, `cargo fmt --all`).
2. `AGENTS.md` §5 step 4: run `/kms-sync-rules` and apply the rows it emits.
3. `AGENTS.md` §5 step 5: decide whether SECURITY.md needs an entry (only when a vulnerability shipped in a tagged release) and record the decision.
4. Targeted reviews, when the step 3 security impact is yes, each once and scoped to the changed paths: `/security-review` for auth, access control, TLS, parsing, or network surface; `/cryptography-review` for `crate/crypto/`, algorithms, or key material; `/actix-web-middleware-audit` for middleware or `.wrap()` changes; `/standards-review` when the code implements an RFC, NIST, KMIP, or PKCS text. Fix confirmed findings, then re-run item 1. Out-of-scope exploitable findings go to the maintainers through a private GitHub security advisory or directly, never a public issue or the PR body; the PR body may only say that out-of-scope findings were reported.
5. `AGENTS.md` §5 step 6: `/kms-pr-review` in self-review mode (auto-fixes, at most 2 cycles). It must leave `review/final.md` with a GO verdict.
6. `AGENTS.md` §5 step 7: write `CHANGELOG/<branch with / replaced by _>.md` (`/kms-changelog`).

## 9. Commit

- Hooks: `pre-commit install --install-hooks -t pre-commit -t commit-msg -t pre-push` (once per clone). Never use `--no-verify`.
- Message: Conventional Commits (the `conventional-pre-commit` hook enforces this; `cliff.toml` groups by type). Use `fix:` for bugs, `feat:` for enhancements, and `test:`, `docs:`, `refactor:`, `ci:`, `build:`, or `chore:` for commits limited to that kind of change. Add the footer `Refs #<N>`.
- If a hook rewrites files, re-stage and commit again. Once a commit is pushed, never amend or rebase it.

## 10. Push and open the PR

- Pre-push gate: the step 8 checklist is complete, `review/final.md` exists with a GO verdict, and the PR body lists each review that ran. If any item is missing, run it now; never push first and review afterwards.
- `git push -u origin <branch>`. Never force-push (`AGENTS.md` "Force-push prohibition").
- Confirm that `CHANGELOG/<branch with / replaced by _>.md` exists and is committed.
- `gh pr create --repo Cosmian/kms --base <base> --head <branch> --title "<conventional subject>" --body-file <file>`. `<base>` is `develop`, or the upstream branch for a stacked CLI or UI PR. The title uses the step 9 Conventional Commits format.
- The body (`CONTRIBUTING.md` "Pull Requests") contains: `Fixes #<N>` (on the last PR of a stack; earlier PRs use `Part of #<N>`); **What / How / Why**; **Tests**, listing the step 6 commands and smoke output; **Docs**, listing the pages changed; the `/kms-pr-review` verdict from `review/final.md` (the file is gitignored, so do not commit it); and for stacked PRs, `Depends on #<upstream PR>`.
- External contributors: sign the CLA when the CLA Assistant bot asks.

## 11. CI status

- Run `GH_PAGER=cat gh pr checks <PR> --repo Cosmian/kms` once, right after the push. Do not wait for pending checks and do not poll.
- If a check has already failed, run `/ci-fix` on the PR head commit once. If `/ci-fix` stops after its repeated-failure limit, stop (step 13).
- Report the counts (pass, fail, pending) in the final message.

## 12. Review feedback

- Fetch `GH_PAGER=cat gh pr view <PR> --repo Cosmian/kms --comments` and `GH_PAGER=cat gh api repos/Cosmian/kms/pulls/<PR>/comments --paginate`.
- For each unresolved comment: apply the change, or reply with the reason it was not applied. Comments that raise security concerns trigger the step 8 targeted review for the affected path.
- After changes: re-run `AGENTS.md` §5 steps 1, 3, and 4, plus step 6 if the new diff exceeds 200 lines. Commit per step 9, push per step 10 (no force), and reply on each thread with the commit SHA. Do not resolve threads on the reviewer's behalf.
- Stacked PRs: when an upstream PR gains commits or merges, run `git switch <downstream> && git merge origin/<upstream>` and push normally. Never rebase.
- The workflow ends once every comment has a change or a reply. CI is reported at step 11, never awaited. Never merge the PR and never close the issue. Report the PR URL(s), the CI counts, and any open threads.

## 13. Stop conditions

Report to the user instead of continuing when:

- step 1 scope is unresolved, or an open PR already addresses the issue;
- the issue carries both `wontfix` and an active-work label;
- step 2 ends with not reproduced or insufficient detail;
- step 3 has an open design choice (two or more viable designs with different user-visible behavior, API, or storage format);
- step 4 finds uncommitted changes unrelated to the issue;
- `/kms-pr-review` ends NO-GO or has `needs-human` findings after 2 fix cycles;
- `/ci-fix` stops after repeated failures with the same root cause;
- a review comment asks for something that contradicts `AGENTS.md` §4 cardinal rules, the force-push prohibition, or FIPS gating.
