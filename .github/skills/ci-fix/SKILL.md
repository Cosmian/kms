---
name: ci-fix
description: 'Fix failures from a supplied GitHub run or the current commit, batch repairs, and verify the resulting runs. Use when CI is failing and needs repair.'
---

# CI Fix Loop

Repair CI for one commit at a time. Read failed jobs only, batch fixes, verify once, push once, then follow runs for the new commit. Do not scan historical branch runs by default.

> **Safety**: this skill commits and pushes code. It never force-pushes, changes branches other than the current one, merges, or deletes branches. Follow repository coding rules on each batch.

## Step 0 — Establish context

```bash
BRANCH=$(git branch --show-current)
HEAD_SHA=$(git rev-parse HEAD)
```

Confirm the branch is not `main` or `develop`. Stop and ask for confirmation before direct work on either protected branch.

## Step 1 — Select the run scope

- If the user supplied a run ID or URL, resolve it to `RUN_ID`, inspect only that run, and verify it matches the current branch before editing.
- Otherwise inspect runs for the current branch and exact `HEAD_SHA` only:

  ```bash
  GH_PAGER=cat gh run list \
    --repo Cosmian/kms \
    --branch "$BRANCH" \
    --commit "$HEAD_SHA" \
    --limit 20 \
    --json databaseId,name,status,conclusion,headSha
  ```

- Never fall back to failures from older commits on the branch. If no runs exist for `HEAD_SHA`, report that and stop; the user can provide a run ID/URL.
- For selected runs that are queued or in progress, use `gh run watch <RUN_ID> --repo Cosmian/kms --compact`. Do not poll the branch with a repeated `gh run list` loop.

## Step 2 — Identify failures

Inspect only the selected run set. If no run failed or timed out, report that the selected commit is green and stop.

Group failures with the same root cause. Keep separate causes distinct, but do not re-read duplicate job failures across runs.

## Step 3 — Read failed jobs only

List failed jobs and steps for each failed run:

```bash
GH_PAGER=cat gh run view "$RUN_ID" \
  --repo Cosmian/kms \
  --json jobs \
  --jq '.jobs[] | select(.conclusion == "failure" or .conclusion == "timed_out") | {databaseId, name, steps: [.steps[] | select(.conclusion == "failure" or .conclusion == "timed_out") | {name, number}]}'
```

Fetch logs only for those failed job IDs:

```bash
GH_PAGER=cat gh run view "$RUN_ID" --repo Cosmian/kms --job "$JOB_ID" --log-failed
```

Read the failing step and enough surrounding output to identify the root cause. If insufficient, expand logs for that same failed job only. Do not fetch successful-job or full-run logs by default; avoid truncation that could hide the first error.

## Step 4 — Categorize

When `omp-jev-tools` is installed (OMP only — not available in VS Code
Copilot Chat, Copilot CLI, or Copilot Cloud Agent), classify failures the
table below cannot match with `jev_judge` in one batched call: one `noul`
question per unmatched failure, `instructions: "Is this failure flaky or
infrastructure-related rather than a real code defect?"`. Treat `noul > 0.7`
as flaky, `noul < 0.3` as a real defect, and anything between as
undetermined — undetermined failures, and every failure the table already
matches, still go through the table below. Without the tool, use the table
for every failure.

| Category | Indicators | Fix strategy |
| ---------- | ----------- | -------------- |
| **Formatting** | `error: would reformat` / `cargo fmt` / `rustfmt` | `cargo fmt --all` |
| **Clippy warning** | `error[clippy::...]` / `-D warnings` | Fix lint, then required Clippy verification |
| **Compile error** | `error[E...]` / `could not compile` | Read error, fix source |
| **Test failure** | `test ... FAILED` / assertion / panic | Read failing test output, fix logic |
| **Dependency audit** | `cargo deny` / `cargo audit` / `cargo machete` | Upgrade vulnerable deps; remove unused deps; use only justified exceptions |
| **Nix hash mismatch** | `hash mismatch` / `got: sha256-` | Update the matching expected hash from the failed job |
| **Docker/packaging** | packaging-job failure | Inspect the failing Docker/package path only |
| **Flaky test** | intermittent failure | Re-run the affected test; investigate if repeatable |

Fix fast deterministic failures (formatting/Clippy) first when they block diagnosis of later failures.

## Step 5 — Batch fixes and verify

Inspect only files implicated by the failed steps. Apply all confirmed fixes for the selected commit as one repair batch; do not commit/push once per category.

Use the narrowest relevant verification for each fix:

- Rust source change: run `cargo clippy-all`, `cargo fmt --all`, and the targeted test(s) for changed behavior once after the batch. These required project checks are not skipped; avoid rerunning them after each individual hunk.
- Nix hash-only change: verify the matching hash; do not run unrelated Rust tests.
- Workflow, shell, Docker, or packaging change: run the failing job's relevant local check where available.
- Dependency audit: inspect existing `deny.toml` exceptions; upgrade affected crates or use only a justified, time-limited exception.
- `cargo machete`: remove confirmed unused dependencies after checking conditional and target-specific usage.

```bash
# Example: targeted behavioral verification
cargo test -p <affected_crate> <test_name>
```

For Nix hash mismatches, either update `nix/expected-hashes/` from the failed log or run `mise run release:update-hashes <failed-job-link>`.

## Step 6 — Commit and push

After the batch passes required local checks, stage only the fix hunks and make one conventional commit for this repair batch:

```bash
git add -p
git commit -m "fix(<scope>): <description>"
git push origin "$BRANCH"
```

- Use `fix(fmt):` for formatting-only changes, `fix(clippy):` for lint-only changes, `fix(ci):` for workflow/hash/packaging fixes, or `fix(<crate>):` for source/test fixes.
- Never use `--no-verify` or any force-push option.

## Step 7 — Follow the new commit

After pushing, set `HEAD_SHA=$(git rev-parse HEAD)` and return to Step 1. Query only runs for this new SHA.
If GitHub has not registered a run, wait once briefly and query that SHA again; if still absent, report it as pending instead of polling indefinitely.

**Loop termination:**

- **Stop** when all selected runs for the current SHA succeed.
- **Continue** on a failure for that SHA; inspect failed jobs only.
- **Abort and report** after the same failure category recurs three times without a distinct fix.

## Step 8 — Final report

Report only the selected commit's CI runs:

```markdown
## CI Fix Summary — <branch> — <head SHA>

| Run | Workflow | Status |
|-----|----------|--------|
| <id> | <workflow> | ✅ |

### Fixes applied

| Commit | Category | Description |
|--------|----------|-------------|
| <sha> | <category> | <description> |

### Iterations: <N>
```
