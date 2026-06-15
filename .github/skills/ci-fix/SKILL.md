---
name: ci-fix
description: Fix CI failures in a loop until all GitHub workflow runs on the current branch are green. Use when CI is failing and needs automated repair.
---

# CI Fix Loop

Monitor the GitHub CI pipeline for the current branch, fix every failure, push
fixes, and repeat until all workflow runs pass.

> **Safety**: this skill commits and pushes code. It will not force-push, will
> not modify branches other than the current one, and will not merge or delete
> branches. It follows all cardinal coding rules on every fix attempt.

---

## Step 0 — Establish context

```bash
BRANCH=$(git branch --show-current)
echo "Branch: $BRANCH"
```

Confirm the branch is not `main` or `develop`. If it is, stop and ask the user
to confirm before proceeding — direct pushes to protected branches require
explicit approval.

---

## Step 1 — Get current CI status

```bash
GH_PAGER=cat gh run list \
  --repo Cosmian/kms \
  --branch "$BRANCH" \
  --limit 20 \
  --json databaseId,name,status,conclusion,headBranch,headSha \
  --jq '.[] | select(.status == "completed" or .status == "in_progress" or .status == "queued")'
```

Wait for all runs to reach `completed` status before proceeding. If any run is
`in_progress` or `queued`, poll every 60 seconds:

```bash
# Poll loop — wait for all runs on the branch to complete
while GH_PAGER=cat gh run list \
    --repo Cosmian/kms \
    --branch "$BRANCH" \
    --limit 20 \
    --json status \
    --jq '.[].status' \
    | grep -qE "in_progress|queued|waiting|requested"; do
  echo "CI still running — waiting 60s..."
  sleep 60
done
echo "All runs completed."
```

---

## Step 2 — Check for failures

```bash
GH_PAGER=cat gh run list \
  --repo Cosmian/kms \
  --branch "$BRANCH" \
  --limit 20 \
  --json databaseId,name,conclusion \
  --jq '.[] | select(.conclusion == "failure" or .conclusion == "timed_out")'
```

If **no failures** → print "✅ All CI runs are green. Nothing to fix." and stop.

If failures exist → collect the run IDs and continue to Step 3.

---

## Step 3 — Fetch failure logs

For each failed run ID, retrieve the failed jobs and their logs:

```bash
# List failed jobs in a run
GH_PAGER=cat gh run view <RUN_ID> \
  --repo Cosmian/kms \
  --json jobs \
  --jq '.jobs[] | select(.conclusion == "failure") | {name: .name, steps: [.steps[] | select(.conclusion == "failure")]}'

# Fetch the full log for a failed run
GH_PAGER=cat gh run view <RUN_ID> --repo Cosmian/kms --log-failed 2>&1 | head -300
```

Repeat for each failed run. Collect all error messages.

---

## Step 4 — Categorize and triage failures

Classify each failure into one of these categories (in priority order):

| Category | Indicators | Fix strategy |
|----------|-----------|--------------|
| **Formatting** | `error: would reformat` / `cargo fmt` / `rustfmt` | `cargo fmt --all` |
| **Clippy warning** | `error[clippy::...]` / `-D warnings` | Fix lint, then `cargo clippy-all` locally |
| **Compile error** | `error[E...]` / `could not compile` | Read error, fix source |
| **Test failure** | `test ... FAILED` / `assertion failed` / `panicked` | Read test output, fix logic |
| **Dependency audit** | `cargo deny` / `cargo machete` / `cargo audit` | Update `Cargo.toml`, add `deny.toml` exception if justified |
| **Nix hash mismatch** | `hash mismatch` / `got: sha256-` | Update `nix/expected-hashes/` with value from log |
| **Docker/packaging** | build failures in packaging jobs | Check `Dockerfile`, packaging scripts |
| **Flaky test** | intermittent, not reproducible locally | Re-run first; if persistent, investigate |

Fix **Formatting** and **Clippy** first — they are fastest and unblock other
failure diagnosis.

---

## Step 5 — Fix cycle

For each failure category, apply the appropriate fix:

### Formatting

```bash
cargo fmt --all
```

### Clippy

```bash
cargo clippy-all 2>&1
# Fix each warning. Follow the decision tree:
# 1. Can it be fixed? → fix it
# 2. Cannot be fixed, documented reason → add #[allow(clippy::X)] with inline comment
# 3. Undecided → report to user before suppressing
```

### Compile error / Test failure

- Read the exact error from the log
- Locate the file using the path in the error message
- Read the surrounding code (at least 20 lines of context)
- Apply the minimal fix required
- Run locally to verify:

  ```bash
  cargo test -p <crate> <test_name> 2>&1
  ```

### Nix hash mismatch

- Extract the correct hash from the log line: `got: sha256-XXXX`
- Update the matching file in `nix/expected-hashes/`

### Dependency audit (`cargo deny`)

- Read `deny.toml` for existing exceptions
- If a new CVE was added to the advisory DB, update `Cargo.toml` to upgrade the
  affected crate, or add a time-limited `deny.toml` ignore entry with a comment

### Dependency unused (`cargo machete`)

- Remove unused `[dev-dependencies]` and `[dependencies]` entries from
  `Cargo.toml`

**After every fix, verify locally before committing:**

```bash
cargo clippy-all
cargo fmt --all
cargo test -p <affected_crate> 2>&1 | tail -20
```

---

## Step 6 — Commit and push

Group all fixes into a single conventional commit per failure category:

```bash
git add -p   # review each hunk — never commit unrelated changes
git commit -m "fix(<scope>): <description>"
git push origin "$BRANCH"
```

- Use `fix(fmt):` for formatting-only commits
- Use `fix(clippy):` for lint-only commits
- Use `fix(ci):` for Nix hash or packaging fixes
- Use `fix(<crate>):` for test or compile fixes
- Never use `--no-verify` — pre-commit hooks must pass

---

## Step 7 — Wait for CI and loop

After pushing, return to Step 1 and wait for the new runs to complete.

```bash
echo "Pushed fixes. Waiting for CI to start..."
sleep 30  # give GitHub time to register the push
# Then re-enter the Step 1 polling loop
```

**Loop termination conditions:**

- ✅ **Stop**: all runs on the branch have `conclusion == "success"`
- 🔁 **Continue**: any run has `conclusion == "failure"` — go back to Step 3
- 🛑 **Abort and report**: the same failure category appears 3 times in a row
  without a new distinct fix being applied — this indicates a systematic
  problem beyond simple code fixes. Report to the user:
  > "CI loop aborted after 3 attempts on the same failure: `<category>: <message>`.
  > Manual investigation required."

---

## Step 8 — Final report

When all CI runs are green, produce:

```markdown
## CI Fix Summary — <branch>

| Run | Workflow | Status |
|-----|----------|--------|
| <id> | CI | ✅ |
| <id> | Packaging | ✅ |

### Fixes applied

| Commit | Category | Description |
|--------|----------|-------------|
| <sha> | fmt | Reformatted 3 files |
| <sha> | clippy | Fixed unwrap in `crate/server/src/core/operations/get.rs:42` |

### Iterations: <N>
```
