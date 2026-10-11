---
name: ci-dedupe
description: 'Audit GitHub Actions workflows for duplicated step sequences across jobs/files and recommend extracting local composite actions under .github/actions/ to simplify and factorize the YAML. Use when workflows grow repetitive, before adding a new job that copies an existing step block, or when asked to simplify/factorize GitHub workflows.'
---

# CI Action Deduplication (Composite Action Extraction)

Find repeated step blocks across `.github/workflows/*.yml`, check whether an existing `.github/actions/*` composite action already covers them, and recommend/extract new composite actions for blocks that don't.

## This Codebase's Existing Composite Actions

`.github/actions/<name>/action.yml`, `runs: using: composite`, invoked as `uses: ./.github/actions/<name>`:

- `cleanup-runner` — frees GH-hosted runner disk space (no inputs)
- `setup-nix` — installs Nix + warms the nix store (`extra-nix-config` input)
- `install-mise` — installs `mise` for Linux/macOS (no inputs)
- `docker-login-ghcr` — logs in to `ghcr.io` (`github-token` input)

## Step 1 — Measure First

```bash
# Find candidate duplicate step blocks: same `uses:`/`name:` repeated across files
rg -n "^\s*- (name:|uses:)" .github/workflows | sort | uniq -c | sort -rn | head -40

# Find every call site of each existing composite action (confirm reuse opportunities, not just dupes)
rg -n "uses: \./\.github/actions/" .github/workflows

# Spot workflows that hand-roll a step an existing composite action already covers,
# or repeat a third-party action block (e.g. docker/login-action, actions/checkout)
# with identical `with:` values across files
rg -n "uses: docker/login-action|uses: actions/checkout@v7" .github/workflows -A4
```

Classify every exact-duplicate block (3+ lines, byte-identical `with:` values except matrix/job-scoped variables) found in 2+ places:

- **Reuse candidate**: an existing `.github/actions/*` already implements this — replace the inline block with `uses: ./.github/actions/<name>`.
- **Extraction candidate**: no existing action covers it, and the block appears verbatim (or with only secrets/inputs varying) in **3 or more** call sites — propose a new `.github/actions/<name>/action.yml`.
- **Leave inline**: appears in <3 places, or the steps genuinely differ per call site (different `with:` values driven by real per-job logic, not copy-paste) — note it, don't extract.

## Step 2 — Apply Guardrails

1. **Secrets context is unavailable inside composite actions** ([actions/runner ADR 1144](https://github.com/actions/runner/blob/main/docs/adrs/1144-composite-actions.md)) — any `${{ secrets.X }}` used inside the extracted block MUST become a required composite-action `input:`, passed explicitly from each call site's `with:`. `github.*`/`env.*`/`matrix.*` contexts remain directly usable inside the composite action.
2. **Step-level `if:` also cannot read `secrets` directly** (not listed in the `jobs.<job_id>.steps.if` context-availability table in GitHub's Contexts reference) — if a step needs to branch on whether a secret is set, the calling job must mirror it into `env:` first (`env: { FOO: ${{ secrets.FOO }} }`) and test `env.FOO != ''`.
3. **Don't collapse blocks that look identical but diverge in intent** — e.g. two `docker/login-action` blocks targeting different registries (`ghcr.io` vs `docker.io`) are different concerns; extract them as separate composite actions, never merge into one parameterized action unless every call site already passes the registry as a variable today. Likewise, a multi-step preamble (e.g. checkout + optional cleanup + optional nix + mise) where call sites genuinely vary which steps/inputs they include is not a clean extraction target until those call sites converge.
4. **Preserve every required check and matrix leg** — extraction must not change job/step names relied on by branch protection, nor silently drop a step only some call sites had (diff the resulting step list per call site against the original).
5. **No behavior change** — the composite action's steps must be the exact original steps in the exact original order; this is a structural refactor, not a logic change.
6. **Local composite actions need the repo checked out first** — `uses: ./.github/actions/<name>` resolves from the workspace, so any call site that runs before `actions/checkout` (or in a job with no checkout, e.g. a manifest-only job) cannot use it. Leave those call sites inline, or add a checkout only if the job's behavior is otherwise unaffected.

## Step 3 — Propose Candidates

Rank by occurrence count × lines saved. For each candidate, state: exact call-site line ranges (file:line-line), the proposed composite action name/path, its `inputs:` (one row per secret/variable that was inline before), and the exact replacement step for every call site.

## Step 4 — Verify

- `python3 -c "import yaml,glob; [yaml.safe_load(open(f)) for f in glob.glob('.github/workflows/*.yml')+glob.glob('.github/actions/*/action.yml')]"` — every touched file still parses.
- `rg -n "<the original duplicated uses:/with: block>" .github/workflows` — zero remaining matches outside the new composite action's own `action.yml`.
- If `actionlint` is available on the host, run it; otherwise state static-only and that `actionlint` was not run.
- No live workflow run is required for a pure step-extraction (behavior-preserving) refactor; only run `gh workflow run <file> --ref <branch>` when the extraction changes conditionals/inputs beyond a literal step move.

## Required Output

1. **Reuse opportunities** — inline blocks that should become `uses: ./.github/actions/<existing>`.
2. **Extraction candidates** — ranked list of new composite actions to create, with occurrence count and exact call sites.
3. **Recommended minimal first step** — the single lowest-risk, highest-count-identical-block candidate to extract first.
4. **Not extracted** — blocks that looked similar but diverge in intent (Guardrail 3), left inline on purpose.
