---
name: 'GitHub Actions'
description: 'GitHub Actions workflow and composite action conventions for the Eviden KMS CI/CD'
applyTo: '.github/workflows/**, .github/actions/**'
---

# GitHub Actions conventions

## Workflow structure

- **Entry point**: All substantive CI logic runs through MISE:

  ```yaml
  - run: mise run [task] --variant [fips|non-fips]
  ```

- Keep workflow YAML thin — delegate heavy logic to MISE tasks, not inline `run:` blocks.
- Use reusable workflows (`.github/workflows/*.yml` with `workflow_call:`) to avoid duplication across jobs.

## Naming

- Use `kebab-case` for workflow file names and job IDs.
- Job names use `Title Case` for display clarity in the GitHub UI.
- Step names use imperative present tense: "Build server", "Run FIPS tests".

## Triggers

- Every workflow must declare explicit triggers (`on:`).
- Use `workflow_call:` for reusable workflows; `workflow_dispatch:` for manual runs.
- Limit `push:` triggers to protected branches or tag patterns to avoid wasted CI runs.

## Permissions

- Declare the minimum required `permissions:` at the job level, not workflow level:

  ```yaml
  permissions:
    contents: read
    packages: write  # only if needed
  ```

- Never use `permissions: write-all`.

## Secrets and environment variables

- Reference secrets via `${{ secrets.SECRET_NAME }}` — never hardcode values.
- Mask sensitive values in logs with `::add-mask::$VALUE` when echoing.
- Use `env:` at the step level for locally scoped variables.

## Caching and performance

- Cache Cargo registry and build artifacts using `actions/cache` with a key that includes the Rust toolchain version and `Cargo.lock` hash.
- Cache pnpm store for UI jobs.
- Set `CARGO_INCREMENTAL=0` in CI to reduce cache churn.

## Nix builds

All packaging and reproducible builds use Nix via the `setup-nix` composite action:

```yaml
- uses: ./.github/actions/setup-nix
```

See `nix.instructions.md` for vendor hash management.

## Composite actions (`.github/actions/`)

- Each composite action must have a descriptive `description:` in its `action.yml`.
- Use `inputs:` with `required: true/false` and `default:` where applicable.
- Composite action steps follow the same naming conventions as workflow steps.

## Conditionals

- Use `if:` conditions sparingly; prefer branch or tag filters in `on:`.
- When needed: `if: github.event_name == 'push' && startsWith(github.ref, 'refs/tags/')`.
- Avoid `continue-on-error: true` — fix the root cause instead.

## Timeouts

Set explicit `timeout-minutes:` on long-running jobs to prevent runaway runners:

```yaml
jobs:
  build:
    timeout-minutes: 60
```
