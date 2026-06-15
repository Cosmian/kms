---
agent: agent
description: 'Plan a multi-file Rust refactor safely: investigate → plan → confirm → implement. Use: /refactor-plan'
---

# Refactor Plan

Create a detailed, safe plan before making any code changes in this Rust codebase.

## Instructions

1. **Do not edit files** while preparing the plan.
2. **Search the codebase** to understand the current state. Read enough implementation, tests, config, and docs to make the plan specific to this repository.
3. **Identify affected files**, ownership boundaries, dependencies, and likely hidden coupling.
4. **Plan changes in safe sequence**: contracts and types first → implementations → callers → tests → cleanup.
5. **Include verification steps** between phases using `cargo` commands.
6. **Include rollback steps** for the riskiest phases.
7. **Output the complete plan** using the format below.
8. **Stop after the plan** and ask for confirmation before implementing. If the user already said to implement, still produce the plan first and wait for confirmation — unless they explicitly said "continue without review".

If the request is too ambiguous to plan safely, ask concise clarifying questions instead of editing files.

## Verification Commands for This Repo

Use these at each phase checkpoint:

```bash
cargo clippy-all                        # zero warnings required
cargo fmt --all                         # formatting
cargo test -p <crate>                   # targeted test (preferred)
cargo test-fips                         # full FIPS test suite (only if needed)
cargo test-non-fips                     # full non-FIPS suite (only if needed)
```

Use `cargo test -p <crate> <test_name>` to run the narrowest scope first.

## Output Format

```markdown
## Refactor Plan: [title]

### Current State
[How things work now — be specific to this codebase]

### Target State
[How things will work after — measurable outcome]

### Affected Files
| File | Change Type | Dependencies |
|------|-------------|--------------|
| `crate/foo/src/bar.rs` | modify | blocks `baz.rs`, blocked by `qux.rs` |

### Execution Plan

#### Phase 1: Types and Traits
- [ ] Step 1.1: [action] in `crate/foo/src/bar.rs`
- [ ] Verify: `cargo clippy -p foo` passes

#### Phase 2: Implementations
- [ ] Step 2.1: [action] in `crate/foo/src/impl.rs`
- [ ] Verify: `cargo test -p foo test_name`

#### Phase 3: Callers
- [ ] Step 3.1: Update callers in `crate/server/src/...`
- [ ] Verify: `cargo build --workspace`

#### Phase 4: Tests
- [ ] Step 4.1: Update unit tests
- [ ] Verify: `cargo test -p foo`

#### Phase 5: Cleanup
- [ ] Remove deprecated code
- [ ] Run `cargo fmt --all` and `cargo clippy-all`
- [ ] Final verify: `git diff --stat` — every hunk explainable by the task

### Rollback Plan
If Phase N fails:
1. `git checkout crate/foo/src/bar.rs` — restore original
2. `git stash` — save partial work for inspection

### Risks
- [Potential issue]: [mitigation]
- Trait object overhead: prefer generics if the type set is closed
- Public API change: run `rg "fn_name" --type rust` across workspace before deleting
```

After the plan, ask: **"Shall I proceed with Phase 1?"**
