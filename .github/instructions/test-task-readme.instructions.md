---
name: 'Test task README'
description: 'Keep the single .mise/tasks/test/README.md (with its Mermaid diagrams) in sync on every test task or test script change'
applyTo: '.mise/tasks/test/**, .mise/scripts/test/**'
---

# Test task README (`.mise/tasks/test/README.md`)

`.mise/tasks/test/README.md` is the ONLY documentation page for the test tasks. There is no
per-group README: never create `.mise/tasks/test/<group>/README.md`.

This is a standing rule, not a one-off. Apply it **automatically, in the same change**, whenever you:

- add, rename, delete or change the behaviour, flags, images or prerequisites of a task file under `.mise/tasks/test/`;
- add, rename, delete or change the behaviour of a script under `.mise/scripts/test/` (including its subfolders) that a task calls;
- change a `.mise/lib/*.sh` helper in a way that alters what those tasks do.

Find the affected entries with `grep -n "<task or script name>" .mise/tasks/test/README.md`. Do not wait to be asked.

## What to update

- The entry of every affected task (`### \`test:<group>:<leaf>\``): description, flags, prerequisites, scripts it calls (linked).
- **Mermaid diagrams**: every task entry keeps its diagrams in step with the code. A new task gets a `graph` (architecture) and/or a `sequenceDiagram` (steps: build, start the KMS, run the client, assert, clean up). A changed topology (a component added or removed, such as a proxy, a verifier or a new client) changes the diagram in the same change. A removed task loses its diagrams.
- The overview tables and task lists at the top of the file, when a task is added, renamed or removed.

## Rules

- Facts come from the code, not from memory: read the task file and the script before writing. Do not describe behaviour you did not see.
- Follow `mermaid.instructions.md`: `<br/>` for line breaks, no list markers or code spans in labels, descriptive ids (never `end`, `off`, `loop`, `note`), quote labels containing punctuation.
- Validate each `sequenceDiagram` with the headless parser from `mermaid.instructions.md`. Flowcharts cannot be parsed headlessly; check their labels by hand and say so in the report.
- Run `/kms-docs-verify` claims for flags and env vars you mention (`--variant`, `--link`, image names).
