---
name: 'Test task README'
description: 'Every folder under .mise/tasks/test/ has a README.md with Mermaid diagrams and a table of the .mise/scripts/test/ scripts it calls; keep it in sync on every change'
applyTo: '.mise/tasks/test/**, .mise/scripts/test/**'
---

# Test task README (per group folder)

Every group folder `.mise/tasks/test/<group>/` (`cloud`, `db`, `hsm`, `interop`, `k8s`, `obs`,
`pkcs11`, `pkg`, `pki`, `spire`, `ui`, and any new one) MUST have a `README.md` that explains what
its tasks do. The model is [`.mise/tasks/test/interop/README.md`](../../.mise/tasks/test/interop/README.md).
The cross-group overview stays in `.mise/tasks/test/README.md`; the group README holds the detail.

This is a standing rule, not a one-off. Apply it **automatically, in the same change**, whenever you:

- add, rename, delete or change the behaviour, flags, images or prerequisites of a task file in a group folder;
- add, rename, delete or change the behaviour of a script under `.mise/scripts/test/` (including its subfolders) that a task calls;
- change a `.mise/lib/*.sh` helper in a way that alters what those tasks do.

Find the groups affected with `grep -rln "<script name>" .mise/tasks/test`. Do not wait to be asked.

## Required content, in this order

1. **Intro** - one paragraph: what the group tests, the task id pattern `test:<group>:<file>`, the shared flags, and which tasks skip and why.
2. **Task topology** - a Mermaid `flowchart` of `test:<group>` (the `_default` leaf) and its leaves, showing which leaf is a thin wrapper around a script and which is self-contained.
3. **Common lifecycle** - a Mermaid `sequenceDiagram` of the steps every leaf shares (build, start the KMS, run the client, assert, clean up). Skip it only if the group has a single leaf.
4. **One diagram per family** - group leaves that share a topology (for example "database TDE clients", "protocol interop") into one `flowchart`, with the component under test, the transport and the KMS. Add two or three bullets for the facts a diagram cannot show (sad path, skip conditions, required secrets).
5. **Scripts table** - a Markdown table of EVERY script called from `.mise/scripts/test/` by a task of the group. Columns: `Script`, `Called by`, `What it does`, `External needs`. Include helper scripts those scripts load. List scripts that live elsewhere under `.mise/scripts/` (patches, generators) in a sentence below the table. List shared `.mise/lib/` libraries in one sentence.
6. **Keeping this page current** - the closing section linking to this instruction file.

## Rules

- Facts come from the code, not from memory: read the task file and the script before writing. Do not describe behaviour you did not see.
- A script called by tasks of two groups appears in both tables.
- Follow `mermaid.instructions.md`: `<br/>` for line breaks, no list markers or code spans in labels, descriptive ids (never `end`, `off`, `loop`, `note`), quote labels containing punctuation.
- Validate each `sequenceDiagram` with the headless parser from `mermaid.instructions.md`. Flowcharts cannot be parsed headlessly; check their labels by hand and say so in the report.
- Do not duplicate prose that already lives in `.mise/tasks/test/README.md`; link to it.
- Run `/kms-docs-verify` claims for flags and env vars you mention (`--variant`, `--link`, `EDB_SUBSCRIPTION_TOKEN`, image names).
