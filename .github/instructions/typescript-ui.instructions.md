---
name: 'TypeScript Web UI'
description: 'React 19 + Ant Design 5 + Tailwind 4 conventions for the KMS Web UI'
applyTo: 'ui/src/**/*.{ts,tsx}'
---

# Web UI conventions

## Stack

- **React 19** with functional components and hooks only (no class components).
- **Vite 7** for bundling — use `import.meta.env` for environment variables.
- **Ant Design 5** for UI components — prefer AntD components over custom implementations.
- **Tailwind CSS 4** for utility styling — no inline `style={}` props.
- **pnpm** as package manager (not npm or yarn).

## FIPS guard pattern

Non-FIPS features (PQC, Covercrypt, AES-XTS) must be wrapped with a FIPS detection guard:

```tsx
{!isFips && <NonFipsFeatureComponent />}
```

Never expose non-FIPS algorithms in the UI when running in FIPS mode.

## TypeScript strictness

- **No `any` type** — use proper interfaces, generics, or `unknown` with type guards.
- Enable all strict checks (`strict: true` in `tsconfig.json`).
- Prefer `interface` over `type` for object shapes.

## Testing attributes

- Add `data-testid` on **every interactive element** (buttons, inputs, selects, links).
- Format: `data-testid="feature-action"` (e.g., `data-testid="symmetric-create-key"`).

## WASM integration

- KMS client logic comes from `cosmian_kms_client_wasm` (compiled from `crate/clients/wasm/`).
- WASM module is loaded asynchronously — handle loading states.

## Actions structure

`ui/src/actions/` contains 14 feature modules mapping to KMIP operation groups:

```text
Access/ Attributes/ Certificates/ CloudProviders/ Covercrypt/ EC/
FPE/ Keys/ MAC/ Objects/ PQC/ RSA/ Symmetric/ Tokenize/
```

> For deeper guidance on patterns and component structure, run `/react-ant-patterns`.
