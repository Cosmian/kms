---
name: 'Playwright E2E Tests'
description: 'E2E test conventions using Playwright for the KMS Web UI'
applyTo: 'ui/tests/e2e/**/*.ts'
---

# Playwright E2E test rules

## Selectors

- **Always** use `data-testid` selectors: `page.getByTestId('feature-action')`.
- **Never** use CSS class selectors, XPath, or raw text selectors — they break on styling or i18n changes.
- For headings/labels where `data-testid` isn't practical, use `page.getByRole()` or `page.getByText()` with regex.

## Ant Design Select components

Ant Design Select renders options in a portal (outside the component DOM). Use the helpers from `ui/tests/e2e/helpers.ts`:

```typescript
import { selectAntOption } from './helpers';
await selectAntOption(page, 'testid-of-select', 'Option Label');
```

## FIPS mode handling

- Tests for non-FIPS features (PQC, Covercrypt, AES-XTS) must be skipped in FIPS mode:

```typescript
test.skip(isFips, 'Non-FIPS feature — skipped in FIPS mode');
```

## Test structure

- One `*.spec.ts` file per feature area (matching `ui/src/actions/` modules).
- Use `test.describe()` to group related scenarios.
- Use `test.beforeEach()` for shared setup (login, navigation).

## Documentation

- Update `ui/tests/e2e/README.md` whenever adding or removing test files.

> Rule 4.16 of `/kms-sync-rules`.

## Running tests

```bash
cd ui && CI=true PLAYWRIGHT_BASE_URL="http://127.0.0.1:5173" pnpm run test:e2e
# Or via nix:
mise run test:ui --variant non-fips
```

> For detailed patterns and examples, run `/playwright-kms`.
