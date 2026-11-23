---
name: playwright-kms
description: 'Create Playwright E2E tests for the KMS Web UI following project conventions: data-testid, Ant Design Select helpers, regex assertions, FIPS skips. Use when adding E2E tests.'
---

# Playwright KMS Test Generator

Create Playwright E2E tests for the KMS Web UI following the project's established conventions.

## When to Use

- Adding E2E coverage for a new UI feature
- Updating tests after a UI component change
- Converting manual test scenarios into automated E2E tests

## Project E2E Conventions

**Test location**: `ui/tests/e2e/`
**Config**: `ui/playwright.config.ts`
**Runner**: `cd ui && CI=true PLAYWRIGHT_BASE_URL="http://127.0.0.1:5173" pnpm run test:e2e`
**Timeouts and workers**: See [playwright.config.ts](../../../ui/playwright.config.ts), or [playwright.auth.config.ts](../../../ui/playwright.auth.config.ts) for auth tests.

## Step 1 — Understand the Feature

Read the existing spec files most similar to the new test:

```bash
ls ui/tests/e2e/
```

Read the helpers file — it contains Ant Design-specific utilities you must reuse:

```bash
cat ui/tests/e2e/helpers.ts
```

Read the relevant UI action component:

```bash
ls ui/src/actions/
```

## Step 2 — Test File Structure

Name the file `ui/tests/e2e/<feature>.spec.ts`. Start with one `test(...)`: navigate with `gotoAndWait`, exercise the feature, and assert the result. Cover relevant rejection paths separately. Use the closest existing spec as a template; see [sym-key-flow.spec.ts](../../../ui/tests/e2e/sym-key-flow.spec.ts) for form submission and result assertions.

## Step 3 — Element Selection Rules

**Always use `data-testid` attributes.** Never select by CSS class, text content, or DOM structure.

```typescript
// ✅ Correct
await page.locator('[data-testid="create-key-button"]').click()
await page.locator('[data-testid="key-uid-input"]').fill('my-key-id')

// ❌ Wrong — brittle
await page.locator('.ant-btn-primary').click()
await page.locator('button:has-text("Create")').click()
```

If the UI component doesn't have `data-testid`, add it to the component first (in `ui/src/actions/<Module>/`).

## Step 4 — Ant Design Select Portals

Ant Design `<Select>` dropdowns render in `document.body`, not in the component tree. **Always use the helpers from `helpers.ts`**:

```typescript
import { selectOption, selectOptionById, selectMultipleOptions } from './helpers'

// ✅ By data-testid (pass the bare testid string, not a CSS selector)
await selectOption(page, 'ec-curve-select', 'NIST P-256')

// ✅ By CSS selector (e.g. Form.Item id) or multi-select
await selectOptionById(page, '#keyFormat', 'json-ttlv')
await selectMultipleOptions(page, '#keyUsage', ['Encrypt', 'Decrypt'])

// ❌ Wrong — native <select> helper fails on Ant Design portal dropdowns
await page.locator('[data-testid="ec-curve-select"]').selectOption('NIST P-256')
```

## Step 5 — Assertions

**Use regex-based `toHaveText()`** — Playwright's `toHaveText` does not support an `exact` option for partial matches.

```typescript
// ✅ Correct — regex for partial match
await expect(page.locator('[data-testid="result-message"]')).toHaveText(/Key created successfully/)
await expect(page.locator('[data-testid="key-uid"]')).toHaveText(/[0-9a-f-]{36}/)

// ✅ Correct — exact string when you know the full content
await expect(page.locator('[data-testid="error-message"]')).toHaveText('Permission denied')

// ❌ Avoid — .textContent() requires manual assertions
const text = await page.locator('[data-testid="result"]').textContent()
expect(text).toContain('success')
```

## Step 6 — FIPS / Non-FIPS Skipping

```typescript
const FIPS_MODE = process.env.PLAYWRIGHT_FIPS_MODE === 'true'

// Skip entire test in FIPS mode
test('Covercrypt encrypt', async ({ page }) => {
  test.skip(FIPS_MODE, 'Covercrypt is not available in FIPS mode')
  // ...
})

// Or skip a describe block
test.describe('Non-FIPS algorithms', () => {
  test.skip(FIPS_MODE, 'These tests require non-FIPS mode')
  // ...
})
```

## Step 7 — WASM-Backed Forms

Wait for the form control the test needs to be ready before submitting. Prefer the existing readiness and submission helpers in [helpers.ts](../../../ui/tests/e2e/helpers.ts). There is no `window.wasmModule` global.

## Step 8 — Update E2E README

After creating the test file, update `ui/tests/e2e/README.md`:

- Add the new spec file to the coverage table
- Add a row to the FIPS-skip table if applicable
