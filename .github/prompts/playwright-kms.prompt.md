---
agent: agent
description: 'Create Playwright E2E tests for the KMS Web UI following project conventions: data-testid, Ant Design Select helpers, regex assertions, FIPS skips. Use: /playwright-kms'
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
**Timeout budget**: 60 seconds per test (CI runs 10 parallel workers against one KMS server)

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

Name the file `ui/tests/e2e/<feature>.spec.ts`. Follow this structure:

```typescript
import { test, expect } from '@playwright/test'
import { selectAntOption, waitForKmsResponse } from './helpers'

// Skip non-FIPS tests in FIPS mode
const FIPS_MODE = process.env.FIPS_MODE === 'true'

test.describe('<Feature Name>', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/<route>')
    // Wait for the page to be ready
    await page.waitForSelector('[data-testid="<main-component>"]')
  })

  test('<should do something>', async ({ page }) => {
    // ...
  })

  test.skip(FIPS_MODE, '<non-fips feature> is not available in FIPS mode')
})
```

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
import { selectAntOption } from './helpers'

// ✅ Use the helper — it handles the portal rendering
await selectAntOption(page, '[data-testid="algorithm-select"]', 'AES-256-GCM')

// ❌ Wrong — select portal won't be found inside the component
await page.locator('[data-testid="algorithm-select"]').selectOption('AES-256-GCM')
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
const FIPS_MODE = process.env.FIPS_MODE === 'true'

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

## Step 7 — WASM Call Tests

When testing features that use WASM (e.g. key creation with specific TTLV structure):

```typescript
// Wait for WASM to initialize before interacting
await page.waitForFunction(() => typeof window.wasmModule !== 'undefined', { timeout: 10000 })

// Then proceed with the test
await page.locator('[data-testid="create-button"]').click()
```

## Step 8 — Update E2E README

After creating the test file, update `ui/tests/e2e/README.md`:

- Add the new spec file to the coverage table
- Add a row to the FIPS-skip table if applicable

## Example: Full Test Skeleton

```typescript
import { test, expect, Page } from '@playwright/test'
import { selectAntOption } from './helpers'

const FIPS_MODE = process.env.FIPS_MODE === 'true'

test.describe('Symmetric Key Creation', () => {
  async function navigateToCreateKey(page: Page) {
    await page.goto('/keys')
    await page.locator('[data-testid="create-symmetric-key-tab"]').click()
    await page.waitForSelector('[data-testid="symmetric-key-form"]')
  }

  test('creates an AES-256-GCM key', async ({ page }) => {
    await navigateToCreateKey(page)

    await page.locator('[data-testid="key-id-input"]').fill('test-key-001')
    await selectAntOption(page, '[data-testid="algorithm-select"]', 'AES')
    await selectAntOption(page, '[data-testid="key-length-select"]', '256')

    await page.locator('[data-testid="create-key-button"]').click()

    await expect(page.locator('[data-testid="success-banner"]')).toHaveText(
      /Key created successfully/
    )
    await expect(page.locator('[data-testid="created-key-uid"]')).toHaveText(
      /test-key-001/
    )
  })

  test('shows error for invalid key length', async ({ page }) => {
    await navigateToCreateKey(page)
    // ... negative test
  })
})
```
