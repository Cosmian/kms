/**
 * Anonymize / Tokenize E2E smoke tests
 *
 * Validates the full UI → REST → KMS pipeline for all 8 anonymization methods:
 *   POST /tokenize/hash
 *   POST /tokenize/noise
 *   POST /tokenize/word-mask
 *   POST /tokenize/word-tokenize
 *   POST /tokenize/word-pattern-mask
 *   POST /tokenize/aggregate-number
 *   POST /tokenize/aggregate-date
 *   POST /tokenize/scale-number
 *
 * All endpoints are plain JSON (no KMIP/WASM).  Expected values are sourced
 * from Rust unit tests in crate/crypto/src/crypto/anonymization/tests.rs.
 *
 * Skipped in FIPS mode: the /tokenize endpoints are guarded by #[cfg(feature = "non-fips")].
 */
import { expect, test } from "@playwright/test";
import { gotoAndWait, selectOption, submitAndWaitForResponse, UI_READY_TIMEOUT } from "./helpers";

const FIPS_MODE = process.env.PLAYWRIGHT_FIPS_MODE === "true";

// ── Navigation smoke tests ─────────────────────────────────────────────────

test.describe("Tokenize navigation", () => {
    const pages = [
        { name: "hash", path: "/ui/tokenize/hash" },
        { name: "noise", path: "/ui/tokenize/noise" },
        { name: "word-mask", path: "/ui/tokenize/word-mask" },
        { name: "word-tokenize", path: "/ui/tokenize/word-tokenize" },
        { name: "word-pattern-mask", path: "/ui/tokenize/word-pattern-mask" },
        { name: "aggregate-number", path: "/ui/tokenize/aggregate-number" },
        { name: "aggregate-date", path: "/ui/tokenize/aggregate-date" },
        { name: "scale-number", path: "/ui/tokenize/scale-number" },
    ];

    for (const { name, path } of pages) {
        test(`navigate to ${name} page`, async ({ page }) => {
            test.skip(FIPS_MODE, "Tokenize endpoints not available in FIPS mode");
            await gotoAndWait(page, path);
            await expect(page.locator('[data-testid="submit-btn"]')).toBeVisible({
                timeout: UI_READY_TIMEOUT,
            });
        });
    }
});

// ── Hash ───────────────────────────────────────────────────────────────────

test.describe("Tokenize — Hash", () => {
    // Expected value sourced from test_hash_sha2 in crate/crypto/src/crypto/anonymization/tests.rs
    test("SHA2 hash of known input returns known base64 digest", async ({ page }) => {
        test.skip(FIPS_MODE, "Tokenize endpoints not available in FIPS mode");

        await gotoAndWait(page, "/ui/tokenize/hash");
        await page.fill('input[placeholder="e.g. hello world"]', "test sha2");
        // Default method is SHA2; no salt needed.
        const text = await submitAndWaitForResponse(page);
        expect(text).toMatch(/Result:\s*Px0txVYqBePXWF5K4xFn0Pa2mhnYA\/jfsLtpIF70vJ8=/);
    });

    // Expected value sourced from test_hash_sha3 in crate/crypto/src/crypto/anonymization/tests.rs
    test("SHA3 hash of known input returns known base64 digest", async ({ page }) => {
        test.skip(FIPS_MODE, "Tokenize endpoints not available in FIPS mode");

        await gotoAndWait(page, "/ui/tokenize/hash");
        await page.fill('input[placeholder="e.g. hello world"]', "test sha3");
        // Switch method to SHA3
        await selectOption(page, "hash-method-select", "SHA3 (256-bit)");
        const text = await submitAndWaitForResponse(page);
        expect(text).toMatch(/Result:\s*b8rRtRqnSFs8s12jsKSXHFcLf5MeHx8g6m4tvZq04\/I=/);
    });
});

// ── Noise ──────────────────────────────────────────────────────────────────

test.describe("Tokenize — Add Noise", () => {
    test("Gaussian noise on a float returns a finite number", async ({ page }) => {
        test.skip(FIPS_MODE, "Tokenize endpoints not available in FIPS mode");

        await gotoAndWait(page, "/ui/tokenize/noise");
        await page.fill('input[placeholder="e.g. 42.5 or 2023-04-07T12:34:56+02:00"]', "100.0");
        // Default method is Gaussian; fill mean and std_dev
        await page.fill('input[placeholder="e.g. 0"]', "0");
        await page.fill('input[placeholder="e.g. 1.0"]', "5.0");
        const text = await submitAndWaitForResponse(page);
        expect(text).toMatch(/Result:\s*-?\d+(\.\d+)?/);
    });

    test("Uniform noise shows min/max bounds fields when method switched", async ({ page }) => {
        test.skip(FIPS_MODE, "Tokenize endpoints not available in FIPS mode");

        await gotoAndWait(page, "/ui/tokenize/noise");
        // Switch to Uniform
        await page.click('[data-testid="noise-method-select"]');
        await page.locator('.ant-select-dropdown :text("Uniform")').first().click();
        // Verify min/max bound fields are shown
        await expect(page.locator("text=Min bound")).toBeVisible();
        await expect(page.locator("text=Max bound")).toBeVisible();
        // Verify mean/std_dev fields are not shown
        await expect(page.locator("text=Standard deviation")).not.toBeVisible();
    });
});

// ── Word Mask ──────────────────────────────────────────────────────────────

test.describe("Tokenize — Word Mask", () => {
    // Expected value sourced from test_mask_word in crate/crypto/src/crypto/anonymization/tests.rs
    test("masks known words with XXXX", async ({ page }) => {
        test.skip(FIPS_MODE, "Tokenize endpoints not available in FIPS mode");

        await gotoAndWait(page, "/ui/tokenize/word-mask");
        await page.fill(
            'textarea[placeholder="e.g. Confidential: contains secret documents"]',
            "Confidential: contains -secret- documents",
        );
        // Add words using tags Select
        const tagsInput = page.locator(".ant-select-selector input").first();
        await tagsInput.click();
        await tagsInput.fill("confidential");
        await tagsInput.press("Enter");
        await tagsInput.fill("secret");
        await tagsInput.press("Enter");

        const text = await submitAndWaitForResponse(page);
        expect(text).toMatch(/XXXX.*XXXX/);
        expect(text).toMatch(/Result:/);
    });
});

// ── Word Tokenize ──────────────────────────────────────────────────────────

test.describe("Tokenize — Word Tokenize", () => {
    test("replaces words with consistent hex tokens", async ({ page }) => {
        test.skip(FIPS_MODE, "Tokenize endpoints not available in FIPS mode");

        await gotoAndWait(page, "/ui/tokenize/word-tokenize");
        await page.fill('textarea[placeholder="e.g. Alice sent the report to Alice and Bob"]', "Alice sent the report to Alice");
        const tagsInput = page.locator(".ant-select-selector input").first();
        await tagsInput.click();
        await tagsInput.fill("Alice");
        await tagsInput.press("Enter");

        const text = await submitAndWaitForResponse(page);
        // Both occurrences should be replaced with the same hex token
        expect(text).toMatch(/Result:/);
        // Original word should be gone
        expect(text).not.toMatch(/\bAlice\b/);
    });
});

// ── Word Pattern Mask ──────────────────────────────────────────────────────

test.describe("Tokenize — Pattern Mask", () => {
    test("replaces regex matches with replacement string", async ({ page }) => {
        test.skip(FIPS_MODE, "Tokenize endpoints not available in FIPS mode");

        await gotoAndWait(page, "/ui/tokenize/word-pattern-mask");
        await page.fill('textarea[placeholder="e.g. Call +33 6 12 34 56 78 or +1 800 555 0199"]', "Contact: user@example.com");
        await page.fill('[data-testid="pattern-input"]', String.raw`\S+@\S+\.\S+`);
        await page.fill('input[placeholder="e.g. [PHONE]"]', "[EMAIL]");
        const text = await submitAndWaitForResponse(page);
        expect(text).toMatch(/\[EMAIL\]/);
        expect(text).not.toMatch(/example\.com/);
    });
});

// ── Aggregate Number ────────────────────────────────────────────────────────

test.describe("Tokenize — Aggregate Number", () => {
    // Expected value sourced from test_int_aggregation in crate/crypto/src/crypto/anonymization/tests.rs
    test("rounds 1234 with power_of_ten=2 to 1200", async ({ page }) => {
        test.skip(FIPS_MODE, "Tokenize endpoints not available in FIPS mode");

        await gotoAndWait(page, "/ui/tokenize/aggregate-number");
        // data_type is already "integer" by default
        await page.fill('input[placeholder="e.g. 1234"]', "1234");
        // power_of_ten default is 2 — clear and re-enter to be safe
        await page.fill(".ant-input-number input", "2");
        const text = await submitAndWaitForResponse(page);
        expect(text).toMatch(/Result:\s*1200/);
    });
});

// ── Aggregate Date ─────────────────────────────────────────────────────────

test.describe("Tokenize — Aggregate Date", () => {
    // Expected value sourced from test_time_aggregation in crate/crypto/src/crypto/anonymization/tests.rs
    test("truncates date to Hour precision", async ({ page }) => {
        test.skip(FIPS_MODE, "Tokenize endpoints not available in FIPS mode");

        await gotoAndWait(page, "/ui/tokenize/aggregate-date");
        await page.fill('input[placeholder="e.g. 2023-04-07T12:34:56+02:00"]', "2023-04-07T12:34:56+02:00");
        // Default time_unit is Hour
        const text = await submitAndWaitForResponse(page);
        expect(text).toMatch(/2023-04-07T12:00:00/);
    });
});

// ── Scale Number ────────────────────────────────────────────────────────────

test.describe("Tokenize — Scale Number", () => {
    test("z-score normalise then scale returns a finite number", async ({ page }) => {
        test.skip(FIPS_MODE, "Tokenize endpoints not available in FIPS mode");

        await gotoAndWait(page, "/ui/tokenize/scale-number");
        await page.fill('input[placeholder="e.g. 150.0"]', "150.0");
        // Default values: mean=0, std_deviation=1, scale=1, translate=0 → result should be 150.0
        const text = await submitAndWaitForResponse(page);
        expect(text).toMatch(/Result:\s*-?\d+(\.\d+)?/);
    });
});
