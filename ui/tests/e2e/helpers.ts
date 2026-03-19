import { Download, expect, Page } from "@playwright/test";
import * as fs from "fs";
import * as path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/** Timeout (ms) used when waiting for the UI to finish loading WASM/React data. */
export const UI_READY_TIMEOUT = 15_000;

/** Extract the first UUID (v4 / v1) from an arbitrary text string. */
export function extractUuid(text: string): string | null {
    const m = text.match(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i);
    return m ? m[0] : null;
}

/**
 * Extract the key identifier that follows a labelled field in a server response string.
 *
 * Captures the full identifier including optional suffixes like `_pk` for public keys.
 * Example: `extractUuidAfterLabel(text, "Public key Id")` returns `"abc-...-123_pk"`.
 */
export function extractUuidAfterLabel(text: string, label: string): string | null {
    const pattern = new RegExp(
        label + ":\\s*([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?:_[a-z]+)?)",
        "i"
    );
    const m = text.match(pattern);
    return m ? m[1] : null;
}

/**
 * Extract *all* UUIDs (v4 / v1) from an arbitrary text string.
 * Returns an empty array when no UUID is found.
 */
export function extractAllUuids(text: string): string[] {
    return text.match(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi) ?? [];
}

/**
 * Navigate to a page and wait for it to be fully idle (WASM, React effects,
 * Ant Design initialisation).  All async hooks that populate dropdowns from
 * WASM resolve during `networkidle`.
 */
export async function gotoAndWait(page: Page, path: string): Promise<void> {
    await page.goto(path);
    await page.waitForLoadState("networkidle", { timeout: 30_000 });
}

/**
 * Click the `[data-testid="submit-btn"]` button and wait for the
 * `[data-testid="response-output"]` panel to appear.
 *
 * Returns the text content of the response panel.
 */
export async function submitAndWaitForResponse(page: Page): Promise<string> {
    await page.click('[data-testid="submit-btn"]');
    const responseEl = page.locator('[data-testid="response-output"]');
    await responseEl.waitFor({ state: "visible", timeout: 30_000 });
    return (await responseEl.textContent()) ?? "";
}

/**
 * Like `submitAndWaitForResponse` but additionally intercepts the file
 * download that operations such as Export / Encrypt trigger via a synthetic
 * `<a download>` click.
 */
export async function submitAndWaitForDownload(page: Page): Promise<{ text: string; download: Download }> {
    const [download] = await Promise.all([page.waitForEvent("download", { timeout: 30_000 }), page.click('[data-testid="submit-btn"]')]);
    const responseEl = page.locator('[data-testid="response-output"]');
    await responseEl.waitFor({ state: "visible", timeout: UI_READY_TIMEOUT });
    const text = (await responseEl.textContent()) ?? "";
    return { text, download };
}

/**
 * Open an Ant Design `<Select>` identified by a `data-testid` attribute and
 * choose the option whose visible label matches `optionText`.
 *
 * Ant Design renders options inside a portal appended to `document.body`, so
 * the search is done document-wide rather than scoped to the select element.
 */
export async function selectOption(page: Page, selectTestId: string, optionText: string): Promise<void> {
    const trigger = page.locator(`[data-testid="${selectTestId}"]`);
    await trigger.scrollIntoViewIfNeeded();

    // Ant Design wraps the actual click-target in `.ant-select-selector`.
    // Use a forced click to avoid the occasional overlay/label intercept.
    const selector = trigger.locator(".ant-select-selector");
    if (await selector.count()) {
        await selector.click({ force: true });
    } else {
        await trigger.click({ force: true });
    }

    // Prefer scoping to the *currently open* dropdown. Ant Design renders
    // options in a portal and may keep multiple dropdown trees around.
    const dropdown = page.locator(".ant-select-dropdown:not(.ant-select-dropdown-hidden)");
    const classCandidates = dropdown.locator(`.ant-select-item-option`, { hasText: optionText });
    const roleCandidates = dropdown.getByRole("option", { name: optionText, exact: true });
    const listHolder = dropdown.locator(".rc-virtual-list-holder").first();
    const deadline = Date.now() + 10_000;
    let clicked = false;
    // Alternate bottom / top scrolls so all items are rendered by the virtual
    // list across two positions (covers lists of any length).
    let scrolledToBottom = false;

    while (Date.now() < deadline && !clicked) {
        // Prefer AntD's visible option container (most reliable click target).
        if ((await classCandidates.count()) > 0) {
            const option = classCandidates.first();
            try {
                await option.scrollIntoViewIfNeeded();
                await option.click({ force: true });
            } catch {
                // In some headless/CI layouts the portal dropdown can end up
                // outside the viewport. Dispatching the DOM click avoids the
                // viewport restriction while still triggering AntD handlers.
                await option.dispatchEvent("click");
            }
            clicked = true;
            break;
        }

        // Fallback: accessible role-based option.
        const count = await roleCandidates.count();
        for (let i = 0; i < count; i++) {
            const candidate = roleCandidates.nth(i);
            if (await candidate.isVisible()) {
                try {
                    await candidate.scrollIntoViewIfNeeded();
                    await candidate.click({ force: true });
                } catch {
                    await candidate.dispatchEvent("click");
                }
                clicked = true;
                break;
            }
        }

        if (!clicked) {
            // Toggle virtual-list scroll position so all items are rendered.
            if (await listHolder.count() > 0) {
                if (!scrolledToBottom) {
                    await listHolder.evaluate((el) => { el.scrollTop = el.scrollHeight; });
                    scrolledToBottom = true;
                } else {
                    await listHolder.evaluate((el) => { el.scrollTop = 0; });
                    scrolledToBottom = false;
                }
            }
            await page.waitForTimeout(100);
        }
    }

    if (!clicked) {
        throw new Error(`selectOption: option not visible: ${optionText}`);
    }

    // Ensure the selection actually changed before returning.
    // Use Playwright's built-in assertion retry rather than a raw
    // waitForFunction: rc-select 14.x renders data-testid on BOTH the outer
    // div.ant-select container and the inner <input type="search"> (via
    // pickAttrs → Input.js attrs spread), so a raw document.querySelector
    // would return the outer div in standard DOM order – but Playwright's
    // CSS descendant selector reliably narrows the scope and the toHaveText
    // assertion retries automatically, making this robust in slow CI.
    await expect(
        page.locator(`[data-testid="${selectTestId}"] .ant-select-selection-item`)
    ).toHaveText(optionText, { exact: true, timeout: 30_000 });
}

/**
 * Open an Ant Design `<Select>` identified by a CSS selector (e.g. `#keyFormat`)
 * and choose the option whose visible label matches `optionText`.
 *
 * Uses the same robust retry / dispatchEvent fallback as `selectOption`, so it
 * works even when the dropdown portal renders outside the viewport in CI.
 */
export async function selectOptionById(page: Page, cssSelector: string, optionText: string): Promise<void> {
    const trigger = page.locator(cssSelector);
    await trigger.scrollIntoViewIfNeeded();
    await trigger.click({ force: true });

    const dropdown = page.locator(".ant-select-dropdown:not(.ant-select-dropdown-hidden)");
    // Wait for the dropdown to open before trying to scroll the virtual list.
    await dropdown.first().waitFor({ state: "visible", timeout: 10_000 });

    // Use a regex anchored to start/end so "Active" does not accidentally match "PreActive".
    const escapedText = optionText.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const candidates = dropdown.locator(".ant-select-item-option", { hasText: new RegExp(`^\\s*${escapedText}\\s*$`) });
    const listHolder = dropdown.locator(".rc-virtual-list-holder").first();
    const deadline = Date.now() + 10_000;
    let clicked = false;
    // Alternate between scrolling to the bottom and back to the top so that
    // all items are rendered by the virtual list across two scroll positions.
    let scrolledToBottom = false;

    while (Date.now() < deadline && !clicked) {
        if ((await candidates.count()) > 0) {
            const option = candidates.first();
            try {
                await option.scrollIntoViewIfNeeded();
                await option.click({ force: true });
            } catch {
                // Dropdown portal may be outside the viewport on narrow CI runners.
                await option.dispatchEvent("click");
            }
            clicked = true;
            break;
        }

        // Toggle between bottom / top to cover all items in the virtual list.
        if (await listHolder.count() > 0) {
            if (!scrolledToBottom) {
                await listHolder.evaluate((el) => { el.scrollTop = el.scrollHeight; });
                scrolledToBottom = true;
            } else {
                await listHolder.evaluate((el) => { el.scrollTop = 0; });
                scrolledToBottom = false;
            }
        }
        await page.waitForTimeout(100);
    }

    if (!clicked) {
        throw new Error(`selectOptionById: option not visible: ${optionText}`);
    }
}

/**
 * Select multiple options in an Ant Design multi-select (`mode="multiple"`).
 *
 * @param cssSelector  CSS selector targeting the `<Select>` wrapper (e.g. `"#keyUsage"`).
 * @param optionLabels Array of visible label strings to select.
 */
export async function selectMultipleOptions(page: Page, cssSelector: string, optionLabels: string[]): Promise<void> {
    for (const label of optionLabels) {
        const trigger = page.locator(cssSelector);
        const selector = trigger.locator(".ant-select-selector");
        if ((await selector.count()) > 0) {
            await selector.click({ force: true });
        } else {
            await trigger.click({ force: true });
        }
        const dropdown = page.locator(".ant-select-dropdown:not(.ant-select-dropdown-hidden)");
        await dropdown.first().waitFor({ state: "visible", timeout: 10_000 });
        const option = dropdown.locator(".ant-select-item-option", { hasText: label }).first();
        await option.waitFor({ state: "visible", timeout: 10_000 });
        try {
            await option.scrollIntoViewIfNeeded();
            await option.click({ force: true });
        } catch {
            await option.dispatchEvent("click");
        }
        await page.waitForTimeout(200);
    }
}

/**
 * Create a fresh AES-256 symmetric key and return its UUID.
 *
 * Shared by sym-key, attributes, access-rights and any other test files that
 * need a key as a fixture, avoiding copy-pasted `createSymKey` functions.
 */
export async function createSymKey(page: Page): Promise<string> {
    await gotoAndWait(page, "/ui/sym/keys/create");
    // The algorithm Select is populated by WASM; wait until it shows a value.
    await expect(page.locator(".ant-select-selection-item").first()).not.toHaveText("", { timeout: UI_READY_TIMEOUT });
    const text = await submitAndWaitForResponse(page);
    expect(text).toMatch(/has been created/i);
    const id = extractUuid(text);
    expect(id).not.toBeNull();
    return id!;
}

/**
 * Create a fresh 4096-bit RSA key pair and return both key IDs.
 */
export async function createRsaKeyPair(page: Page): Promise<{ privKeyId: string; pubKeyId: string }> {
    await gotoAndWait(page, "/ui/rsa/keys/create");
    const text = await submitAndWaitForResponse(page);
    expect(text).toMatch(/Key pair has been created/i);
    const privKeyId = extractUuidAfterLabel(text, "Private key Id");
    const pubKeyId = extractUuidAfterLabel(text, "Public key Id");
    expect(privKeyId).not.toBeNull();
    expect(pubKeyId).not.toBeNull();
    return { privKeyId: privKeyId!, pubKeyId: pubKeyId! };
}

/**
 * Create a fresh EC key pair (NIST P-256) and return both key IDs.
 */
export async function createEcKeyPair(page: Page): Promise<{ privKeyId: string; pubKeyId: string }> {
    await gotoAndWait(page, "/ui/ec/keys/create");
    await selectOption(page, "ec-curve-select", "NIST P-256");
    const text = await submitAndWaitForResponse(page);
    expect(text).toMatch(/Key pair has been created/i);
    const privKeyId = extractUuidAfterLabel(text, "Private key Id");
    const pubKeyId = extractUuidAfterLabel(text, "Public key Id");
    expect(privKeyId).not.toBeNull();
    expect(pubKeyId).not.toBeNull();
    return { privKeyId: privKeyId!, pubKeyId: pubKeyId! };
}

/**
 * Upload a file to the first `FormUploadDragger` on the page.
 *
 * Because Ant Design's `Upload` component wraps a hidden `<input type="file">`,
 * we use Playwright's `setInputFiles()` directly on the native input element.
 *
 * @param filePath Absolute path to the file to upload, or the path returned by `download.path()`.
 */
export async function uploadFile(page: Page, filePath: string): Promise<void> {
    const fileInput = page.locator('input[type="file"]').first();
    await fileInput.setInputFiles(filePath);
}

/**
 * Upload a file to the Nth `FormUploadDragger` on the page (0-based).
 */
export async function uploadFileNth(page: Page, filePath: string, nth: number): Promise<void> {
    const fileInput = page.locator('input[type="file"]').nth(nth);
    await fileInput.setInputFiles(filePath);
}

/**
 * Write content to a temporary file and return its path.
 * Useful for creating test data files to upload.
 */
export function writeTempFile(name: string, content: string | Buffer): string {
    const tmpDir = path.join(__dirname, "..", "..", "test-results");
    fs.mkdirSync(tmpDir, { recursive: true });
    const filePath = path.join(tmpDir, name);
    fs.writeFileSync(filePath, content);
    return filePath;
}

/**
 * KMS API base URL used by helpers that bypass the UI to create test fixtures.
 * Defaults to the local development KMS port; override via PLAYWRIGHT_KMS_URL env var.
 */
const KMS_API_URL =
    (globalThis as { process?: { env?: Record<string, string | undefined> } }).process?.env
        ?.PLAYWRIGHT_KMS_URL ?? "http://127.0.0.1:9998";

/**
 * Create an HMAC key via direct KMIP API call (bypasses the UI since there is
 * no dedicated "create HMAC key" UI page).
 *
 * @param _page  Playwright Page object (unused but kept for API consistency with other create helpers).
 * @param algorithm  KMIP CryptographicAlgorithm string, e.g. "HMACSHA256" (default) or "HMACSHA1".
 * @returns The UUID of the newly created key.
 */
export async function createHmacKey(_page: Page, algorithm = "HMACSHA256"): Promise<string> {
    const request = {
        tag: "Create",
        type: "Structure",
        value: [
            { tag: "ObjectType", type: "Enumeration", value: "SymmetricKey" },
            {
                tag: "Attributes",
                type: "Structure",
                value: [
                    { tag: "CryptographicAlgorithm", type: "Enumeration", value: algorithm },
                    { tag: "CryptographicLength", type: "Integer", value: 256 },
                    // MACGenerate (0x80=128) | MACVerify (0x100=256) = 384
                    { tag: "CryptographicUsageMask", type: "Integer", value: 384 },
                ],
            },
        ],
    };
    const response = await fetch(`${KMS_API_URL}/kmip/2_1`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(request),
    });
    if (!response.ok) {
        const body = await response.text();
        throw new Error(`createHmacKey: KMS request failed with status ${response.status}: ${body}`);
    }
    const json = (await response.json()) as {
        tag?: string;
        value?: Array<{ tag: string; value: unknown }>;
    };
    const idItem = json.value?.find((item) => item.tag === "UniqueIdentifier");
    if (!idItem || typeof idItem.value !== "string") {
        throw new Error(`createHmacKey: no UniqueIdentifier in response: ${JSON.stringify(json)}`);
    }
    return idItem.value;
}
