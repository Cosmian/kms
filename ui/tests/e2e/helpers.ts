import { Download, Page } from "@playwright/test";

/** Extract the first UUID (v4 / v1) from an arbitrary text string. */
export function extractUuid(text: string): string | null {
    const m = text.match(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i);
    return m ? m[0] : null;
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
    await responseEl.waitFor({ state: "visible", timeout: 15_000 });
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

    // Ant Design may keep hidden duplicate option nodes mounted (previous
    // dropdowns, virtual lists, etc). Find and click the first *visible*
    // matching option rather than relying on a specific dropdown container.
    const classCandidates = page.locator(`.ant-select-item-option:visible`, { hasText: optionText });
    const roleCandidates = page.getByRole("option", { name: optionText, exact: true });
    const deadline = Date.now() + 10_000;
    let clicked = false;

    while (Date.now() < deadline && !clicked) {
        // Prefer AntD's visible option container (most reliable click target).
        if ((await classCandidates.count()) > 0) {
            await classCandidates.first().click({ force: true });
            clicked = true;
            break;
        }

        // Fallback: accessible role-based option.
        const count = await roleCandidates.count();
        for (let i = 0; i < count; i++) {
            const candidate = roleCandidates.nth(i);
            if (await candidate.isVisible()) {
                await candidate.click({ force: true });
                clicked = true;
                break;
            }
        }

        if (!clicked) {
            await page.waitForTimeout(100);
        }
    }

    if (!clicked) {
        throw new Error(`selectOption: option not visible: ${optionText}`);
    }

    // Ensure the selection actually changed before returning.
    await page.waitForFunction(
        ({ testId, expected }) => {
            const root = document.querySelector(`[data-testid="${testId}"]`);
            const item = root?.querySelector(".ant-select-selection-item");
            return (item?.textContent ?? "").trim() === expected;
        },
        { testId: selectTestId, expected: optionText }
    );
}
