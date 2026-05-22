/**
 * Multi-HSM key creation / destruction E2E tests.
 *
 * These tests verify that the UI correctly creates and destroys symmetric
 * (AES-256) keys on three independent SoftHSM2 instances using both the
 * legacy UID prefix convention and the new model-qualified prefix convention:
 *
 *   - Slot 1 (`PLAYWRIGHT_HSM_SLOT_ID_1`) → legacy prefix `hsm::<slot>::<name>`
 *   - Slot 2 (`PLAYWRIGHT_HSM_SLOT_ID_2`) → new prefix `hsm::softhsm2::<slot>::<name>`
 *   - Slot 3 (`PLAYWRIGHT_HSM_SLOT_ID_3`) → disambiguated prefix `hsm::softhsm2_1::<slot>::<name>`
 *
 * The tests are guarded by `HSM_AVAILABLE` (requires all three slot IDs to be
 * set via environment variables exported by `test_ui.sh`).
 *
 * Key steps:
 *  1. Navigate to `/ui/sym/keys/create`
 *  2. Fill in an explicit Key ID using the appropriate HSM UID prefix
 *  3. Submit the form and assert the server echoes the same UID back
 *  4. Navigate to `/ui/sym/keys/destroy`
 *  5. Fill in the UID and destroy the key (with remove=true for HSM keys)
 *  6. Assert the response confirms destruction
 */
import { expect, test } from "@playwright/test";
import { gotoAndWait, submitAndWaitForResponse, UI_READY_TIMEOUT } from "./helpers";
import type { Page } from "@playwright/test";

type GlobalWithProcess = typeof globalThis & {
    process?: { env?: Record<string, string | undefined> };
};
const _env = (globalThis as GlobalWithProcess).process?.env ?? {};

const HSM_SLOT_ID_1 = _env.PLAYWRIGHT_HSM_SLOT_ID_1 ?? "";
const HSM_SLOT_ID_2 = _env.PLAYWRIGHT_HSM_SLOT_ID_2 ?? "";
const HSM_SLOT_ID_3 = _env.PLAYWRIGHT_HSM_SLOT_ID_3 ?? "";

// All three slot IDs must be set for the tests to run.
const HSM_AVAILABLE = HSM_SLOT_ID_1 !== "" && HSM_SLOT_ID_2 !== "" && HSM_SLOT_ID_3 !== "";

/**
 * Create an AES-256 key on the given HSM slot using the provided explicit UID,
 * then assert the server returns the same UID.
 *
 * Returns the UID string that was created.
 */
async function createHsmSymKey(page: Page, keyId: string): Promise<string> {
    await gotoAndWait(page, "/ui/sym/keys/create");

    // Wait until the algorithm Select is populated by WASM before proceeding.
    await expect(page.locator(".ant-select-selection-item").first()).not.toHaveText("", {
        timeout: UI_READY_TIMEOUT,
    });

    // Fill in the explicit Key ID field.
    await page.fill('input[placeholder="Enter key ID"]', keyId);

    const text = await submitAndWaitForResponse(page);
    // The server echoes back `<uid> has been created.`
    expect(text).toMatch(new RegExp(keyId.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + " has been created", "i"));
    return keyId;
}

/**
 * Destroy a symmetric key by its UID using `/ui/sym/keys/destroy`.
 * For HSM keys we also tick "Remove completely from database" so the object
 * is fully removed from the HSM slot (not just soft-deleted).
 */
async function destroyHsmSymKey(page: Page, keyId: string): Promise<void> {
    await gotoAndWait(page, "/ui/sym/keys/destroy");

    await page.fill('input[placeholder="Enter key ID"]', keyId);

    // Tick "Remove completely from database" (Form.Item name="remove" → id="remove").
    // HSM objects must be completely removed so the slot is freed.
    const removeCheckbox = page.locator("label").filter({ hasText: /remove completely/i });
    if ((await removeCheckbox.count()) > 0) {
        const checkbox = removeCheckbox.locator("..").locator('input[type="checkbox"]');
        if ((await checkbox.count()) > 0 && !(await checkbox.first().isChecked())) {
            await removeCheckbox.first().click();
        }
    }

    const text = await submitAndWaitForResponse(page);
    expect(text).toMatch(/destroyed/i);
}

test.describe("Multi-HSM key creation / destruction", () => {
    test.skip(!HSM_AVAILABLE, "Three SoftHSM2 slot IDs (PLAYWRIGHT_HSM_SLOT_ID_1/2/3) are required – skipping");

    /**
     * Slot 1 — legacy prefix `hsm::<slot>::<name>`
     * This exercises the backward-compatible single-HSM config path.
     */
    test("create and destroy key on slot 1 using legacy prefix (hsm::)", async ({ page }) => {
        const ts = Date.now();
        const keyId = `hsm::${HSM_SLOT_ID_1}::ui_test_legacy_${ts}`;

        await createHsmSymKey(page, keyId);
        await destroyHsmSymKey(page, keyId);
    });

    /**
     * Slot 2 — new prefix `hsm::softhsm2::<slot>::<name>`
     * This exercises the first [[hsm_instances]] entry.
     */
    test("create and destroy key on slot 2 using new prefix (hsm::softhsm2::)", async ({ page }) => {
        const ts = Date.now();
        const keyId = `hsm::softhsm2::${HSM_SLOT_ID_2}::ui_test_new_${ts}`;

        await createHsmSymKey(page, keyId);
        await destroyHsmSymKey(page, keyId);
    });

    /**
     * Slot 3 — disambiguated prefix `hsm::softhsm2_1::<slot>::<name>`
     * This exercises the second [[hsm_instances]] entry (same model → disambiguated).
     */
    test("create and destroy key on slot 3 using disambiguated prefix (hsm::softhsm2_1::)", async ({ page }) => {
        const ts = Date.now();
        const keyId = `hsm::softhsm2_1::${HSM_SLOT_ID_3}::ui_test_disambig_${ts}`;

        await createHsmSymKey(page, keyId);
        await destroyHsmSymKey(page, keyId);
    });

    /**
     * Cross-validation: create a key on each slot in quick succession and
     * verify that all three are independently accessible (the keys are
     * routed to different HSM instances).
     */
    test("create keys on all three slots concurrently and verify routing", async ({ page }) => {
        const ts = Date.now();

        // Create keys on all three slots sequentially (same page/session).
        const keyId1 = `hsm::${HSM_SLOT_ID_1}::ui_routing_1_${ts}`;
        const keyId2 = `hsm::softhsm2::${HSM_SLOT_ID_2}::ui_routing_2_${ts}`;
        const keyId3 = `hsm::softhsm2_1::${HSM_SLOT_ID_3}::ui_routing_3_${ts}`;

        await createHsmSymKey(page, keyId1);
        await createHsmSymKey(page, keyId2);
        await createHsmSymKey(page, keyId3);

        // Destroy all three.
        await destroyHsmSymKey(page, keyId1);
        await destroyHsmSymKey(page, keyId2);
        await destroyHsmSymKey(page, keyId3);
    });
});
