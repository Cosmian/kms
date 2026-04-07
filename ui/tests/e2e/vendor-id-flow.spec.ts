/**
 * Vendor identification E2E test.
 *
 * Verifies that when the KMS server is configured with `vendor_identification = "test_vendor"`,
 * the UI correctly syncs the value at startup (QueryServerInformation in App.tsx) and the WASM
 * module then embeds "test_vendor" as the VendorIdentification inside every KMIP request.
 *
 * Flow:
 *  1.  Navigate to the Certify page — App.tsx startup sync runs automatically.
 *  2.  Install a Playwright route intercept on /kmip/2_1 to capture outgoing KMIP bodies.
 *  3.  Select "Generate New Keypair" and fill a subject name.
 *  4.  Submit — the UI sends a Certify KMIP request.
 *  5.  Assert the intercepted Certify request body contains VendorIdentification = "test_vendor".
 *      (`requested_validity_days` is always stored as a KMIP VendorAttribute, so the field is
 *       always present in the request.)
 *  6.  Assert QueryServerInformation also returns "test_vendor", confirming server config.
 *
 * Prerequisites:
 *  • KMS server running on http://127.0.0.1:9998 with vendor_identification = "test_vendor"
 *    (guaranteed by test_ui.sh which injects this into the generated config).
 */
import { expect, test } from "@playwright/test";
import { gotoAndWait, submitAndWaitForResponse, UI_READY_TIMEOUT } from "./helpers";

/** KMS REST endpoint used for direct KMIP calls (bypasses the UI). */
const KMS_URL = "http://127.0.0.1:9998";

// ── TTLV helpers ─────────────────────────────────────────────────────────────

type TtlvNode = { tag: string; type?: string; value: unknown };

/**
 * Recursively collect every TextString value whose TTLV tag matches `targetTag`
 * anywhere in the TTLV tree.
 */
function collectValuesByTag(node: unknown, targetTag: string): string[] {
    if (Array.isArray(node)) {
        return node.flatMap((n) => collectValuesByTag(n, targetTag));
    }
    if (node && typeof node === "object") {
        const obj = node as TtlvNode;
        if (obj.tag === targetTag && typeof obj.value === "string") {
            return [obj.value];
        }
        // Recurse into array children (Structure nodes).
        if (Array.isArray(obj.value)) {
            return collectValuesByTag(obj.value, targetTag);
        }
    }
    return [];
}

// ── Test ─────────────────────────────────────────────────────────────────────

test.describe("Vendor identification", () => {
    test("certify (generate keypair) — KMIP request uses test_vendor", async ({ page, request }) => {
        // ── 1. Navigate to Certify page (App.tsx syncs vendor_id on mount) ────
        await gotoAndWait(page, "/ui/certificates/certs/certify");

        // ── 2. Intercept all outgoing KMIP requests ───────────────────────────
        // Collect every request body sent to /kmip/2_1 so we can inspect them.
        const capturedBodies: unknown[] = [];

        await page.route("**/kmip/2_1", async (route) => {
            try {
                const postData = route.request().postDataJSON() as unknown;
                capturedBodies.push(postData);
            } catch {
                // ignore parse errors for non-JSON requests
            }
            // Forward the request normally so the UI still gets a real response.
            await route.continue();
        });

        // ── 3. Select "Generate New Keypair" and fill the subject name ────────
        await page.getByText("4. Generate New Keypair").waitFor({ state: "visible", timeout: UI_READY_TIMEOUT });
        await page.getByText("4. Generate New Keypair").click();
        const subjectInput = page.locator('input[placeholder="CN=John Doe,OU=Org Unit,O=Org Name,L=City,ST=State,C=US"]');
        await subjectInput.waitFor({ state: "visible", timeout: 10_000 });
        await subjectInput.fill("CN=test-vendor-e2e");

        // ── 4. Submit the form ────────────────────────────────────────────────
        const responseText = await submitAndWaitForResponse(page);
        expect(responseText).toMatch(/Certificate successfully created/i);

        // ── 5. Assert the Certify request contained VendorIdentification = "test_vendor"
        // Filter for the Certify KMIP operation (not startup QueryServerInformation).
        const certifyBodies = capturedBodies.filter((b) => {
            const node = b as TtlvNode;
            return node?.tag === "Certify";
        });
        expect(
            certifyBodies.length,
            `No "Certify" KMIP request was intercepted.\nAll captured tags: ${JSON.stringify(capturedBodies.map((b) => (b as TtlvNode).tag))}`,
        ).toBeGreaterThan(0);

        const certifyBody = certifyBodies[0];
        const vendorIds = collectValuesByTag(certifyBody, "VendorIdentification");
        expect(
            vendorIds.length,
            `The Certify request had no VendorIdentification field.\nRequest body:\n${JSON.stringify(certifyBody, null, 2)}`,
        ).toBeGreaterThan(0);

        for (const vid of vendorIds) {
            expect(
                vid,
                `Certify request contained VendorIdentification "${vid}" — expected "test_vendor".\nRequest body:\n${JSON.stringify(certifyBody, null, 2)}`,
            ).toBe("test_vendor");
        }

        // ── 6. Confirm the server itself reports vendor_identification = "test_vendor"
        const qsiResp = await request.post(`${KMS_URL}/kmip/2_1`, {
            headers: { "Content-Type": "application/json" },
            data: {
                tag: "Query",
                type: "Structure",
                value: [{ tag: "QueryFunction", type: "Enumeration", value: "QueryServerInformation" }],
            },
        });
        expect(qsiResp.ok()).toBe(true);
        const qsiBody: unknown = await qsiResp.json();
        const serverVendorIds = collectValuesByTag(qsiBody, "VendorIdentification");
        expect(serverVendorIds.length, "QueryServerInformation must return a VendorIdentification").toBeGreaterThan(0);
        expect(serverVendorIds[0], "KMS server must report vendor_identification = 'test_vendor'").toBe("test_vendor");
    });
});
