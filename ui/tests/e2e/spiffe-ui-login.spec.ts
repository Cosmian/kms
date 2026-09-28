/**
 * SPIFFE JWT-SVID — Web UI session E2E test.
 *
 * The Web UI has no SPIFFE login form: the session is established by a gateway that
 * posts a JWT-SVID to `POST /ui/login_svid`. This test plays the gateway (the request
 * shares its cookie jar with the browser context), then loads the SPA and checks that
 * it resolves the session identity to the SPIFFE ID carried by the token's `sub` claim.
 *
 * Requires a real UI build served by the KMS (`ui/dist`); a placeholder index.html
 * cannot render the SPA.
 */
import { expect, test } from "@playwright/test";

const KMS_URL = process.env.PLAYWRIGHT_KMS_URL ?? "https://127.0.0.1:9998";
const JWT_SVID_TOKEN = process.env.TEST_JWT_SVID_TOKEN;
const EXPECTED_SPIFFE_ID = process.env.TEST_SPIFFE_ID ?? "spiffe://cosmian-test-a.local/webui-demo-user";

test.describe("SPIFFE JWT-SVID Web UI session", () => {
    test.skip(!JWT_SVID_TOKEN, "TEST_JWT_SVID_TOKEN environment variable not set");

    test("advertises the SPIFFE auth method", async ({ request }) => {
        const response = await request.get(`${KMS_URL}/ui/auth_method`, { ignoreHTTPSErrors: true });
        expect(response.status()).toBe(200);
        const data = await response.json();
        expect(data.auth_methods).toContain("SPIFFE");
    });

    test("rejects an invalid JWT-SVID on /ui/login_svid", async ({ page }) => {
        const response = await page.request.post(`${KMS_URL}/ui/login_svid`, {
            data: { jwt_svid: `${JWT_SVID_TOKEN}tampered` },
            ignoreHTTPSErrors: true,
        });
        expect(response.status()).toBe(401);
    });

    test("gateway-established session is picked up by the UI", async ({ page }) => {
        const login = await page.request.post(`${KMS_URL}/ui/login_svid`, {
            data: { jwt_svid: JWT_SVID_TOKEN },
            ignoreHTTPSErrors: true,
        });
        expect(login.status()).toBe(200);

        await page.goto(`${KMS_URL}/ui/locate`, { waitUntil: "domcontentloaded" });
        await expect(page.getByTestId("session-user-tag")).toContainText(EXPECTED_SPIFFE_ID);
    });
});
