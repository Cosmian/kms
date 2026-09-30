/**
 * SPIFFE JWT-SVID — Web UI / HTTP API Authentication E2E tests.
 *
 * Validates that:
 * 1. An HTTP request with Authorization: Bearer <JWT-SVID> is authenticated by the KMS server.
 * 2. The KMS resolves the authenticated user as the SPIFFE ID (e.g., spiffe://...).
 * 3. Subsequent API calls (e.g. GET /me, GET /access/owned, KMIP operations) execute under this identity.
 */
import { expect, test } from "@playwright/test";

const KMS_URL = process.env.PLAYWRIGHT_KMS_URL ?? "https://127.0.0.1:9998";
const JWT_SVID_TOKEN = process.env.TEST_JWT_SVID_TOKEN;
const EXPECTED_SPIFFE_ID = process.env.TEST_SPIFFE_ID ?? "spiffe://cosmian-test-a.local/test-workload-app";

test.describe("SPIFFE JWT-SVID Authentication", () => {
    test.skip(!JWT_SVID_TOKEN, "TEST_JWT_SVID_TOKEN environment variable not set");

    test("GET /me with Bearer JWT-SVID returns SPIFFE ID user", async ({ request }) => {
        const response = await request.get(`${KMS_URL}/me`, {
            headers: {
                Authorization: `Bearer ${JWT_SVID_TOKEN}`,
            },
            ignoreHTTPSErrors: true,
        });

        expect(response.status()).toBe(200);
        const data = await response.json();
        expect(data).toHaveProperty("user", EXPECTED_SPIFFE_ID);
    });

    test("GET /access/owned with Bearer JWT-SVID returns 200 list", async ({ request }) => {
        const response = await request.get(`${KMS_URL}/access/owned`, {
            headers: {
                Authorization: `Bearer ${JWT_SVID_TOKEN}`,
            },
            ignoreHTTPSErrors: true,
        });

        expect(response.status()).toBe(200);
        const data = await response.json();
        expect(Array.isArray(data)).toBeTruthy();
    });

    test("KMIP JSON Query operation authenticated with Bearer JWT-SVID", async ({ request }) => {
        const response = await request.post(`${KMS_URL}/kmip/2_1`, {
            headers: {
                "Content-Type": "application/json",
                Authorization: `Bearer ${JWT_SVID_TOKEN}`,
            },
            data: {
                tag: "Query",
                type: "Structure",
                value: [{ tag: "QueryFunction", type: "Enumeration", value: "QueryServerInformation" }],
            },
            ignoreHTTPSErrors: true,
        });

        expect(response.status()).toBe(200);
        const data = await response.json();
        expect(data).toHaveProperty("tag", "QueryResponse");
    });
});
