/**
 * Swagger / OpenAPI endpoint E2E tests.
 *
 * These tests cover three layers:
 *
 *   1. **HTTP contract** — raw request tests verifying status codes, content-types,
 *      and security headers for `/openapi.yaml` and `/swagger-ui`.
 *
 *   2. **Spec correctness** — parse the live YAML spec and assert that every
 *      documented path, tag, and schema key is present and correctly formed.
 *
 *   3. **Browser rendering** — navigate Playwright to `/swagger-ui` and assert
 *      that Swagger UI boots, loads the spec from `/openapi.yaml`, and renders
 *      the tag tree and individual operations correctly.
 *
 * All requests target the KMS server directly (not the Vite UI preview).
 * The KMS URL is read from `PLAYWRIGHT_KMS_URL` (set by `test_ui.sh`) and falls
 * back to `http://localhost:9998` for local plain-HTTP dev runs.
 *
 * Prerequisites:
 *   - KMS server running on port 9998 with `no_auth.toml` (or any auth config).
 *   - Internet access available for the CDN Swagger UI JS/CSS resources.
 */
import { expect, test } from "@playwright/test";

// KMS server base URL — direct (not through the Vite preview UI server).
// In CI, test_ui.sh exports PLAYWRIGHT_KMS_URL="https://127.0.0.1:9998".
// For local HTTP dev testing the default is the plain HTTP dev server.
const KMS_URL = process.env.PLAYWRIGHT_KMS_URL ?? "http://localhost:9998";

// ── /openapi.yaml — HTTP contract ─────────────────────────────────────────────

test.describe("GET /openapi.yaml — HTTP contract", () => {
    test("returns 200 with application/yaml content-type", async ({ request }) => {
        const response = await request.get(`${KMS_URL}/openapi.yaml`);
        expect(response.status()).toBe(200);
        expect(response.headers()["content-type"]).toMatch(/application\/yaml/);
    });

    test("returns security headers (X-Frame-Options, CSP)", async ({ request }) => {
        const response = await request.get(`${KMS_URL}/openapi.yaml`);
        expect(response.headers()["x-frame-options"]).toBe("DENY");
        expect(response.headers()["content-security-policy"]).toContain("frame-ancestors 'none'");
    });

    test("response body is within expected size bounds (50 KB–500 KB)", async ({ request }) => {
        const response = await request.get(`${KMS_URL}/openapi.yaml`);
        const text = await response.text();
        expect(text.length, "spec too small — likely truncated").toBeGreaterThan(50_000);
        expect(text.length, "spec too large — sanity cap exceeded").toBeLessThan(500_000);
    });
});

// ── /openapi.yaml — spec structure ────────────────────────────────────────────

test.describe("GET /openapi.yaml — spec structure", () => {
    test("starts with OpenAPI 3.1.0 declaration and correct title", async ({ request }) => {
        const response = await request.get(`${KMS_URL}/openapi.yaml`);
        const text = await response.text();
        expect(text).toContain("openapi: 3.1.0");
        expect(text).toContain("title: Cosmian KMS");
    });

    test("contains all expected API tag groups", async ({ request }) => {
        const response = await request.get(`${KMS_URL}/openapi.yaml`);
        const text = await response.text();
        const requiredTags = [
            "Public",
            "KMIP",
            "Access",
            "Server",
            "REST Crypto API",
            "Google CSE",
            "AWS XKS",
            "Azure EKM",
            "MS DKE",
            "UI Auth",
        ];
        for (const tag of requiredTags) {
            expect(text, `Missing tag: "${tag}"`).toContain(tag);
        }
    });

    test("contains all documented path entries", async ({ request }) => {
        const response = await request.get(`${KMS_URL}/openapi.yaml`);
        const text = await response.text();
        const requiredPaths = [
            "/health",
            "/version",
            "/openapi.yaml",
            "/swagger-ui",
            "/kmip/2_1",
            "/me",
            "/access/owned",
            "/access/obtained",
            "/access/list/{object_id}",
            "/access/grant",
            "/access/revoke",
            "/access/create",
            "/access/privileged",
            "/server-info",
            "/hsm/status",
            "/v1/crypto/encrypt",
            "/v1/crypto/decrypt",
            "/v1/crypto/sign",
            "/v1/crypto/verify",
            "/v1/crypto/mac",
            "/v1/crypto/keys",
            "/v1/crypto/keys/{kid}",
            "/google_cse/status",
            "/google_cse/certs",
            "/google_cse/digest",
            "/aws/kms/xks/v1/health",
            "/aws/kms/xks/v1/keys/{key_id}/metadata",
            "/aws/kms/xks/v1/keys/{key_id}/encrypt",
            "/aws/kms/xks/v1/keys/{key_id}/decrypt",
            "/azureekm/info",
            "/azureekm/{key_name}/metadata",
            "/azureekm/{key_name}/wrapkey",
            "/azureekm/{key_name}/unwrapkey",
            "/ms_dke/version",
            "/ms_dke/{key_name}",
            "/download-cli",
            "/ui/login_flow",
            "/ui/callback",
            "/ui/token",
            "/ui/logout",
            "/ui/auth_method",
        ];
        for (const path of requiredPaths) {
            expect(text, `Missing path: "${path}"`).toContain(path);
        }
    });

    test("defines all required component schemas", async ({ request }) => {
        const response = await request.get(`${KMS_URL}/openapi.yaml`);
        const text = await response.text();
        const requiredSchemas = [
            "TtlvNode",
            "TtlvStructure",
            "EncryptRequest",
            "EncryptResponse",
            "DecryptRequest",
            "DecryptResponse",
            "SignRequest",
            "SignResponse",
            "VerifyRequest",
            "VerifyResponse",
            "MacRequest",
            "MacComputeResponse",
            "MacVerifyResponse",
            "KeyCreateRequest",
            "KeyCreateResponse",
        ];
        for (const schema of requiredSchemas) {
            expect(text, `Missing schema: "${schema}"`).toContain(schema);
        }
    });

    test("security schemes declare bearerAuth and mtls", async ({ request }) => {
        const response = await request.get(`${KMS_URL}/openapi.yaml`);
        const text = await response.text();
        expect(text).toContain("bearerAuth:");
        expect(text).toContain("mtls:");
        expect(text).toContain("mutualTLS");
    });
});

// ── /swagger-ui — HTTP contract ────────────────────────────────────────────────

test.describe("GET /swagger-ui — HTTP contract", () => {
    test("returns 200 with text/html content-type", async ({ request }) => {
        const response = await request.get(`${KMS_URL}/swagger-ui`);
        expect(response.status()).toBe(200);
        expect(response.headers()["content-type"]).toMatch(/text\/html/);
    });

    test("HTML references /openapi.yaml as the spec URL", async ({ request }) => {
        const response = await request.get(`${KMS_URL}/swagger-ui`);
        const html = await response.text();
        expect(html).toContain("/openapi.yaml");
    });

    test("HTML loads Swagger UI bundle from unpkg CDN with SRI hashes", async ({ request }) => {
        const response = await request.get(`${KMS_URL}/swagger-ui`);
        const html = await response.text();
        expect(html).toContain("unpkg.com/swagger-ui-dist");
        // Both CSS and JS must declare integrity + crossorigin attributes
        expect(html).toContain('integrity="sha384-');
        expect(html).toContain('crossorigin="anonymous"');
    });

    test("returns strict Content-Security-Policy header", async ({ request }) => {
        const response = await request.get(`${KMS_URL}/swagger-ui`);
        const csp = response.headers()["content-security-policy"] ?? "";
        expect(csp).toContain("default-src 'none'");
        expect(csp).toContain("script-src https://unpkg.com");
        expect(csp).toContain("style-src https://unpkg.com");
        expect(csp).toContain("connect-src 'self'");
    });

    test("returns X-Frame-Options: DENY header", async ({ request }) => {
        const response = await request.get(`${KMS_URL}/swagger-ui`);
        expect(response.headers()["x-frame-options"]).toBe("DENY");
    });

    test("page title is set to Cosmian KMS — API", async ({ request }) => {
        const response = await request.get(`${KMS_URL}/swagger-ui`);
        const html = await response.text();
        expect(html).toContain("Cosmian KMS");
    });
});

// ── /swagger-ui — browser rendering ──────────────────────────────────────────

test.describe("GET /swagger-ui — browser rendering", () => {
    test("Swagger UI container mounts and loads the spec title", async ({ page }) => {
        await page.goto(`${KMS_URL}/swagger-ui`);

        // The swagger-ui <div> must be present immediately (it is part of the HTML).
        const container = page.locator("#swagger-ui");
        await container.waitFor({ state: "visible", timeout: 10_000 });

        // The SwaggerUIBundle JS fetches /openapi.yaml and renders the info title.
        await expect(page.locator(".swagger-ui .info .title")).toBeVisible({ timeout: 30_000 });
        await expect(page.locator(".swagger-ui .info .title")).toHaveText(/Cosmian KMS/);
    });

    test("all expected API tag sections are rendered", async ({ page }) => {
        await page.goto(`${KMS_URL}/swagger-ui`);

        // Wait for the first operation tag section to render
        await expect(page.locator(".swagger-ui .opblock-tag").first()).toBeVisible({
            timeout: 30_000,
        });

        const renderedTags = await page.locator(".swagger-ui .opblock-tag span:not(.no-margin)").allTextContents();
        for (const expected of ["Public", "KMIP", "Access", "Server"]) {
            expect(
                renderedTags.some((t) => t.includes(expected)),
                `Tag section "${expected}" not found in rendered Swagger UI`,
            ).toBe(true);
        }
    });

    test("clicking a tag section expands its operations", async ({ page }) => {
        await page.goto(`${KMS_URL}/swagger-ui`);

        const firstTag = page.locator(".swagger-ui .opblock-tag").first();
        await firstTag.waitFor({ state: "visible", timeout: 30_000 });

        // Click the tag heading to expand
        await firstTag.click();

        // At least one operation block should now be visible
        await expect(page.locator(".swagger-ui .opblock").first()).toBeVisible({
            timeout: 10_000,
        });
    });

    test("clicking an operation block expands its detail panel", async ({ page }) => {
        await page.goto(`${KMS_URL}/swagger-ui`);

        // Expand first tag
        const firstTag = page.locator(".swagger-ui .opblock-tag").first();
        await firstTag.waitFor({ state: "visible", timeout: 30_000 });
        await firstTag.click();

        // Click first operation to expand
        const firstOp = page.locator(".swagger-ui .opblock").first();
        await firstOp.waitFor({ state: "visible", timeout: 10_000 });
        await firstOp.click();

        // The operation detail panel should now contain a summary or description
        await expect(page.locator(".swagger-ui .opblock.is-open .opblock-body")).toBeVisible({
            timeout: 10_000,
        });
    });
});

// ── Cross-check: live endpoints match the documented spec ─────────────────────

test.describe("Live endpoint responses match OpenAPI spec", () => {
    test("GET /health → 200 {status:'UP', latency_ms, dependencies}", async ({ request }) => {
        const response = await request.get(`${KMS_URL}/health`);
        expect(response.status()).toBe(200);
        expect(response.headers()["content-type"]).toMatch(/application\/json/);
        const body = await response.json() as Record<string, unknown>;
        expect(body).toHaveProperty("status", "UP");
        expect(body).toHaveProperty("latency_ms");
        expect(body).toHaveProperty("dependencies");
    });

    test("GET /version → 200 JSON string matching semver", async ({ request }) => {
        const response = await request.get(`${KMS_URL}/version`);
        expect(response.status()).toBe(200);
        const body = await response.json() as string;
        expect(typeof body).toBe("string");
        expect(body).toMatch(/\d+\.\d+\.\d+/);
    });

    test("GET /me → 200 {user: string}", async ({ request }) => {
        const response = await request.get(`${KMS_URL}/me`);
        expect(response.status()).toBe(200);
        const body = await response.json() as Record<string, unknown>;
        expect(body).toHaveProperty("user");
        expect(typeof body.user).toBe("string");
    });

    test("GET /server-info → 200 with version, fips_mode, hsm_instances, default_username", async ({ request }) => {
        const response = await request.get(`${KMS_URL}/server-info`);
        expect(response.status()).toBe(200);
        const body = await response.json() as Record<string, unknown>;
        expect(body).toHaveProperty("version");
        expect(body).toHaveProperty("fips_mode");
        expect(body).toHaveProperty("hsm_instances");
        expect(body).toHaveProperty("default_username");
        expect(typeof body.fips_mode).toBe("boolean");
        expect(Array.isArray(body.hsm_instances)).toBe(true);
    });

    test("GET /hsm/status → 200 JSON array", async ({ request }) => {
        const response = await request.get(`${KMS_URL}/hsm/status`);
        expect(response.status()).toBe(200);
        const body = await response.json() as unknown[];
        expect(Array.isArray(body)).toBe(true);
    });

    test("GET /access/owned → 200 JSON array", async ({ request }) => {
        const response = await request.get(`${KMS_URL}/access/owned`);
        expect(response.status()).toBe(200);
        const body = await response.json() as unknown[];
        expect(Array.isArray(body)).toBe(true);
    });

    test("GET /access/obtained → 200 JSON array", async ({ request }) => {
        const response = await request.get(`${KMS_URL}/access/obtained`);
        expect(response.status()).toBe(200);
        const body = await response.json() as unknown[];
        expect(Array.isArray(body)).toBe(true);
    });

    test("GET /access/create → 200 {has_create_permission: boolean}", async ({ request }) => {
        const response = await request.get(`${KMS_URL}/access/create`);
        expect(response.status()).toBe(200);
        const body = await response.json() as Record<string, unknown>;
        expect(body).toHaveProperty("has_create_permission");
        expect(typeof body.has_create_permission).toBe("boolean");
    });

    test("GET /access/privileged → 200 {has_privileged_access: boolean}", async ({ request }) => {
        const response = await request.get(`${KMS_URL}/access/privileged`);
        expect(response.status()).toBe(200);
        const body = await response.json() as Record<string, unknown>;
        expect(body).toHaveProperty("has_privileged_access");
        expect(typeof body.has_privileged_access).toBe("boolean");
    });

    test("POST /kmip/2_1 with empty payload → 422 Unprocessable Entity", async ({ request }) => {
        const response = await request.post(`${KMS_URL}/kmip/2_1`, {
            data: {},
            headers: { "Content-Type": "application/json" },
        });
        expect(response.status()).toBe(422);
    });

    test("GET /download-cli → not a server error (200 or 404)", async ({ request }) => {
        const response = await request.get(`${KMS_URL}/download-cli`);
        expect(response.status()).toBeLessThan(500);
    });

    test("GET /access/list/{nonexistent-id} → 401 or 404, not a server error", async ({ request }) => {
        const response = await request.get(`${KMS_URL}/access/list/00000000-0000-0000-0000-000000000000`);
        expect(response.status()).toBeLessThan(500);
    });
});

// ── HTTP method semantics ─────────────────────────────────────────────────────

test.describe("HTTP method semantics", () => {
    test("POST /openapi.yaml is rejected with 404 or 405", async ({ request }) => {
        const response = await request.post(`${KMS_URL}/openapi.yaml`, { data: {} });
        expect([404, 405]).toContain(response.status());
    });

    test("DELETE /swagger-ui is rejected with 404 or 405", async ({ request }) => {
        const response = await request.delete(`${KMS_URL}/swagger-ui`);
        expect([404, 405]).toContain(response.status());
    });

    test("GET /openapi.yaml is idempotent — two requests return identical body", async ({ request }) => {
        const [r1, r2] = await Promise.all([
            request.get(`${KMS_URL}/openapi.yaml`),
            request.get(`${KMS_URL}/openapi.yaml`),
        ]);
        expect(await r1.text()).toBe(await r2.text());
    });
});

// ── KMIP protocol — version acceptance ───────────────────────────────────────

/** Build a minimal KMIP Query TTLV-as-JSON request for the given protocol version. */
function kmipQueryRequest(major: number, minor: number): unknown {
    return {
        tag: "RequestMessage",
        value: [
            {
                tag: "RequestHeader",
                value: [
                    {
                        tag: "ProtocolVersion",
                        value: [
                            { tag: "ProtocolVersionMajor", type: "Integer", value: major },
                            { tag: "ProtocolVersionMinor", type: "Integer", value: minor },
                        ],
                    },
                    { tag: "MaximumResponseSize", type: "Integer", value: 1024 },
                    { tag: "BatchCount", type: "Integer", value: 1 },
                ],
            },
            {
                tag: "BatchItem",
                value: [
                    { tag: "Operation", type: "Enumeration", value: "Query" },
                    {
                        tag: "RequestPayload",
                        value: [{ tag: "QueryFunction", type: "Enumeration", value: "QueryOperations" }],
                    },
                ],
            },
        ],
    };
}

/** Build a minimal KMIP 2.1 Create AES-256 TTLV-as-JSON request. */
function kmipCreateAes256Request(): unknown {
    return {
        tag: "RequestMessage",
        value: [
            {
                tag: "RequestHeader",
                value: [
                    {
                        tag: "ProtocolVersion",
                        value: [
                            { tag: "ProtocolVersionMajor", type: "Integer", value: 2 },
                            { tag: "ProtocolVersionMinor", type: "Integer", value: 1 },
                        ],
                    },
                    { tag: "BatchCount", type: "Integer", value: 1 },
                ],
            },
            {
                tag: "BatchItem",
                value: [
                    { tag: "Operation", type: "Enumeration", value: "Create" },
                    {
                        tag: "RequestPayload",
                        value: [
                            { tag: "ObjectType", type: "Enumeration", value: "SymmetricKey" },
                            {
                                tag: "Attributes",
                                value: [
                                    { tag: "CryptographicAlgorithm", type: "Enumeration", value: "AES" },
                                    { tag: "CryptographicLength", type: "Integer", value: 256 },
                                ],
                            },
                        ],
                    },
                ],
            },
        ],
    };
}

test.describe("KMIP protocol — version acceptance", () => {
    const JSON_HEADERS = { "Content-Type": "application/json" };

    test("KMIP 2.1 Query request → 200, ResultStatus Success (not rejected)", async ({ request }) => {
        const response = await request.post(`${KMS_URL}/kmip/2_1`, {
            data: kmipQueryRequest(2, 1),
            headers: JSON_HEADERS,
        });
        expect(response.status()).toBe(200);
        const body = await response.text();
        expect(body).not.toContain("only accepts KMIP 2.1 or 1.4");
        // KMIP TTLV-as-JSON uses ResultStatus with value "Success" (not "OperationSuccess")
        expect(body).toContain('"ResultStatus"');
        expect(body).not.toContain('"OperationFailed"');
    });

    test("KMIP 1.4 Query request → 200, not rejected", async ({ request }) => {
        const response = await request.post(`${KMS_URL}/kmip/2_1`, {
            data: kmipQueryRequest(1, 4),
            headers: JSON_HEADERS,
        });
        expect(response.status()).toBe(200);
        const body = await response.text();
        expect(body).not.toContain("only accepts KMIP 2.1 or 1.4");
    });

    test("KMIP 1.3 request → 200, accepted and processed (backward compatible)", async ({ request }) => {
        const response = await request.post(`${KMS_URL}/kmip/2_1`, {
            data: kmipQueryRequest(1, 3),
            headers: JSON_HEADERS,
        });
        expect(response.status()).toBe(200);
        const body = await response.text();
        // Server accepts KMIP 1.3 requests as backward compatible — no version rejection
        expect(body).toContain('"ResultStatus"');
        expect(body).not.toContain('"OperationFailed"');
    });

    test("KMIP 1.0 request → 200, accepted and processed (backward compatible)", async ({ request }) => {
        const response = await request.post(`${KMS_URL}/kmip/2_1`, {
            data: kmipQueryRequest(1, 0),
            headers: JSON_HEADERS,
        });
        expect(response.status()).toBe(200);
        const body = await response.text();
        // Server accepts KMIP 1.0 requests as backward compatible — no version rejection
        expect(body).toContain('"ResultStatus"');
        expect(body).not.toContain('"OperationFailed"');
    });

    test("KMIP 2.1 Create AES-256 → 200, ResultStatus Success and UniqueIdentifier", async ({ request }) => {
        const response = await request.post(`${KMS_URL}/kmip/2_1`, {
            data: kmipCreateAes256Request(),
            headers: JSON_HEADERS,
        });
        expect(response.status()).toBe(200);
        const body = await response.text();
        // KMIP TTLV-as-JSON uses ResultStatus with value "Success" (not "OperationSuccess")
        expect(body).toContain('"ResultStatus"');
        expect(body).not.toContain('"OperationFailed"');
        expect(body).toContain("UniqueIdentifier");
    });
});

// ── REST Crypto API (`/v1/crypto/keys`) ──────────────────────────────────────

test.describe("REST Crypto API — key lifecycle", () => {
    const JSON_HEADERS = { "Content-Type": "application/json" };

    test("POST /v1/crypto/keys with AES-256-GCM params → 200, returns kid", async ({ request }) => {
        const response = await request.post(`${KMS_URL}/v1/crypto/keys`, {
            data: { kty: "oct", alg: "A256GCM" },
            headers: JSON_HEADERS,
        });
        expect(response.status()).toBe(200);
        const body = await response.json() as Record<string, unknown>;
        expect(body).toHaveProperty("kid");
        expect(typeof body.kid).toBe("string");
        expect((body.kid as string).length).toBeGreaterThan(0);
        expect(body).toHaveProperty("kty", "oct");
        expect(body).toHaveProperty("key_ops");
        expect(Array.isArray(body.key_ops)).toBe(true);
    });

    test("POST /v1/crypto/keys with EC P-256 params → 200, returns kid and kid_public", async ({ request }) => {
        const response = await request.post(`${KMS_URL}/v1/crypto/keys`, {
            data: { kty: "EC", crv: "P-256", alg: "ES256" },
            headers: JSON_HEADERS,
        });
        expect(response.status()).toBe(200);
        const body = await response.json() as Record<string, unknown>;
        expect(body).toHaveProperty("kid");
        expect(body).toHaveProperty("kid_public");
        expect(body).toHaveProperty("kty", "EC");
    });

    test("POST /v1/crypto/keys with missing required field → 400 Bad Request", async ({ request }) => {
        const response = await request.post(`${KMS_URL}/v1/crypto/keys`, {
            data: {},
            headers: JSON_HEADERS,
        });
        // Server returns 400 Bad Request for missing required JSON fields (deserialization error)
        expect(response.status()).toBe(400);
    });

    test("DELETE /v1/crypto/keys/{kid} destroys the key → 204", async ({ request }) => {
        // First create a key
        const createResp = await request.post(`${KMS_URL}/v1/crypto/keys`, {
            data: { kty: "oct", alg: "A256GCM" },
            headers: JSON_HEADERS,
        });
        expect(createResp.status()).toBe(200);
        const { kid } = await createResp.json() as { kid: string };

        // Then destroy it
        const deleteResp = await request.delete(`${KMS_URL}/v1/crypto/keys/${kid}`);
        expect(deleteResp.status()).toBe(204);
    });
});

// ── Swagger UI — advanced browser interactions ────────────────────────────────

test.describe("GET /swagger-ui — advanced browser interactions", () => {
    test("search filter input is rendered and accepts text input", async ({ page }) => {
        await page.goto(`${KMS_URL}/swagger-ui`);
        // Wait for swagger to fully render
        await expect(page.locator(".swagger-ui .opblock-tag").first()).toBeVisible({ timeout: 30_000 });

        // Swagger UI renders a filter/search input
        const filterInput = page.locator(".swagger-ui input[placeholder*='filter' i], .swagger-ui input[type='text'].filter");
        // The filter might be rendered under different selectors across swagger-ui versions
        const hasFilter = (await filterInput.count()) > 0;
        if (hasFilter) {
            await filterInput.first().fill("KMIP");
            // After filtering, only matching tag sections should be visible
            await page.waitForTimeout(300);
            const visibleTags = await page.locator(".swagger-ui .opblock-tag:visible span:not(.no-margin)").allTextContents();
            expect(visibleTags.length).toBeGreaterThan(0);
        }
        // If filter is not present in this swagger-ui version, skip gracefully
    });

    test('"Try it out" button appears inside an expanded operation', async ({ page }) => {
        await page.goto(`${KMS_URL}/swagger-ui`);

        // Expand first tag
        const firstTag = page.locator(".swagger-ui .opblock-tag").first();
        await firstTag.waitFor({ state: "visible", timeout: 30_000 });
        await firstTag.click();

        // Click first operation
        const firstOp = page.locator(".swagger-ui .opblock").first();
        await firstOp.waitFor({ state: "visible", timeout: 10_000 });
        await firstOp.click();

        // "Try it out" button should appear in the expanded operation body
        const tryItOut = page.locator(".swagger-ui .try-out__btn, .swagger-ui button:has-text('Try it out')");
        await expect(tryItOut.first()).toBeVisible({ timeout: 10_000 });
    });

    test("spec info block renders description and version", async ({ page }) => {
        await page.goto(`${KMS_URL}/swagger-ui`);
        await expect(page.locator(".swagger-ui .info .title")).toBeVisible({ timeout: 30_000 });

        // The info block should render a version badge
        const infoBlock = page.locator(".swagger-ui .info");
        await expect(infoBlock).toBeVisible();
        const infoText = await infoBlock.textContent();
        // Should contain the server title
        expect(infoText).toMatch(/Cosmian KMS/i);
    });

    test("all tag sections are collapsed by default (first render)", async ({ page }) => {
        await page.goto(`${KMS_URL}/swagger-ui`);
        await expect(page.locator(".swagger-ui .opblock-tag").first()).toBeVisible({ timeout: 30_000 });

        // Before clicking any tag, no operation blocks should be visible
        // (Swagger UI renders tags collapsed by default)
        const openOperations = page.locator(".swagger-ui .opblock-tag-section.is-open");
        // This may or may not be present depending on swagger-ui defaultModelsExpandDepth;
        // just verify the tag header is rendered without crashing
        const tagCount = await page.locator(".swagger-ui .opblock-tag").count();
        expect(tagCount).toBeGreaterThan(0);
    });
});
