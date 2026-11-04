/**
 * SAML 2.0 single sign-on — true end-to-end test of the KMS Web UI.
 *
 * Real stack (`.mise/scripts/test/saml_sso/stack.sh`, started by `test_ui_saml.sh`): Keycloak
 * as SAML IdP, the Auth Verifier SAML build (`cargo run`) as SAML SP, nginx serving both and the KMS on
 * `https://localhost:8443`. Nothing is mocked: the browser goes KMS -> Auth Verifier -> Keycloak
 * login form -> Auth Verifier ACS -> `_ea_` cookie -> KMS, and the KMS validates the session
 * JWT against the Auth Verifier JWKS (the production signature path that unit tests skip).
 *
 * Run: `mise run test:ui-saml`.
 */
import { expect, test, request as playwrightRequest, type BrowserContext, type Page } from "@playwright/test";

const SAML_USER = "alice@example.com"; // Keycloak user `alice`; `sub` = email attribute (stack.sh)
const SESSION_COOKIE = "_ea_";
// Reached directly, as the KMS does. The harness passes the address the verifier binds (the docker
// bridge gateway on Linux, loopback on macOS).
const AUTH_VERIFIER_URL = process.env.AUTH_VERIFIER_URL ?? "https://127.0.0.1:8444";

const CREATE_AES_KEY = {
    tag: "Create",
    type: "Structure",
    value: [
        { tag: "ObjectType", type: "Enumeration", value: "SymmetricKey" },
        {
            tag: "Attributes",
            type: "Structure",
            value: [
                { tag: "CryptographicAlgorithm", type: "Enumeration", value: "AES" },
                { tag: "CryptographicLength", type: "Integer", value: 256 },
                { tag: "CryptographicUsageMask", type: "Integer", value: 12 },
            ],
        },
    ],
};

/** Sign in through the UI: SSO button -> Keycloak form -> back on the KMS UI. */
async function ssoLogin(page: Page, username = "alice", password = "alice-pw"): Promise<void> {
    await page.goto("/ui/");
    await page.getByTestId("saml-login-btn").click();
    await page.waitForURL(/:9443\/realms\/demo\//);
    await page.locator("#username").fill(username);
    await page.locator("#password").fill(password);
    await page.locator("#kc-login").click();
    await page.waitForURL(/\/ui\/locate/);
}

async function sessionCookie(context: BrowserContext) {
    return (await context.cookies()).find((c) => c.name === SESSION_COOKIE);
}

test.describe("SAML single sign-on — Keycloak, Auth Verifier, KMS", () => {
    test("advertises SAML and rejects anonymous access", async ({ request }) => {
        const methods = await (await request.get("/ui/auth_method")).json();
        expect(methods.auth_methods).toEqual(["AUTH_VERIFIER_SAML"]);
        expect((await request.get("/ui/whoami")).status()).toBe(401);
        expect((await request.post("/kmip/2_1", { data: CREATE_AES_KEY })).status()).toBe(401);
    });

    test("logs in through the IdP and shows the SAML user with a hardened session cookie", async ({ page, context }) => {
        await ssoLogin(page);
        await expect(page.getByTestId("session-user-tag")).toHaveText(SAML_USER);
        await expect(page.getByTestId("logout-btn")).toBeVisible();

        const cookie = await sessionCookie(context);
        expect(cookie, "the Auth Verifier must set the _ea_ session cookie").toBeDefined();
        expect(cookie).toMatchObject({ httpOnly: true, secure: true, sameSite: "Strict", path: "/" });
    });

    test("the session cookie authenticates the KMIP API and the key is owned by the SAML user", async ({ page, context }) => {
        await ssoLogin(page);
        const api = context.request;

        const created = await api.post("/kmip/2_1", { data: CREATE_AES_KEY });
        expect(created.status()).toBe(200);
        const uid = JSON.stringify(await created.json()).match(/"UniqueIdentifier"[^}]*?"value":"([^"]+)"/)?.[1];
        expect(uid, "Create must return the new key UID").toBeTruthy();

        const owned = await (await api.get("/access/owned")).json();
        expect(owned.map((o: { object_id: string }) => o.object_id)).toContain(uid);
        expect((await (await api.get("/ui/whoami")).json()).user_id).toBe(SAML_USER);
    });

    test("CSRF: the cookie is refused for a state-changing request with a CORS-safelisted content type", async ({ page, context }) => {
        await ssoLogin(page);
        const forged = await context.request.post("/kmip/2_1", {
            headers: { "Content-Type": "text/plain" },
            data: JSON.stringify(CREATE_AES_KEY),
        });
        expect(forged.status()).toBe(401);
    });

    test("a session cookie with a forged signature does not authenticate", async ({ page, context, baseURL }) => {
        await ssoLogin(page);
        const real = await sessionCookie(context);
        const [header, payload, signature] = (real?.value ?? "").split(".");
        expect(signature, "the _ea_ cookie must be a signed JWT").toBeTruthy();
        // Alter the first signature character (the last one may only carry base64 padding bits).
        const forgedSignature = (signature[0] === "A" ? "B" : "A") + signature.slice(1);

        const kms = await playwrightRequest.newContext({
            baseURL,
            ignoreHTTPSErrors: true,
            extraHTTPHeaders: { Cookie: `${SESSION_COOKIE}=${header}.${payload}.${forgedSignature}` },
        });
        expect((await kms.get("/ui/whoami")).status()).toBe(401);
        expect((await kms.post("/kmip/2_1", { data: CREATE_AES_KEY })).status()).toBe(401);
        await kms.dispose();
    });

    test("a valid session of another Auth Verifier realm does not authenticate to the KMS", async ({ baseURL }) => {
        // Real, correctly signed `_ea_` token of the Auth Verifier admin realm `_` (dev super-admin).
        const av = await playwrightRequest.newContext({ ignoreHTTPSErrors: true });
        const login = await av.post(`${AUTH_VERIFIER_URL}/login?realm=_`, {
            headers: { Authorization: `Basic ${Buffer.from("admin:change_me").toString("base64")}` },
            data: {},
        });
        expect(login.status()).toBe(200);
        const adminCookie = (await av.storageState()).cookies.find((c) => c.name === SESSION_COOKIE);
        expect(adminCookie, "the Auth Verifier must issue an admin-realm _ea_ cookie").toBeDefined();

        const kms = await playwrightRequest.newContext({
            baseURL,
            ignoreHTTPSErrors: true,
            extraHTTPHeaders: { Cookie: `${SESSION_COOKIE}=${adminCookie?.value}` },
        });
        expect((await kms.get("/ui/whoami")).status()).toBe(401);
        expect((await kms.post("/kmip/2_1", { data: CREATE_AES_KEY })).status()).toBe(401);
        await av.dispose();
        await kms.dispose();
    });

    test("logout expires the cookie and revokes the session on the Auth Verifier", async ({ page, context }) => {
        await ssoLogin(page);
        const before = await sessionCookie(context);
        expect(before).toBeDefined();
        // `GET /whoami` on the Auth Verifier answers 200 only while the session exists in its store.
        const av = await playwrightRequest.newContext({
            ignoreHTTPSErrors: true,
            extraHTTPHeaders: { Cookie: `${SESSION_COOKIE}=${before?.value}` },
        });
        expect((await av.get(`${AUTH_VERIFIER_URL}/whoami`)).status(), "live before logout").toBe(200);

        await page.getByTestId("logout-btn").click();
        await page.waitForURL(/\/ui\/login/);
        expect(await sessionCookie(context)).toBeUndefined();
        expect((await context.request.get("/ui/whoami")).status()).toBe(401);
        expect((await av.get(`${AUTH_VERIFIER_URL}/whoami`)).status(), "revoked by logout").toBe(401);
        await av.dispose();
    });
});
