/**
 * Centralised KMS UI route map for E2E tests.
 *
 * Keep all UI path strings here.  Individual spec files import only the routes
 * they need, avoiding duplicated string literals.  `sitemap.spec.ts` imports
 * `ALL_ROUTES` to run a single navigation pass across the entire application.
 */

export interface Route {
    /** Human-readable label used as part of the Playwright test name. */
    name: string;
    /** URL path relative to the Playwright baseURL (starts with /ui). */
    path: string;
    /**
     * CSS selector used by `sitemap.spec.ts` to verify the page rendered.
     * Defaults to `[data-testid="submit-btn"]` if omitted (form pages).
     * List / info pages that render a heading but no submit button should
     * set this to `'h1'`.
     */
    locator?: string;
}

// ── Symmetric Key routes ─────────────────────────────────────────────────────
export const SYM_KEY_ROUTES: Route[] = [
    { name: "create", path: "/ui/sym/keys/create" },
    { name: "export", path: "/ui/sym/keys/export" },
    { name: "import", path: "/ui/sym/keys/import" },
    { name: "revoke", path: "/ui/sym/keys/revoke" },
    { name: "destroy", path: "/ui/sym/keys/destroy" },
    { name: "encrypt", path: "/ui/sym/encrypt" },
    { name: "decrypt", path: "/ui/sym/decrypt" },
];

// ── RSA Key routes ───────────────────────────────────────────────────────────
export const RSA_KEY_ROUTES: Route[] = [
    { name: "create", path: "/ui/rsa/keys/create" },
    { name: "export", path: "/ui/rsa/keys/export" },
    { name: "import", path: "/ui/rsa/keys/import" },
    { name: "revoke", path: "/ui/rsa/keys/revoke" },
    { name: "destroy", path: "/ui/rsa/keys/destroy" },
    { name: "encrypt", path: "/ui/rsa/encrypt" },
    { name: "decrypt", path: "/ui/rsa/decrypt" },
    { name: "sign", path: "/ui/rsa/sign" },
    { name: "verify", path: "/ui/rsa/verify" },
];

// ── EC Key routes ────────────────────────────────────────────────────────────
export const EC_KEY_ROUTES: Route[] = [
    { name: "create", path: "/ui/ec/keys/create" },
    { name: "export", path: "/ui/ec/keys/export" },
    { name: "import", path: "/ui/ec/keys/import" },
    { name: "revoke", path: "/ui/ec/keys/revoke" },
    { name: "destroy", path: "/ui/ec/keys/destroy" },
    { name: "encrypt", path: "/ui/ec/encrypt" },
    { name: "decrypt", path: "/ui/ec/decrypt" },
    { name: "sign", path: "/ui/ec/sign" },
    { name: "verify", path: "/ui/ec/verify" },
];

// ── Covercrypt Key routes ────────────────────────────────────────────────────
export const CC_KEY_ROUTES: Route[] = [
    { name: "create master key pair", path: "/ui/cc/keys/create-master-key-pair" },
    { name: "create user key", path: "/ui/cc/keys/create-user-key" },
    { name: "export", path: "/ui/cc/keys/export" },
    { name: "import", path: "/ui/cc/keys/import" },
    { name: "revoke", path: "/ui/cc/keys/revoke" },
    { name: "destroy", path: "/ui/cc/keys/destroy" },
    { name: "encrypt", path: "/ui/cc/encrypt" },
    { name: "decrypt", path: "/ui/cc/decrypt" },
];

// ── Certificate routes ───────────────────────────────────────────────────────
export const CERT_ROUTES: Route[] = [
    { name: "certify", path: "/ui/certificates/certs/certify" },
    { name: "export", path: "/ui/certificates/certs/export" },
    { name: "import", path: "/ui/certificates/certs/import" },
    { name: "revoke", path: "/ui/certificates/certs/revoke" },
    { name: "destroy", path: "/ui/certificates/certs/destroy" },
    { name: "validate", path: "/ui/certificates/certs/validate" },
    { name: "encrypt", path: "/ui/certificates/encrypt" },
    { name: "decrypt", path: "/ui/certificates/decrypt" },
];

// ── Opaque Object routes ─────────────────────────────────────────────────────
export const OPAQUE_ROUTES: Route[] = [
    { name: "create", path: "/ui/opaque-object/create" },
    { name: "export", path: "/ui/opaque-object/export" },
    { name: "import", path: "/ui/opaque-object/import" },
    { name: "revoke", path: "/ui/opaque-object/revoke" },
    { name: "destroy", path: "/ui/opaque-object/destroy" },
];

// ── Attributes routes ────────────────────────────────────────────────────────
export const ATTRIBUTES_ROUTES: Route[] = [
    { name: "get", path: "/ui/attributes/get" },
    { name: "set", path: "/ui/attributes/set" },
    { name: "modify", path: "/ui/attributes/modify" },
    { name: "delete", path: "/ui/attributes/delete" },
];

// ── Access Rights routes ─────────────────────────────────────────────────────
export const ACCESS_RIGHTS_ROUTES: Route[] = [
    { name: "grant", path: "/ui/access-rights/grant" },
    { name: "revoke", path: "/ui/access-rights/revoke" },
    { name: "list", path: "/ui/access-rights/list" },
    // "owned" and "obtained" are read-only list pages with no submit button.
    { name: "owned", path: "/ui/access-rights/owned", locator: "h1" },
    { name: "obtained", path: "/ui/access-rights/obtained", locator: "h1" },
];

// ── Azure BYOK routes ────────────────────────────────────────────────────────
export const AZURE_ROUTES: Route[] = [
    { name: "import KEK", path: "/ui/azure/import-kek" },
    { name: "export BYOK", path: "/ui/azure/export-byok" },
];

// ── Standalone page routes ───────────────────────────────────────────────────
// Google CSE is an info page that shows a heading but has no submit button.
export const GOOGLE_CSE_ROUTES: Route[] = [{ name: "Google CSE", path: "/ui/google-cse", locator: "h1" }];

export const LOCATE_ROUTES: Route[] = [{ name: "locate", path: "/ui/locate" }];

/**
 * All application routes, grouped by section.
 *
 * Used by `sitemap.spec.ts` to verify every page is reachable and renders its
 * primary action button.
 */
export const ALL_ROUTES: { section: string; routes: Route[] }[] = [
    { section: "Symmetric Keys", routes: SYM_KEY_ROUTES },
    { section: "RSA Keys", routes: RSA_KEY_ROUTES },
    { section: "EC Keys", routes: EC_KEY_ROUTES },
    { section: "Covercrypt Keys", routes: CC_KEY_ROUTES },
    { section: "Certificates", routes: CERT_ROUTES },
    { section: "Opaque Objects", routes: OPAQUE_ROUTES },
    { section: "Attributes", routes: ATTRIBUTES_ROUTES },
    { section: "Access Rights", routes: ACCESS_RIGHTS_ROUTES },
    { section: "Azure", routes: AZURE_ROUTES },
    { section: "Google CSE", routes: GOOGLE_CSE_ROUTES },
    { section: "Locate", routes: LOCATE_ROUTES },
];
