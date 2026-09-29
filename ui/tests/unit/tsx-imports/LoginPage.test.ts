import React from "react";
import { expect, test } from "vitest";

import LoginPage from "../../../src/pages/LoginPage";
import { shouldAutoLoginWithCert } from "../../../src/utils/utils";
import { smokeRender } from "../test-utils";

test("renders LoginPage OIDC primary button", () => {
    const { container } = smokeRender(React.createElement(LoginPage, { auth: true, authMethods: ["JWT"] }));
    expect(container.querySelector('[data-testid="oidc-login-btn"]')).not.toBeNull();
    expect(container).toHaveTextContent(/OIDC/i);
});

test("renders LoginPage AUTH_VERIFIER username/password form", () => {
    const { container } = smokeRender(React.createElement(LoginPage, { auth: false, authMethods: ["AUTH_VERIFIER"] }));
    expect(container.querySelector('[data-testid="auth-verifier-login-form"]')).not.toBeNull();
    expect(container.querySelector('input[placeholder="Username"]')).not.toBeNull();
    expect(container.querySelector('input[placeholder="Password"]')).not.toBeNull();
});

test("renders LoginPage CERT primary button", () => {
    const { container } = smokeRender(React.createElement(LoginPage, { auth: false, authMethods: ["CERT"] }));
    expect(container.querySelector('[data-testid="cert-login-btn"]')).not.toBeNull();
    expect(container).toHaveTextContent(/Client certificate/i);
});

test("single method has no secondary control", () => {
    const { container } = smokeRender(React.createElement(LoginPage, { auth: true, authMethods: ["JWT"] }));
    expect(container.querySelector('[data-testid="login-secondary-btn"]')).toBeNull();
    expect(container.querySelector('[data-testid="login-secondary-dropdown"]')).toBeNull();
});

test("two methods render primary + a single secondary button", () => {
    // Primary = JWT (priority order), secondary = the one alternative (CERT).
    const { container } = smokeRender(React.createElement(LoginPage, { auth: true, authMethods: ["JWT", "CERT"] }));
    expect(container.querySelector('[data-testid="oidc-login-btn"]')).not.toBeNull();
    const secondary = container.querySelector('[data-testid="login-secondary-btn"]');
    expect(secondary).not.toBeNull();
    expect(secondary).toHaveTextContent(/Client certificate/i);
    expect(container.querySelector('[data-testid="login-secondary-dropdown"]')).toBeNull();
});

test("three methods render primary + a secondary dropdown", () => {
    const { container } = smokeRender(React.createElement(LoginPage, { auth: true, authMethods: ["JWT", "AUTH_VERIFIER", "CERT"] }));
    expect(container.querySelector('[data-testid="oidc-login-btn"]')).not.toBeNull();
    expect(container.querySelector('[data-testid="login-secondary-dropdown"]')).not.toBeNull();
    expect(container.querySelector('[data-testid="login-secondary-btn"]')).toBeNull();
});

// shouldAutoLoginWithCert: only true when CERT is the sole configured method.
test("shouldAutoLoginWithCert: true for CERT-only", () => {
    expect(shouldAutoLoginWithCert(["CERT"])).toBe(true);
});
test("shouldAutoLoginWithCert: false for JWT+CERT", () => {
    expect(shouldAutoLoginWithCert(["JWT", "CERT"])).toBe(false);
});
test("shouldAutoLoginWithCert: false for AUTH_VERIFIER+CERT", () => {
    expect(shouldAutoLoginWithCert(["AUTH_VERIFIER", "CERT"])).toBe(false);
});
test("shouldAutoLoginWithCert: false for JWT alone", () => {
    expect(shouldAutoLoginWithCert(["JWT"])).toBe(false);
});
test("shouldAutoLoginWithCert: false for empty list", () => {
    expect(shouldAutoLoginWithCert([])).toBe(false);
});
