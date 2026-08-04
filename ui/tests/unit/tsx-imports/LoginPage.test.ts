import React from "react";
import { expect, test } from "vitest";

import LoginPage from "../../../src/pages/LoginPage";
import { smokeRender } from "../test-utils";

test("renders LoginPage", () => {
    const { container } = smokeRender(React.createElement(LoginPage, { auth: true }));
    expect(container).toHaveTextContent(/LOGIN/i);
});

test("renders LoginPage AUTH_VERIFIER username/password form", () => {
    const { container } = smokeRender(React.createElement(LoginPage, { auth: false, authMethod: "AUTH_VERIFIER" }));
    expect(container).toHaveTextContent(/LOGIN/i);
    expect(container.querySelector('input[placeholder="Username"]')).not.toBeNull();
    expect(container.querySelector('input[placeholder="Password"]')).not.toBeNull();
});
