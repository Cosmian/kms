import React from "react";
import { expect, test } from "vitest";

import LoginPage from "../../../src/pages/LoginPage";
import { smokeRender } from "../test-utils";

test("renders LoginPage", () => {
    const { container } = smokeRender(React.createElement(LoginPage, { auth: true }));
    expect(container).toHaveTextContent(/LOGIN/i);
});
