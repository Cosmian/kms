import { screen } from "@testing-library/react";
import React from "react";
import { expect, test } from "vitest";

import SecretDataCreate from "../../../src/SecretDataCreate";
import { smokeRender } from "../test-utils";

test("renders SecretDataCreate", () => {
    smokeRender(React.createElement(SecretDataCreate));
    expect(screen.getByRole("heading", { name: "Create a new secret data" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Create Secret Data" })).toBeInTheDocument();
});
