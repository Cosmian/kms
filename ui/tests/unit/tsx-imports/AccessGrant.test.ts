import { screen } from "@testing-library/react";
import React from "react";
import { expect, test } from "vitest";

import AccessGrant from "../../../src/AccessGrant";
import { smokeRender } from "../test-utils";

test("renders AccessGrant", () => {
    smokeRender(React.createElement(AccessGrant));
    expect(screen.getByRole("heading", { name: "Grant access rights" })).toBeInTheDocument();
    expect(screen.getByPlaceholderText("Enter object UID")).toBeDisabled();
    expect(screen.getByRole("button", { name: "Grant Access" })).toBeInTheDocument();
});
