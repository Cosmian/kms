import { screen } from "@testing-library/react";
import React from "react";
import { expect, test } from "vitest";

import AccessRevoke from "../../../src/AccessRevoke";
import { smokeRender } from "../test-utils";

test("renders AccessRevoke", () => {
    smokeRender(React.createElement(AccessRevoke));
    expect(screen.getByRole("heading", { name: "Revoke access rights" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Revoke Access" })).toBeInTheDocument();
});
