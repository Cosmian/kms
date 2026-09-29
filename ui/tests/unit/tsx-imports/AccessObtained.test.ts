import { screen } from "@testing-library/react";
import React from "react";
import { expect, test } from "vitest";

import AccessObtained from "../../../src/actions/Access/AccessObtained";
import { smokeRender } from "../test-utils";

test("renders AccessObtained", () => {
    smokeRender(React.createElement(AccessObtained));
    expect(screen.getByRole("heading", { name: "Access rights obtained" })).toBeInTheDocument();
    // Button may be in loading state since fetch starts immediately on mount
    expect(screen.getByRole("button", { name: /Refresh/ })).toBeInTheDocument();
    expect(screen.getByText("Create access right")).toBeInTheDocument();
});
