import { screen } from "@testing-library/react";
import React from "react";
import { expect, test } from "vitest";

import AccessObtained from "../../../src/AccessObtained";
import { smokeRender } from "../test-utils";

test("renders AccessObtained", () => {
    smokeRender(React.createElement(AccessObtained));
    expect(screen.getByRole("heading", { name: "Access rights obtained" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Refresh" })).toBeInTheDocument();
    expect(screen.getByText("Create access right")).toBeInTheDocument();
});
