import { screen } from "@testing-library/react";
import React from "react";
import { expect, test } from "vitest";

import CseInfo from "../../../src/CseInfo";
import { smokeRender } from "../test-utils";

test("renders CseInfo", () => {
    smokeRender(React.createElement(CseInfo));
    expect(screen.getByRole("heading", { name: "CSE Information" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Refresh/i })).toBeInTheDocument();
});
