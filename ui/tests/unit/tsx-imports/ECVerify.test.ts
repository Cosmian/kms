import { screen } from "@testing-library/react";
import React from "react";
import { expect, test } from "vitest";

import ECVerify from "../../../src/ECVerify";
import { smokeRender } from "../test-utils";

test("renders ECVerify", () => {
    smokeRender(React.createElement(ECVerify));
    expect(screen.getByRole("heading", { name: "Elliptic Curve Verify" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Verify Signature" })).toBeInTheDocument();
});
