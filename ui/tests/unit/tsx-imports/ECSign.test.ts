import { screen } from "@testing-library/react";
import React from "react";
import { expect, test } from "vitest";

import ECSign from "../../../src/ECSign";
import { smokeRender } from "../test-utils";

test("renders ECSign", () => {
    smokeRender(React.createElement(ECSign));
    expect(screen.getByRole("heading", { name: "Elliptic Curve Sign" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Sign File" })).toBeInTheDocument();
});
