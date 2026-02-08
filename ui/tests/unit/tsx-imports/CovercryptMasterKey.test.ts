import { screen } from "@testing-library/react";
import React from "react";
import { expect, test } from "vitest";

import CovercryptMasterKey from "../../../src/CovercryptMasterKey";
import { smokeRender } from "../test-utils";

test("renders CovercryptMasterKey", () => {
    smokeRender(React.createElement(CovercryptMasterKey));
    expect(screen.getByRole("heading", { name: "Create a Covercrypt master key pair" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Create Master Key/i })).toBeInTheDocument();
});
