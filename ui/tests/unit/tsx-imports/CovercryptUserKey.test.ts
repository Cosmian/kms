import { screen } from "@testing-library/react";
import React from "react";
import { expect, test } from "vitest";

import CovercryptUserKey from "../../../src/CovercryptUserKey";
import { smokeRender } from "../test-utils";

test("renders CovercryptUserKey", () => {
    smokeRender(React.createElement(CovercryptUserKey));
    expect(screen.getByRole("heading", { name: "Create a Covercrypt user key" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Create User Key" })).toBeInTheDocument();
});
