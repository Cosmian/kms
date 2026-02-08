import { screen } from "@testing-library/react";
import React from "react";
import { expect, test } from "vitest";

import OpaqueObject from "../../../src/OpaqueObject";
import { smokeRender } from "../test-utils";

test("renders OpaqueObject", () => {
    smokeRender(React.createElement(OpaqueObject));
    expect(screen.getByRole("heading", { name: "Create a new opaque object" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Create Opaque Object" })).toBeInTheDocument();
});
