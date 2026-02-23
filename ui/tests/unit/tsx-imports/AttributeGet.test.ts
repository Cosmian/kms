import { screen } from "@testing-library/react";
import React from "react";
import { expect, test } from "vitest";

import AttributeGet from "../../../src/AttributeGet";
import { smokeRender } from "../test-utils";

test("renders AttributeGet", () => {
    smokeRender(React.createElement(AttributeGet));
    expect(screen.getByRole("heading", { name: "Get KMIP Object Attributes", level: 2 })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Get Attributes" })).toBeInTheDocument();
});
