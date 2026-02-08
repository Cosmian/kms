import { screen } from "@testing-library/react";
import React from "react";
import { expect, test } from "vitest";

import AttributeSet from "../../../src/AttributeSet";
import { smokeRender } from "../test-utils";

test("renders AttributeSet", () => {
    smokeRender(React.createElement(AttributeSet));
    expect(screen.getByRole("heading", { name: "Set KMIP Object Attribute", level: 2 })).toBeInTheDocument();
    expect(screen.getByPlaceholderText("First select an attribute name")).toBeDisabled();
    expect(screen.getByRole("button", { name: "Set Attribute" })).toBeInTheDocument();
});
