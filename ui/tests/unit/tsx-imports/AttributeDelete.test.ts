import { screen } from "@testing-library/react";
import React from "react";
import { expect, test } from "vitest";

import AttributeDelete from "../../../src/AttributeDelete";
import { smokeRender } from "../test-utils";

test("renders AttributeDelete", () => {
    smokeRender(React.createElement(AttributeDelete));
    expect(screen.getByRole("heading", { name: "Delete KMIP Object Attribute", level: 2 })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Delete Attribute" })).toBeInTheDocument();
});
