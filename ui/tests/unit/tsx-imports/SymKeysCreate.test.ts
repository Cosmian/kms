import { screen } from "@testing-library/react";
import React from "react";
import { expect, test } from "vitest";

import SymKeysCreate from "../../../src/SymKeysCreate";
import { smokeRender } from "../test-utils";

test("renders SymKeysCreate", () => {
    smokeRender(React.createElement(SymKeysCreate));
    expect(screen.getByRole("heading", { name: "Create a symmetric key" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Create Symmetric Key" })).toBeInTheDocument();
});
