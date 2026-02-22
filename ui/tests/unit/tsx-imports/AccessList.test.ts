import { screen } from "@testing-library/react";
import React from "react";
import { expect, test } from "vitest";

import AccessList from "../../../src/AccessList";
import { smokeRender } from "../test-utils";

test("renders AccessList", () => {
    smokeRender(React.createElement(AccessList));
    expect(screen.getByRole("heading", { name: "List an object access rights" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "List Access Rights" })).toBeInTheDocument();
});
