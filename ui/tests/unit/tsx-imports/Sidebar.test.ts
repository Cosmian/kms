import { screen } from "@testing-library/react";
import React from "react";
import { expect, test } from "vitest";

import Sidebar from "../../../src/Sidebar";
import { smokeRender } from "../test-utils";

test("renders Sidebar", () => {
    smokeRender(React.createElement(Sidebar));
    expect(screen.getByText("Locate")).toBeInTheDocument();
    expect(screen.getByText("Symmetric")).toBeInTheDocument();
    expect(screen.getByText("RSA")).toBeInTheDocument();
});
