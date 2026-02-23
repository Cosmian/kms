import { screen } from "@testing-library/react";
import React from "react";
import { expect, test } from "vitest";

import AzureExportByok from "../../../src/AzureExportByok";
import { smokeRender } from "../test-utils";

test("renders AzureExportByok", () => {
    smokeRender(React.createElement(AzureExportByok));
    expect(screen.getByRole("heading", { name: "Export Azure BYOK File" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Export BYOK File" })).toBeInTheDocument();
});
