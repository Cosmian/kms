import { screen } from "@testing-library/react";
import React from "react";
import { expect, test } from "vitest";

import AzureImportKek from "../../../src/AzureImportKek";
import { smokeRender } from "../test-utils";

test("renders AzureImportKek", () => {
    smokeRender(React.createElement(AzureImportKek));
    expect(screen.getByRole("heading", { name: "Import Azure Key Encryption Key (KEK)" })).toBeInTheDocument();
    expect(screen.getByText("KEK File (required)")).toBeInTheDocument();
});
