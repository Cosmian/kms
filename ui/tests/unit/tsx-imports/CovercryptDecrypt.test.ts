import { screen } from "@testing-library/react";
import React from "react";
import { expect, test } from "vitest";

import CovercryptDecrypt from "../../../src/CovercryptDecrypt";
import { smokeRender } from "../test-utils";

test("renders CovercryptDecrypt", () => {
    smokeRender(React.createElement(CovercryptDecrypt));
    expect(screen.getByRole("heading", { name: "Covercrypt Decryption" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Decrypt File" })).toBeInTheDocument();
});
