import { screen } from "@testing-library/react";
import React from "react";
import { expect, test } from "vitest";

import SymmetricEncrypt from "../../../src/SymmetricEncrypt";
import { smokeRender } from "../test-utils";

test("renders SymmetricEncrypt", () => {
    smokeRender(React.createElement(SymmetricEncrypt));
    expect(screen.getByRole("heading", { name: "Symmetric Encryption" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Encrypt File/i })).toBeInTheDocument();
});
