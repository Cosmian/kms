import { screen } from "@testing-library/react";
import React from "react";
import { expect, test } from "vitest";

import SymmetricDecrypt from "../../../src/SymmetricDecrypt";
import { smokeRender } from "../test-utils";

test("renders SymmetricDecrypt", () => {
    smokeRender(React.createElement(SymmetricDecrypt));
    expect(screen.getByRole("heading", { name: "Symmetric Decryption" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Decrypt File" })).toBeInTheDocument();
});
