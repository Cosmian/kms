import { screen } from "@testing-library/react";
import React from "react";
import { expect, test } from "vitest";

import CovercryptEncrypt from "../../../src/actions/Covercrypt/CovercryptEncrypt";
import { smokeRender } from "../test-utils";

test("renders CovercryptEncrypt", () => {
    smokeRender(React.createElement(CovercryptEncrypt));
    expect(screen.getByRole("heading", { name: "Covercrypt Encryption" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Encrypt File" })).toBeInTheDocument();
});
