import { screen } from "@testing-library/react";
import React from "react";
import { expect, test } from "vitest";

import ECEncrypt from "../../../src/ECEncrypt";
import { smokeRender } from "../test-utils";

test("renders ECEncrypt", () => {
    smokeRender(React.createElement(ECEncrypt));
    expect(screen.getByRole("heading", { name: "EC Encryption" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Encrypt File" })).toBeInTheDocument();
});
