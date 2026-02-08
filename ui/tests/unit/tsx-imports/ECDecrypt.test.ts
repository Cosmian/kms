import { screen } from "@testing-library/react";
import React from "react";
import { expect, test } from "vitest";

import ECDecrypt from "../../../src/ECDecrypt";
import { smokeRender } from "../test-utils";

test("renders ECDecrypt", () => {
    smokeRender(React.createElement(ECDecrypt));
    expect(screen.getByRole("heading", { name: "EC Decryption" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Decrypt File" })).toBeInTheDocument();
});
