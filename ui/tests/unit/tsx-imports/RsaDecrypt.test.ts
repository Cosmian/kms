import { screen } from "@testing-library/react";
import React from "react";
import { expect, test } from "vitest";

import RsaDecrypt from "../../../src/RsaDecrypt";
import { smokeRender } from "../test-utils";

test("renders RsaDecrypt", () => {
    smokeRender(React.createElement(RsaDecrypt));
    expect(screen.getByRole("heading", { name: "RSA Decryption" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Decrypt File" })).toBeInTheDocument();
});
