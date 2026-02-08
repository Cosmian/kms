import { screen } from "@testing-library/react";
import React from "react";
import { expect, test } from "vitest";

import RsaEncrypt from "../../../src/RsaEncrypt";
import { smokeRender } from "../test-utils";

test("renders RsaEncrypt", () => {
    smokeRender(React.createElement(RsaEncrypt));
    expect(screen.getByRole("heading", { name: "RSA Encryption" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Encrypt File" })).toBeInTheDocument();
});
