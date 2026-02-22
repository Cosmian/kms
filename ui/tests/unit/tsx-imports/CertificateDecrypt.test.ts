import { screen } from "@testing-library/react";
import React from "react";
import { expect, test } from "vitest";

import CertificateDecrypt from "../../../src/CertificateDecrypt";
import { smokeRender } from "../test-utils";

test("renders CertificateDecrypt", () => {
    smokeRender(React.createElement(CertificateDecrypt));
    expect(screen.getByRole("heading", { name: "Certificate Decryption" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Decrypt File" })).toBeInTheDocument();
});
