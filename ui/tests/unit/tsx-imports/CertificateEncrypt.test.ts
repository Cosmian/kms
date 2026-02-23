import { screen } from "@testing-library/react";
import React from "react";
import { expect, test } from "vitest";

import CertificateEncrypt from "../../../src/CertificateEncrypt";
import { smokeRender } from "../test-utils";

test("renders CertificateEncrypt", () => {
    smokeRender(React.createElement(CertificateEncrypt));
    expect(screen.getByRole("heading", { name: "Certificate Encryption" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Encrypt File/i })).toBeInTheDocument();
});
