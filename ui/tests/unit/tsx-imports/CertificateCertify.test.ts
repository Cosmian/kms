import { screen } from "@testing-library/react";
import React from "react";
import { expect, test } from "vitest";

import CertificateCertify from "../../../src/CertificateCertify";
import { smokeRender } from "../test-utils";

test("renders CertificateCertify", () => {
    smokeRender(React.createElement(CertificateCertify));
    expect(screen.getByRole("heading", { name: "Certificate Issuance and Renewal" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Issue/Renew Certificate" })).toBeInTheDocument();
});
