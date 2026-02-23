import { screen } from "@testing-library/react";
import React from "react";
import { expect, test } from "vitest";

import CertificateValidate from "../../../src/CertificateValidate";
import { smokeRender } from "../test-utils";

test("renders CertificateValidate", () => {
    smokeRender(React.createElement(CertificateValidate));
    expect(screen.getByRole("heading", { name: "Validate Certificates" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Validate Certificate" })).toBeInTheDocument();
});
