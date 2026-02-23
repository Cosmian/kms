import { screen } from "@testing-library/react";
import React from "react";
import { expect, test } from "vitest";

import CertificateExport from "../../../src/CertificateExport";
import { smokeRender } from "../test-utils";

test("renders CertificateExport", () => {
    smokeRender(React.createElement(CertificateExport));
    expect(screen.getByRole("heading", { name: "Export Certificate" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Export Certificate" })).toBeInTheDocument();
});
