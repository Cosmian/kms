import { screen } from "@testing-library/react";
import React from "react";
import { expect, test } from "vitest";

import CertificateImport from "../../../src/CertificateImport";
import { smokeRender } from "../test-utils";

test("renders CertificateImport", () => {
    smokeRender(React.createElement(CertificateImport));
    expect(screen.getByRole("heading", { name: "Import Certificate" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Import Certificate" })).toBeInTheDocument();
});
