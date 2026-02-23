import { screen } from "@testing-library/react";
import React from "react";
import { expect, test } from "vitest";

import Footer from "../../../src/Footer";
import { smokeRender } from "../test-utils";

test("renders Footer", () => {
    smokeRender(React.createElement(Footer, { version: "test-version" }));
    expect(screen.getByText(/KMS Server Version:/i)).toBeInTheDocument();
});
