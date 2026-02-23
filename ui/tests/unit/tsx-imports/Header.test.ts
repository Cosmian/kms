import { screen } from "@testing-library/react";
import React from "react";
import { expect, test } from "vitest";

import Header from "../../../src/Header";
import { smokeRender } from "../test-utils";

test("renders Header", () => {
    smokeRender(React.createElement(Header, { isDarkMode: false }));
    expect(screen.getByText("Key Management System")).toBeInTheDocument();
});
