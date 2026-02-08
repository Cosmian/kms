import { screen } from "@testing-library/react";
import React from "react";
import { expect, test } from "vitest";

import NotFoundPage from "../../../src/NotFoundPage";
import { smokeRender } from "../test-utils";

test("renders NotFoundPage", () => {
    smokeRender(React.createElement(NotFoundPage));
    expect(screen.getByText(/404 - Page Not Found/i)).toBeInTheDocument();
});
