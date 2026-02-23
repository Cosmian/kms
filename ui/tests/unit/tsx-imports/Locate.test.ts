import { screen } from "@testing-library/react";
import React from "react";
import { expect, test } from "vitest";

import Locate from "../../../src/Locate";
import { smokeRender } from "../test-utils";

test("renders Locate", () => {
    smokeRender(React.createElement(Locate));
    expect(screen.getByRole("heading", { name: "Locate Cryptographic Objects" })).toBeInTheDocument();
    expect(screen.getByText("Basic Search Criteria")).toBeInTheDocument();
    expect(screen.getByLabelText("Tags")).toBeInTheDocument();
});
