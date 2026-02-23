import { screen } from "@testing-library/react";
import React from "react";
import { expect, test } from "vitest";

import HashMapDisplay from "../../../src/HashMapDisplay";
import { smokeRender } from "../test-utils";

test("renders HashMapDisplay when data provided", () => {
    const data = new Map([
        ["a", 1],
        ["b", "two"],
    ]);

    smokeRender(React.createElement(HashMapDisplay, { data }));
    expect(screen.getByText(/HashMap Display/i)).toBeInTheDocument();
});
