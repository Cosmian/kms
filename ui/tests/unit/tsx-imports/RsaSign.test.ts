import { screen } from "@testing-library/react";
import React from "react";
import { expect, test } from "vitest";

import RsaSign from "../../../src/RsaSign";
import { smokeRender } from "../test-utils";

test("renders RsaSign", () => {
    smokeRender(React.createElement(RsaSign));
    expect(screen.getByRole("heading", { name: "RSA Sign" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Sign File" })).toBeInTheDocument();
});
