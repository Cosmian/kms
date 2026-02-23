import { screen } from "@testing-library/react";
import React from "react";
import { expect, test } from "vitest";

import RsaVerify from "../../../src/RsaVerify";
import { smokeRender } from "../test-utils";

test("renders RsaVerify", () => {
    smokeRender(React.createElement(RsaVerify));
    expect(screen.getByRole("heading", { name: "RSA Verify" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Verify Signature" })).toBeInTheDocument();
});
