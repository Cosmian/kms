import { screen } from "@testing-library/react";
import React from "react";
import { expect, test } from "vitest";

import ECKeysCreate from "../../../src/ECKeysCreate";
import { smokeRender } from "../test-utils";

test("renders ECKeysCreate", () => {
    smokeRender(React.createElement(ECKeysCreate));
    expect(screen.getByRole("heading", { name: "Create an EC key pair" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Create EC Keypair" })).toBeInTheDocument();
});
