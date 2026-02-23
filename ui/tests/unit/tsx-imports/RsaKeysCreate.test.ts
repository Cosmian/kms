import { screen } from "@testing-library/react";
import React from "react";
import { expect, test } from "vitest";

import RsaKeysCreate from "../../../src/RsaKeysCreate";
import { smokeRender } from "../test-utils";

test("renders RsaKeysCreate", () => {
    smokeRender(React.createElement(RsaKeysCreate));
    expect(screen.getByRole("heading", { name: "Create an RSA key pair" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Create RSA Keypair" })).toBeInTheDocument();
});
