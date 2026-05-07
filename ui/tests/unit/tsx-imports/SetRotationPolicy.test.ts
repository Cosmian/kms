import React from "react";
import { expect, test } from "vitest";

import SetRotationPolicy from "../../../src/actions/Keys/SetRotationPolicy";
import { smokeRender } from "../test-utils";

test("renders SetRotationPolicy form for symmetric key", () => {
    const { container } = smokeRender(React.createElement(SetRotationPolicy, { objectType: "symmetric" }));
    expect(container).toHaveTextContent(/rotation policy/i);
    expect(container).toHaveTextContent(/Set Rotation Policy/i);
});

test("renders SetRotationPolicy form for rsa key", () => {
    const { container } = smokeRender(React.createElement(SetRotationPolicy, { objectType: "rsa" }));
    expect(container).toHaveTextContent(/rotation policy/i);
});
