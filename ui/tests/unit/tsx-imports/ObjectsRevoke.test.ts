import React from "react";
import { expect, test } from "vitest";

import ObjectsRevoke from "../../../src/actions/Objects/ObjectsRevoke";
import { smokeRender } from "../test-utils";

test("renders ObjectsRevoke form", () => {
    const { container } = smokeRender(React.createElement(ObjectsRevoke, { objectType: "rsa" }));
    expect(container).toHaveTextContent(/Revoke/i);
});
