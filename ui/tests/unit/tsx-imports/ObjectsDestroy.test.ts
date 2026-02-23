import React from "react";
import { expect, test } from "vitest";

import ObjectsDestroy from "../../../src/ObjectsDestroy";
import { smokeRender } from "../test-utils";

test("renders ObjectsDestroy form", () => {
    const { container } = smokeRender(React.createElement(ObjectsDestroy, { objectType: "rsa" }));
    expect(container).toHaveTextContent(/Destroy/i);
});
