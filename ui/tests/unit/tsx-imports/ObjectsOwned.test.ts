import React from "react";
import { expect, test } from "vitest";

import ObjectsOwned from "../../../src/actions/Objects/ObjectsOwned";
import { smokeRender } from "../test-utils";

test("renders ObjectsOwned", () => {
    const { container } = smokeRender(React.createElement(ObjectsOwned));
    expect(container).toHaveTextContent(/Objects owned/i);
});
