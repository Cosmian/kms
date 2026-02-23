import React from "react";
import { expect, test } from "vitest";

import KeysExport from "../../../src/KeysExport";
import { smokeRender } from "../test-utils";

test("renders KeysExport form", () => {
    const { container } = smokeRender(React.createElement(KeysExport, { key_type: "rsa" }));
    expect(container).toHaveTextContent(/Export/i);
});
