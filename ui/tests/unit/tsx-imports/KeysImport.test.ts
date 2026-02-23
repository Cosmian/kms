import React from "react";
import { expect, test } from "vitest";

import KeysImport from "../../../src/KeysImport";
import { smokeRender } from "../test-utils";

test("renders KeysImport form", () => {
    const { container } = smokeRender(React.createElement(KeysImport, { key_type: "rsa" }));
    expect(container).toHaveTextContent(/Import/i);
});
