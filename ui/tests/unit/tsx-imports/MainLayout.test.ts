import React from "react";
import { expect, test } from "vitest";

import MainLayout from "../../../src/MainLayout";
import { smokeRender } from "../test-utils";

test("renders MainLayout with an Outlet child", () => {
    const element = React.createElement(MainLayout, {
        isDarkMode: false,
        setIsDarkMode: () => {},
        authMethod: "None",
    });

    const { container } = smokeRender(element, { withRoutes: true, path: "/" });
    expect(container).toHaveTextContent(/Download CLI|Key Management System/i);
});
