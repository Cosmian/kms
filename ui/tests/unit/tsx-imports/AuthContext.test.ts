import { render, screen } from "@testing-library/react";
import React from "react";
import { expect, test } from "vitest";

import { AuthProvider, useAuth } from "../../../src/AuthContext";

test("useAuth throws outside provider", () => {
    const Consumer = () => {
        useAuth();
        return null;
    };

    expect(() => render(React.createElement(Consumer))).toThrow(/AuthProvider/i);
});

test("AuthProvider provides default values", () => {
    const Consumer = () => {
        const { serverUrl, idToken, userId } = useAuth();
        return React.createElement("div", {}, `${serverUrl}|${idToken}|${userId}`);
    };

    render(React.createElement(AuthProvider, {}, React.createElement(Consumer)));
    expect(screen.getByText(/^\|null\|null$/)).toBeInTheDocument();
});
