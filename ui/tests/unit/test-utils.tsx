import { render, type RenderResult } from "@testing-library/react";
import React from "react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { BrandingProvider } from "../../src/contexts/BrandingProvider";

import { AuthProvider } from "../../src/contexts/AuthContext";
import { AuthContext } from "../../src/contexts/AuthContextDef";

type SmokeRenderOptions = {
    route?: string;
    withRoutes?: boolean;
    path?: string;
    outlet?: React.ReactElement;
    /** Pre-populate userId in AuthContext (e.g. for tests that need the caller's identity). */
    initialUserId?: string;
};

const mockBranding = {
    title: "Key Management System",
    logoAlt: "Key Management System",
    logoLightUrl: "",
    logoDarkUrl: "",
    loginTitle: "",
    backgroundImageUrl: "",
};

export function smokeRender(element: React.ReactElement, options: SmokeRenderOptions = {}): RenderResult {
    const route = options.route ?? "/";

    const routedElement = options.withRoutes ? (
        <Routes>
            <Route path={options.path ?? "/"} element={element}>
                <Route index element={options.outlet ?? <div data-testid="outlet" />} />
            </Route>
        </Routes>
    ) : (
        element
    );

    const inner = (
        <MemoryRouter initialEntries={[route]}>
            <BrandingProvider branding={mockBranding}>{routedElement}</BrandingProvider>
        </MemoryRouter>
    );

    if (options.initialUserId !== undefined) {
        // Provide a pre-populated AuthContext so components that read `userId` from
        // `useAuth()` see a real value (e.g. for CO candidate visibility tests).
        const ctxValue = {
            serverUrl: "http://localhost:9998",
            setServerUrl: () => {},
            userId: options.initialUserId,
            setUserId: () => {},
            login: async () => {},
            logout: () => {},
        };
        return render(<AuthContext.Provider value={ctxValue}>{inner}</AuthContext.Provider>);
    }

    return render(<AuthProvider>{inner}</AuthProvider>);
}
