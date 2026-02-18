import { render, waitFor } from "@testing-library/react";
import React from "react";
import { expect, test } from "vitest";

import App from "../../../src/App";
import { BrandingProvider } from "../../../src/BrandingContext";

const mockBranding = {
    title: "Test KMS",
    logoAlt: "logo-alt",
    logoLightUrl: "logo-light",
    logoDarkUrl: "logo-dark",
    loginTitle: "title",
    backgroundImageUrl: "bg-image",
};

test("renders App (and initializes WASM)", async () => {
    // App uses a BrowserRouter basename="/ui"; ensure the URL matches.
    window.history.pushState({}, "", "/ui/");
    const { container } = render(
        React.createElement(
            BrandingProvider,
            { branding: mockBranding },
            React.createElement(App)
        )
    );

    await waitFor(() => {
        expect(container).toHaveTextContent(/Cosmian KMS user interface|ACCESS KMS|Key Management System|LOGIN|Login|Objects|Keys/i);
    });
});
