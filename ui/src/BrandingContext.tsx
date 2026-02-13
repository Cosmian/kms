import React, { createContext, useContext } from "react";
import type { Branding } from "./branding";

type BrandingContextValue = {
    branding: Branding;
};

const BrandingContext = createContext<BrandingContextValue | undefined>(undefined);

export function BrandingProvider(props: { branding: Branding; children: React.ReactNode }) {
    return <BrandingContext.Provider value={{ branding: props.branding }}>{props.children}</BrandingContext.Provider>;
}

export function useBranding(): Branding {
    const ctx = useContext(BrandingContext);
    if (!ctx) {
        throw new Error("useBranding must be used within BrandingProvider");
    }
    return ctx.branding;
}
