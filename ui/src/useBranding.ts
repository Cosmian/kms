import { useContext } from "react";
import type { Branding } from "./branding";
import { BrandingContext } from "./brandingContext";

export function useBranding(): Branding {
    const ctx = useContext(BrandingContext);
    if (!ctx) {
        throw new Error("useBranding must be used within BrandingProvider");
    }
    return ctx.branding;
}
