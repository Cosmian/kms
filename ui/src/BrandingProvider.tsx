import React from "react";
import type { Branding } from "./branding";
import { BrandingContext } from "./brandingContext";

export function BrandingProvider(props: { branding: Branding; children: React.ReactNode }) {
    return <BrandingContext.Provider value={{ branding: props.branding }}>{props.children}</BrandingContext.Provider>;
}
