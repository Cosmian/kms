import { createContext } from "react";
import type { Branding } from "../utils/branding";

type BrandingContextValue = {
    branding: Branding;
};

export const BrandingContext = createContext<BrandingContextValue | undefined>(undefined);
