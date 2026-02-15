import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import App from "./App.tsx";
import { BrandingProvider } from "./BrandingContext";
import { applyBrandingToDocument, loadBranding } from "./branding";
import "./styles.css";

async function bootstrap() {
    const branding = await loadBranding();
    applyBrandingToDocument(branding);

    createRoot(document.getElementById("root")!).render(
        <StrictMode>
            <BrandingProvider branding={branding}>
                <App />
            </BrandingProvider>
        </StrictMode>
    );
}

bootstrap();
