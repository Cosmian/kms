import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react-swc";
import { defineConfig } from "vite";

// Default KMS backend used by the dev / preview proxy when VITE_KMS_URL is not
// baked into the production build.  Matches the fallback in App.tsx.
const kmsTarget = process.env.VITE_KMS_URL ?? "http://localhost:9998";

// Proxy rules forwarding KMS API paths to the backend so that the Vite dev and
// preview servers can reach the KMS without CORS issues or base-path 404s.
// `secure: false` allows self-signed TLS certificates on the backend.
const proxyOpts = { target: kmsTarget, secure: false };
const apiProxy: Record<string, { target: string; secure: boolean }> = {
    "/kmip": proxyOpts,
    "/access": proxyOpts,
    "/google_cse": proxyOpts,
    "/ms_dke": proxyOpts,
    "/aws": proxyOpts,
    "/azureekm": proxyOpts,
    "/download-cli": proxyOpts,
};

// https://vite.dev/config/
export default defineConfig({
    base: "/ui",
    plugins: [react(), tailwindcss()],
    build: {
        // The UI bundles include Ant Design; keep chunking but avoid noisy warnings when
        // a single library chunk is marginally above 500kB.
        chunkSizeWarningLimit: 1600,
    },
    server: {
        proxy: apiProxy,
    },
    preview: {
        proxy: apiProxy,
    },
});
