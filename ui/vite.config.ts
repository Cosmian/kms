import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react-swc";
import { defineConfig } from "vite";

// https://vite.dev/config/
export default defineConfig({
    base: "/ui",
    plugins: [react(), tailwindcss()],
    build: {
        // The UI bundles include Ant Design; keep chunking but avoid noisy warnings when
        // a single library chunk is marginally above 500kB.
        chunkSizeWarningLimit: 1600,
    },
});
