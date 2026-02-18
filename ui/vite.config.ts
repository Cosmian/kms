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
        chunkSizeWarningLimit: 550,
        rollupOptions: {
            output: {
                manualChunks(id) {
                    // Split the local WASM client glue code into its own chunk.
                    // (The .wasm binary itself is emitted as a separate asset.)
                    if (id.includes("/src/wasm/pkg/") || id.includes("\\src\\wasm\\pkg\\")) {
                        return "wasm-client";
                    }

                    if (id.includes("node_modules")) {
                        // Split Ant Design into multiple chunks to keep each output below the warning threshold.
                        if (id.includes("antd/es/table") || id.includes("antd/lib/table")) return "antd-table";
                        if (id.includes("antd/es/modal") || id.includes("antd/lib/modal")) return "antd-modal";
                        if (id.includes("antd")) return "antd";
                        if (id.includes("@ant-design")) return "ant-icons";
                        if (id.includes("react-router")) return "react-router";
                        if (id.includes("react-dom") || id.includes("react/")) return "react";
                        return "vendor";
                    }

                    return undefined;
                },
            },
        },
    },
});
