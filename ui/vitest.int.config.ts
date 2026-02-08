import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react-swc";
import { defineConfig } from "vitest/config";

export default defineConfig({
    plugins: [react(), tailwindcss()],
    test: {
        environment: "node",
        include: ["./tests/integration/**/*.test.ts"],
        testTimeout: 120_000,
        hookTimeout: 120_000,
    },
});
