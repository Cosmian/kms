import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react-swc";
import { defineConfig } from "vitest/config";

export default defineConfig({
    plugins: [react(), tailwindcss()],
    test: {
        environment: "jsdom",
        testTimeout: 15_000,
        hookTimeout: 60_000,
        setupFiles: ["./tests/unit/setup.ts"],
        include: ["./tests/unit/**/*.test.{ts,tsx}"],
    },
});
