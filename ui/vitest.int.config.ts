import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react-swc";
import { defineConfig } from "vitest/config";

export default defineConfig({
    plugins: [react(), tailwindcss()],
    test: {
        environment: "node",
        include: ["./tests/integration/**/*.test.ts"],
        testTimeout: 120_000,
        // The beforeAll hook in each integration test waits up to 120 s for the
        // KMS server to become ready (waitForKmsServer) and then initialises the
        // WASM module.  Use a larger hookTimeout so that, on a cold CI runner
        // where `cargo run` must compile the server first, the hook does not
        // race with its own internal deadline and produce a misleading
        // "Hook timed out" failure instead of a server-not-reachable error.
        hookTimeout: 300_000,
    },
});
