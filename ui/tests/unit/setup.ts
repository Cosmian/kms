import "@testing-library/jest-dom/vitest";
import { cleanup } from "@testing-library/react";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { afterEach, beforeAll, vi } from "vitest";
import initWasm from "../../src/wasm/pkg";

afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
});

// Minimal browser polyfills commonly needed by Ant Design / UI code.
if (typeof window.matchMedia !== "function") {
    Object.defineProperty(window, "matchMedia", {
        writable: true,
        configurable: true,
        value: (query: string) => ({
            matches: false,
            media: query,
            onchange: null,
            addListener: () => {},
            removeListener: () => {},
            addEventListener: () => {},
            removeEventListener: () => {},
            dispatchEvent: () => false,
        }),
    });
}

// jsdom doesn't implement getComputedStyle(element, pseudoElt); rc-util calls it with pseudo elements.
// Ignore the pseudo element and fall back to the regular getComputedStyle(element).
{
    const originalGetComputedStyle = window.getComputedStyle.bind(window);
    window.getComputedStyle = ((elt: Element, _pseudoElt?: string | null) => {
        // Ignore pseudoElt to avoid jsdom's "Not implemented" exception.
        void _pseudoElt;
        return originalGetComputedStyle(elt);
    }) as typeof window.getComputedStyle;
}

if (!("ResizeObserver" in globalThis)) {
    class ResizeObserver {
        observe() {}
        unobserve() {}
        disconnect() {}
    }
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (globalThis as any).ResizeObserver = ResizeObserver;
}

if (!("clipboard" in navigator)) {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (navigator as any).clipboard = { writeText: async () => {} };
}

if (!("scrollIntoView" in HTMLElement.prototype)) {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (HTMLElement.prototype as any).scrollIntoView = () => {};
}

beforeAll(async () => {
    // Ensure the real WASM module is initialized for any component
    // that calls wasm exports on mount (no mocks).
    await initWasm();
});

// Default fetch stub for unit tests (prevents accidental network calls).
// Individual tests can override with vi.stubGlobal('fetch', ...)
if (!globalThis.fetch) {
    // Node 23 has fetch, but keep a fallback for safety.
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    globalThis.fetch = (async () => ({ ok: true, json: async () => ({}) })) as any;
}

vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL) => {
        const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;

        // Serve real wasm bytes for unit tests (no WASM mocks).
        if (url.includes("cosmian_kms_client_wasm_bg.wasm")) {
            const wasmPath = resolve(process.cwd(), "src/wasm/pkg/cosmian_kms_client_wasm_bg.wasm");
            const wasmBytes = readFileSync(wasmPath);
            return new Response(wasmBytes, {
                status: 200,
                headers: { "Content-Type": "application/wasm" },
            });
        }

        if (url.endsWith("/ui/auth_method")) {
            return new Response(JSON.stringify({ auth_method: "None" }), {
                status: 200,
                headers: { "Content-Type": "application/json" },
            });
        }

        if (url.endsWith("/ui/token")) {
            return new Response(JSON.stringify({ id_token: "dummy", user_id: "dummy" }), {
                status: 200,
                headers: { "Content-Type": "application/json" },
            });
        }

        return new Response(JSON.stringify({}), {
            status: 200,
            headers: { "Content-Type": "application/json" },
        });
    })
);
