import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, test } from "vitest";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const uiRoot = path.resolve(__dirname, "../..");

function assertFileExists(relPathFromUi: string) {
    const absPath = path.resolve(uiRoot, relPathFromUi);
    expect(fs.existsSync(absPath)).toBe(true);
    const stat = fs.statSync(absPath);
    expect(stat.isFile()).toBe(true);
    expect(stat.size).toBeGreaterThan(0);
}

describe("WASM artifacts", () => {
    test("built wasm files are present (run .github/scripts/build_ui.sh if missing)", () => {
        // These are produced by `wasm-pack build` in `crate/wasm` and copied into `ui/src/wasm/pkg`.
        assertFileExists("src/wasm/pkg/cosmian_kms_client_wasm_bg.wasm");
    });
});
