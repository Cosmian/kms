import { execFile } from "node:child_process";
import { promises as fs } from "node:fs";
import path from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

const repoRoot = process.cwd();
const srcPkg = path.join(repoRoot, "crate", "wasm", "pkg");
const dstWasmDir = path.join(repoRoot, "ui", "src", "wasm");
const dstPkg = path.join(dstWasmDir, "pkg");

async function hasWasmOpt() {
    try {
        await execFileAsync("wasm-opt", ["--version"], { windowsHide: true });
        return true;
    } catch {
        return false;
    }
}

async function optimizeWasmInPlace(wasmPath) {
    const tmpPath = `${wasmPath}.opt`;
    await execFileAsync("wasm-opt", ["-Oz", wasmPath, "-o", tmpPath], { windowsHide: true });
    await fs.rename(tmpPath, wasmPath);
}

async function maybeOptimizeWasm(pkgDir) {
    const enabled = await hasWasmOpt();
    if (!enabled) {
        console.log("wasm-opt not found; skipping WASM optimization");
        return;
    }

    const entries = await fs.readdir(pkgDir, { withFileTypes: true });
    const wasmFiles = entries.filter((e) => e.isFile() && e.name.endsWith(".wasm")).map((e) => path.join(pkgDir, e.name));

    if (wasmFiles.length === 0) {
        console.log("No .wasm file found in pkg; skipping WASM optimization");
        return;
    }

    for (const wasmPath of wasmFiles) {
        console.log(`Optimizing WASM with wasm-opt -Oz: ${wasmPath}`);
        await optimizeWasmInPlace(wasmPath);
    }
}

await maybeOptimizeWasm(srcPkg);

await fs.mkdir(dstWasmDir, { recursive: true });
await fs.rm(dstPkg, { recursive: true, force: true });

// Node.js >=16 supports fs.cp; Node.js >=18 is expected on this repo's toolchain.
await fs.cp(srcPkg, dstPkg, { recursive: true });

console.log(`Synced WASM pkg: ${srcPkg} -> ${dstPkg}`);
