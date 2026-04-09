# React App for Cosmian KMS UI

This is a React-based frontend for the **Cosmian KMS**. It is designed to be
built as a static web application and served by the KMS server.

---

## Architecture

The `src` directory is organized like follows:

- **`assets/`**: Static files like images and SVGs.
- **`components/`**: Reusable UI elements, subdivided into `common/` (generic elements) and `layout/` (structural elements like headers and sidebars).
- **`contexts/`**: React Context providers for global state management (e.g., Auth, Branding).
- **`pages/`**: Top-level standalone page components (e.g., Login, Not Found).
- **`utils/`**: Shared helper functions and API utilities.
- **`actions/`**: Feature-specific UI modules, grouped by cryptographic domain (e.g., `Access/`, `Certificates/`, `RSA/`, `Symmetric/`, etc.).
- **`wasm/`**: WebAssembly binding logic.

---

## Prerequisites

| Component | Required Version |
| --------- | ---------------- |
| Node.js   | 22.x             |
| pnpm      | 9.x              |

> These versions are pinned by the Nix derivation (`nodejs_22` + `pnpm_9`).

Install pnpm via corepack (bundled with Node.js):

```bash
corepack enable
corepack prepare pnpm@latest --activate
```

---

## WASM Integration

This application uses WebAssembly (WASM) to handle secure request generation and
parsing.

### Install wasm-pack

Install the `0.13.1` version of `wasm-pack` to ensure compatibility with the
WASM crate:

```bash
cargo install --version 0.13.1 wasm-pack --force
```

### Build the WASM Package manually

The WASM package is built automatically as part of `pnpm run build` (see below).
To build it manually:

```bash
cd crate/clients/wasm
wasm-pack build --target web --release --features non-fips
```

`ui/scripts/sync-wasm.mjs` then copies the generated `pkg` into
`ui/src/wasm/pkg` automatically.

---

## Running the UI Locally

Install dependencies:

```bash
cd ui
pnpm install
```

Start the development server (building wasm only once is usually enough):

```bash
# pnpm run build:wasm
pnpm run dev
```

`dev` runs Vite in development mode with `VITE_DEV_MODE=true`, which skips the authentication gate so the full UI is accessible regardless of the KMS server's auth configuration. WASM must be built first — run `pnpm run build:wasm` once before starting the dev server if `ui/src/wasm/pkg/` does not exist yet.

---

## Build the Production App

```bash
cd ui
pnpm run build
```

The output is placed in `ui/dist/`. Copy its contents to the KMS server's static
resources directory to serve the UI.

If WASM is already built (e.g. by a CI step that handles WASM separately), you can
skip the WASM step:

```bash
pnpm run build:vite
```

---

## Running Tests

### Unit, integration and E2E tests:

```bash
cd ui
pnpm run test
```

Runs unit tests, integration tests, and E2E tests in sequence.

To run a layer add the adequate subprocess suffix (`test:unit`, `test:integration`, `test:e2e`).

The E2E suite exercises real browser flows against a locally running KMS server with no authentification configured (port 9998) and a Vite preview server (port 5173) **running in unrestricted DEV mode**. E2E tests can take a lot of time, only run when needed.

### WASM binding tests

WASM tests are particular and use Nix for a fully reproducible environment:

```bash
# From the repo root:
bash .github/scripts/nix.sh --variant non-fips test wasm
```

### E2E tests (Playwright)


#### Recommended — reproducible Nix environment

```bash
# From the repo root:
bash .github/scripts/nix.sh --variant non-fips test ui
```

#### Manual setup

1. Build the WASM package and the UI:

    ```bash
    cd ui
    VITE_KMS_URL=http://127.0.0.1:9998 VITE_DEV_MODE=true pnpm run build
    ```

    This runs `build:wasm` (wasm-pack) and `build:vite` (tsc + Vite) in one step.

2. Start the KMS server (separate terminal):

    ```bash
    cargo run --features non-fips --bin cosmian_kms -- \
        --database-type sqlite --sqlite-path /tmp/kms-e2e
    ```

3. Start the Vite preview server (separate terminal):

    ```bash
    cd ui
    node_modules/.bin/vite preview --port 5173 --host 127.0.0.1
    ```

4. Run Playwright:

    ```bash
    cd ui
    pnpm run test:e2e
    ```

Playwright captures screenshots and traces on failure inside `ui/test-results/`.

---

## Linting and Checks

Run all checks (type-check, lint with auto-fix, format with auto-fix, dead-code detection):

```bash
cd ui
pnpm run check
```

Or run individual checks:

```bash
pnpm run check:lint    # ESLint with --fix
pnpm run check:format  # Prettier with --write
pnpm run check:dedup   # Knip dead-code/unused exports
```
