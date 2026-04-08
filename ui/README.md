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

Start the development server (builds WASM first):

```bash
pnpm run dev
```

---

## Build the Production App

```bash
cd ui
pnpm run build
```

This command automatically:

1. Builds the WASM package from `crate/clients/wasm` via `wasm-pack`
2. Copies the generated `pkg` into `ui/src/wasm/pkg`
3. Runs the Vite production build

The output is placed in `ui/dist/`. Copy its contents to the KMS server's static
resources directory to serve the UI.

---

## Running Tests

### Unit and integration tests (Vitest)

```bash
cd ui
pnpm run test:unit
```

### WASM binding tests

The recommended way uses Nix for a fully reproducible environment:

```bash
# From the repo root:
bash .github/scripts/nix.sh --variant non-fips test wasm
```

### E2E tests (Playwright)

The E2E suite exercises real browser flows against a locally running KMS server
(port 9998) and a Vite preview server (port 5173).

#### Recommended — reproducible Nix environment

```bash
# From the repo root:
bash .github/scripts/nix.sh --variant non-fips test ui
```

#### Manual setup

1. Build the WASM package and the UI:

    ```bash
    cd crate/clients/wasm
    wasm-pack build --target web --release --features non-fips
    cd ../../ui
    VITE_KMS_URL=http://127.0.0.1:9998 pnpm run build
    ```

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

## Linting

```bash
cd ui
pnpm run lint
```
