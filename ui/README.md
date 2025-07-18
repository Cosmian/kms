# React App for Cosmian KMS UI

This is a React-based frontend for the **Cosmian KMS**. It is designed to be built as a static web application and served by the KMS server.

---

## WASM Integration

This application uses WebAssembly (WASM) to handle secure request generation and parsing.

#### Install wasm-pack

Install the 0.13.1 version of `wasm-pack` globally to ensure compatibility with the WASM crate:

```bash
```sh
cargo install --version 0.13.1 wasm-pack --force
```

#### Build the WASM Package

To build the WASM package from the corresponding Rust crate:

```bash
cd crate/wasm
RUSTUP_TOOLCHAIN="nightly-2025-01-01" wasm-pack build --target web --release --features non-fips
```

#### Copy the WASM Package

Then copy the generated `pkg` directory into the React app's source tree:

```bash
cp -R pkg ../../ui/src/wasm/
```

## Running the UI Locally

To run the UI in development mode:

### NPM version

| Component | Required Version |
|-----------|------------------|
| Node.js   | v23.6.0          |
| npm       | v11.2.0          |

Make sure pnpm is installed. If not, install it:

```bash
cd ui
npm install -g pnpm
```

Install dependencies:

```bash
cd ui
pnpm install
```

Start the development server:

```bash
pnpm run dev
```

## Build the Production App

To build the production-ready UI:

```bash
pnpm run build
```

This will generate a `dist` directory containing all static assets.

You can then copy the contents of the dist folder to the static resources directory of the Cosmian KMS server so it can serve the UI.
