---
mode: 'agent'
description: 'React 19 + Ant Design 5 + Tailwind 4 + Vite 7 patterns for the KMS Web UI: WASM integration, FIPS guards, data-testid placement, Playwright companion. Use: /react-ant-patterns'
---

# React + Ant Design Patterns for the KMS UI

Reference for KMS UI-specific patterns. Stack: **React 19 + Vite 7 + Ant Design 5 + Tailwind CSS 4 + pnpm**.

## Project Structure

```text
ui/src/
  actions/          ← 14 feature modules (one per KMIP operation group)
    Access/         ← Grant, List, Obtained, Revoke
    Attributes/     ← Delete, Get, Modify, Set
    Certificates/   ← Certify, Decrypt, Encrypt, Export, Import, Validate
    CloudProviders/ ← AWS/Azure key export/import
    Covercrypt/     ← Non-FIPS only
    EC/             ← Elliptic Curve
    Keys/           ← Derive, Export, Import, Symmetric
    MAC/            ← Compute, Verify
    Objects/        ← Destroy, List, Revoke, Opaque, SecretData
    PQC/            ← Non-FIPS only
    RSA/            ← RSA key/enc/sign
    Symmetric/      ← Encrypt, Decrypt, Hash
  App.tsx           ← React Router routes
  menuItems.tsx     ← Sidebar menu
  wasm/pkg/         ← Generated WASM bindings (do not edit manually)
```

## Pattern 1 — FIPS Mode Feature Guard

Hide non-FIPS features in the menu and routing when FIPS mode is active.

```tsx
// Read the branding/FIPS flag from the server info endpoint
import { useServerInfo } from '../hooks/useServerInfo'

export function menuItems() {
  const { fipsMode } = useServerInfo()

  return [
    { key: 'symmetric', label: 'Symmetric', icon: <KeyOutlined /> },
    { key: 'ec', label: 'Elliptic Curve', icon: <KeyOutlined /> },
    // Hide Covercrypt in FIPS mode
    ...(!fipsMode ? [{ key: 'covercrypt', label: 'Covercrypt', icon: <LockOutlined /> }] : []),
    // Hide PQC in FIPS mode (non-standardized variants)
    ...(!fipsMode ? [{ key: 'pqc', label: 'Post-Quantum', icon: <SafetyOutlined /> }] : []),
  ]
}
```

For routing in `App.tsx`:

```tsx
{!fipsMode && <Route path="/covercrypt/*" element={<Covercrypt />} />}
```

## Pattern 2 — WASM Integration

The KMS UI uses WASM for building KMIP request objects (TTLV encoding). Always handle async WASM initialization.

```tsx
import { useState, useEffect } from 'react'
// Import from the generated pkg (do not import from wasm.rs directly)
import initWasm, { create_symmetric_key_ttlv_request } from '../wasm/pkg/cosmian_kms_client_wasm'

export function CreateSymmetricKey() {
  const [wasmReady, setWasmReady] = useState(false)

  useEffect(() => {
    initWasm().then(() => setWasmReady(true))
  }, [])

  const handleCreate = async () => {
    if (!wasmReady) return

    // Build the TTLV request via WASM
    const ttlvRequest = create_symmetric_key_ttlv_request({
      keyId: formValues.keyId,
      algorithm: formValues.algorithm,
      keyLength: Number(formValues.keyLength),
    })

    // Send to the KMS server
    const response = await fetch('/kmip/2_1', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: ttlvRequest,
    })
  }

  return (
    <Button
      data-testid="create-key-button"
      disabled={!wasmReady}
      onClick={handleCreate}
    >
      Create Key
    </Button>
  )
}
```

**Never hand-craft TTLV JSON in TypeScript** — always use the WASM bindings. If a WASM function for your operation doesn't exist, add it to `crate/clients/wasm/src/wasm.rs` and rebuild with `wasm-pack build --target web`.

## Pattern 3 — Ant Design Form with `data-testid`

All interactive elements must have `data-testid` attributes for Playwright E2E tests.

```tsx
import { Form, Input, Select, Button } from 'antd'

export function KeyCreationForm() {
  const [form] = Form.useForm()

  return (
    <Form form={form} layout="vertical" data-testid="key-creation-form">
      <Form.Item name="keyId" label="Key ID" rules={[{ required: true }]}>
        <Input
          data-testid="key-id-input"
          placeholder="e.g. my-encryption-key"
        />
      </Form.Item>

      <Form.Item name="algorithm" label="Algorithm">
        {/* Wrap Select in a div with data-testid for Playwright */}
        <div data-testid="algorithm-select-wrapper">
          <Select data-testid="algorithm-select" placeholder="Select algorithm">
            <Select.Option value="AES">AES</Select.Option>
            <Select.Option value="ChaCha20" disabled={fipsMode}>
              ChaCha20 (non-FIPS)
            </Select.Option>
          </Select>
        </div>
      </Form.Item>

      <Button
        type="primary"
        htmlType="submit"
        data-testid="create-key-submit-button"
      >
        Create Key
      </Button>
    </Form>
  )
}
```

**Note**: Ant Design `<Select>` renders its dropdown in a portal attached to `document.body`. Playwright tests must use the helpers in `ui/tests/e2e/helpers.ts` to interact with it — do not try to select options directly on the `<Select>` element.

## Pattern 4 — Error Handling and User Feedback

```tsx
import { message, Alert } from 'antd'

// For transient feedback (toast)
const [messageApi, contextHolder] = message.useMessage()

const handleSubmit = async () => {
  try {
    const result = await callKmsOperation(/* ... */)
    messageApi.success('Key created successfully')
    // Store the UID for display
    setCreatedKeyUid(result.uniqueIdentifier)
  } catch (error) {
    // Show user-friendly error — never expose internal server details
    const userMessage = parseKmsError(error) ?? 'Operation failed. Check server logs.'
    messageApi.error(userMessage)
  }
}

// For persistent error display
{error && (
  <Alert
    data-testid="operation-error-alert"
    type="error"
    message={error}
    showIcon
  />
)}

// For success result display
{createdKeyUid && (
  <Alert
    data-testid="created-key-uid"
    type="success"
    message={`Key created: ${createdKeyUid}`}
    showIcon
  />
)}
```

## Pattern 5 — New Feature Module Structure

When adding a new feature module under `ui/src/actions/<Module>/`:

```text
ui/src/actions/MyFeature/
  index.tsx          ← Main component (default export)
  MyOperation1.tsx   ← Sub-operation component
  MyOperation2.tsx   ← Sub-operation component
  types.ts           ← TypeScript interfaces for this feature
```

In `App.tsx`:

```tsx
import MyFeature from './actions/MyFeature'

// Inside <Routes>:
<Route path="/myfeature/*" element={<MyFeature />} />
```

In `menuItems.tsx`:

```tsx
{
  key: 'myfeature',  // must match the route path prefix
  label: 'My Feature',
  icon: <MyIcon />,
  // Conditionally hide if non-FIPS:
  // hidden: fipsMode,
}
```

In `start_kms_server.rs` (if new top-level path — **required for browser refresh to work**):

```rust
spa_routes.push("/myfeature{_:.*}");
```

## Pattern 6 — TypeScript Strictness

`tsconfig.app.json` enforces `strict: true`, `noUnusedLocals: true`, `noUnusedParameters: true`.

```tsx
// ❌ Will fail: unused parameter
const MyComponent = ({ unusedProp }: { unusedProp: string }) => <div />

// ✅ Prefix unused params with _
const MyComponent = ({ _unusedProp }: { _unusedProp: string }) => <div />

// ❌ Will fail: implicit any
const handleData = (data) => data.value

// ✅ Explicit type
const handleData = (data: KmsResponse) => data.value
```

## Pattern 7 — Tailwind 4 with Ant Design

Use Tailwind utility classes for layout and spacing. Do not override Ant Design component styles with Tailwind unless necessary.

```tsx
// ✅ Tailwind for layout, Ant Design for components
<div className="flex flex-col gap-4 p-6">
  <Card title="Create Key" className="max-w-2xl">
    <Form layout="vertical">
      {/* Ant Design form components */}
    </Form>
  </Card>
</div>

// ❌ Avoid fighting Ant Design's styling
<Button className="!bg-red-500 !text-white">  {/* fragile */}
```

## Quick Rules

- **Every interactive element** gets a `data-testid`
- **Ant Design Select** dropdowns need helpers in Playwright (portal-rendered)
- **WASM must initialize** before calling any WASM function — check `wasmReady` state
- **FIPS mode guard** every non-FIPS feature in menu items AND routes
- **TypeScript strict mode** — no `any`, no unused locals/parameters
- **Mirror the CLI** — every `ckms` subcommand must have a corresponding UI action
