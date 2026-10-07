---
name: react-ant-patterns
description: 'React 19 + Ant Design 5 + Tailwind 4 + Vite 7 patterns for the KMS Web UI: WASM integration, FIPS guards, data-testid placement, Playwright companion. Use as a reference for UI development patterns.'
---

# React + Ant Design Patterns for the KMS UI

> **For authoritative UI coding conventions, see [`.github/instructions/typescript-ui.instructions.md`](../../instructions/typescript-ui.instructions.md)** — stack, FIPS guards, TypeScript strictness, WASM integration, testing attributes, and actions structure.

This page documents KMS-specific UI patterns not covered in the instruction file.

## Ant Design Select Portal Rendering (Playwright Note)

Ant Design `<Select>` renders its dropdown in a **portal attached to `document.body`**, not as a child of the `<Select>` element. When writing Playwright E2E tests, do not try to select options directly on the `<Select>` element:

```tsx
<Form.Item name="algorithm" label="Algorithm">
  <div data-testid="algorithm-select-wrapper">
    <Select data-testid="algorithm-select" placeholder="Select algorithm">
      <Select.Option value="AES">AES</Select.Option>
      <Select.Option value="ChaCha20" disabled={fipsMode}>
        ChaCha20 (non-FIPS)
      </Select.Option>
    </Select>
  </div>
</Form.Item>
```

Use the helpers in `ui/tests/e2e/helpers.ts` to interact with portal-rendered dropdowns from Playwright tests.

## Error Handling and User Feedback

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

## AI-Assisted Development Resources

- **Ant Design LLM context**: Fetch `https://ant.design/llms.txt` for up-to-date component API reference when coding AntD components.
- **Ant Design MCP server**: <https://ant-design.antgroup.com/docs/react/mcp> — provides structured component documentation to AI agents.
- **Context7 MCP** (`io.github.upstash/context7`): Generic library documentation fetcher — use when AntD or other JS library APIs seem outdated in the agent's training data. See <https://context7.com/>.
