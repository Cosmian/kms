# UI Routes & Action Modules Reference

## Contents

- [UI routes](#ui-routes)
- [Action modules](#action-modules)
- [Testing with Chrome DevTools MCP](#testing-with-chrome-devtools-mcp)

---

## UI routes

Read [App.tsx](../../../../ui/src/App.tsx) for registered routes and their guards. Read [menuItems.tsx](../../../../ui/src/menuItems.tsx) for menu visibility. For FIPS checks, verify both; hiding a menu item does not guard a direct URL.

---

## Action modules

Follow the route's imports into [ui/src/actions/](../../../../ui/src/actions/) for form fields, selectors, and submit behavior.

---

## Testing with Chrome DevTools MCP

Install: `npx -y chrome-devtools-mcp@latest`

Use the Chrome DevTools MCP tools exposed by the current client; tool names vary by harness.

**Interaction conventions:**

- Ant Design `<Select>` portals into `document.body` — click the trigger, then click the option in the popup.
- Wait for the response panel to update after submitting a form.
- Target elements by `data-testid` attribute.
