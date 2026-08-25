---
name: 'UI Routes & Navigation'
description: 'Keep server SPA routes, React Router, and the UI menu in sync when adding a new UI page'
applyTo: 'ui/src/App.tsx, ui/src/menuItems.tsx, ui/src/actions/**/*.tsx, ui/src/pages/**/*.tsx'
---

# UI route & navigation sync

Every new top-level UI page must be registered in three places, and the route key must be
consistent across all of them.

## Checklist

- [ ] `ui/src/App.tsx` — add `<Route path="..." element={<Component />} />`
- [ ] `ui/src/menuItems.tsx` — add a `baseMenu` entry; its `key` must match the route path prefix
- [ ] `crate/server/src/start_kms_server.rs` — add the top-level path to the `spa_routes` array (e.g. `"/newfeature{_:.*}"`)

> Rule 4.1 of `/kms-sync-rules`. New UI features also require CLI ⇔ Web UI parity — see
> `cli-ui-sync.instructions.md`.
