## Features

| Feature              | Before                         | After                                                       |
| -------------------- | ------------------------------ | ----------------------------------------------------------- |
| **Crypto Algorithm** | Not shown in results           | New column — displays algorithm (AES, RSA, ECDH…) with sort |
| **Crypto Length**    | Not shown in results           | New column — displays key size in bits with numeric sort    |
| **Column sorting**   | No sort controls on any column | All columns sortable (click header to sort)                 |
| **Table Overflow**   | Clipped on narrow viewports    | Horizontal scroll with `scroll={{ x: "max-content" }}`      |

## Bug Fixes

### Locate table clipped on narrow viewports

Table had no horizontal overflow handling; columns were cut off. Fixed with scroll={{ x: "max-content" }}.

### Date column always showed —

Two bugs combined:

1. activation_date was never in the GetAttributes request — the WASM layer never fetched it, so the value was always undefined.
2. KMIP returns the timestamp in seconds (i64); new Date() needs milliseconds. The raw value placed every date in January 1970.

Fixed by adding activation_date to all four attribute fetch calls and multiplying the result by 1000 before constructing the Date object.

## Code Quality

- Refactored repeated WASM call chains in Locate.tsx: extracted `ENRICH_ATTRS` constant and `fetchAttrs()` helper; consolidated 4 inline call sites; result: -32 lines (987→955), zero regressions.
