## Features

### Locate — new columns and sorting (`ui/src/components/common/Locate.tsx`)

- **Crypto Algorithm column** — displays the algorithm (AES, RSA, ECDH, …) for each located object; sortable.
- **Crypto Length column** — displays the key size formatted as `N bits`; numerically sortable.
- **Sort controls on all columns** — Object UID, Type, Key Format Type, State, and Date columns now have sorters. Date column defaults to descending (most recent first).
- **Horizontal scroll** — table no longer clips on narrow viewports (`scroll={{ x: "max-content" }}`).
- **Pagination** — default page size raised from 10 to 50; options are now [50, 100, 500, 1000].

### HashMapDisplay — omit empty fields (`ui/src/components/common/HashMapDisplay.tsx`)

Empty-string, null, and undefined entries are filtered out before rendering. Certificate attribute maps (which contain many blank issuer/subject fields) now show only the populated values.

## Bug Fixes

### Date column was always blank

Two independent bugs:

1. `activation_date`, `rotate_date`, `initial_date`, and `original_creation_date` were not included in the WASM `GetAttributes` request — the server never returned them, so every date field was `undefined`.
2. KMIP returns `activation_date` in seconds (i64); the renderer needs milliseconds. Without the `* 1000` conversion every date rendered as 1 Jan 1970.

Fixed by adding all four date fields to all four `parse_get_attributes_ttlv_response` call sites, and multiplying `activation_date` by 1000 before constructing the `Date` object.

### Date column sort order was incorrect

The sorter compared `activation_date` (seconds) directly against `rotate_date` / `initial_date` / `original_creation_date` (milliseconds). The sorter now applies the same `* 1000` conversion as the renderer, so all values are in the same unit before subtraction.

### Epoch-0 treated as missing date

`activationDate ? activationDate * 1000 : undefined` treated timestamp 0 as absent. Changed to `activationDate != null ? activationDate * 1000 : undefined`, consistent with the `??` guards used elsewhere.
