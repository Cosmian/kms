## Features

### UI

- **Locate page: sortable KMIP attribute columns** — The Locate results table now has
  sort controls on all columns. Two new columns are displayed: **Crypto Algorithm** and
  **Crypto Length**, populated via KMIP `GetAttributes`. All existing columns (Object UID,
  Type, Key Format Type, State, Date) are also sortable.

## Bug Fixes

### UI

- **Locate page: Date column now populates** — The Date column previously showed `—` for
  every key because `activation_date` was never requested from the server. It is now
  fetched and displayed correctly (seconds-to-milliseconds conversion also fixed).

### WASM / Client utils

- **`parse_selected_attributes_flatten`: tags were silently dropped** — The function had
  no match arm for `"tags"` / `"user_tags"`, so tag lookups always returned nothing.
  Added the missing arm using `VENDOR_ID_COSMIAN` to retrieve vendor-scoped tags.
