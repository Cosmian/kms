## Features

### UI

- Add bilingual (English / Simplified Chinese) internationalization to the KMS Web UI using `react-i18next`:
  - New language switcher in the header (`English` / `中文`) that persists the choice and drives Ant Design + `dayjs` locale
  - Full translation of the sidebar menu (all nesting levels), layout (header, footer), shared components (`Locate`, `HashMapDisplay`, `FormUpload`, `ActionResponse`), and every action form
  - Terminology policy: cryptographic algorithms and abbreviations (`RSA`, `AES`, `SHA`, `EC`, `PQC`, `Covercrypt`, `MAC`, `FPE`, `HSM`, …) are kept in English; business/user-facing copy is translated

## Bug Fixes

### UI

- Fix `zh-CN` translations silently falling back to English: the `nonExplicitSupportedLngs` option caused i18next to treat `zh-CN` as unsupported and downgrade `resolvedLanguage` to `en`
- Fix the sidebar only translating first-level menu items; submenu items (second/third level) now translate as well
- Fix FPE pages (export / import / revoke / destroy) labeling the object as "symmetric key"; the object is now reported as an FPE key, and the export page title is unified to "Export FPE Key"
