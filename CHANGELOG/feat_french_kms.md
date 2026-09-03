## Features

### UI

- Add French (`fr`) as a third supported UI locale alongside English and Simplified Chinese:
  - New "🇫🇷 Français" option in the header language switcher
  - Full translation of the sidebar menu, layout (header, footer, login, 404), `Locate` page, and every action form (`common`, `layout`, `locate`, `menu`, `actions` namespaces)
  - Ant Design components (date pickers, pagination, popconfirm, …) and `dayjs` now follow the French locale when selected
  - Terminology policy: cryptographic algorithms/standards (`RSA`, `AES`, `EC`, `PQC`, `Covercrypt`, `MAC`, `FPE`, `HSM`, `KEK`, `BYOK`, `ML-KEM`, `ML-DSA`, `SLH-DSA`, …) are kept untranslated; business/user-facing copy is translated. "Chiffrer/Déchiffrer" is used consistently for encrypt/decrypt (never "crypter/décrypter")
- Add missing French, English and Simplified Chinese translations for the "Download CRL" (`certificateGenerateCrl`) action, and missing French translations for the login method labels (`login.oidc`, `login.certificate`, `login.authVerifier`)

## Refactoring

### UI

- Extract a `localeRegistry.ts` module as the single source of truth for per-locale configuration (label, Ant Design locale, `dayjs` locale, browser-language matcher, translation bundle). `i18n/index.ts`, `useAppLocale.ts`, and `LanguageSwitcher.tsx` now derive from this registry instead of hardcoding each locale — adding a future locale is a single registry entry plus its JSON bundle
