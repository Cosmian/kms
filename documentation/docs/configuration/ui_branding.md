# UI Branding (post-install, no rebuild)

The KMS UI can be white‑labeled at runtime by editing the installed UI static files (no UI rebuild required).

## What to change after install

The UI is served under `/ui`, from the UI dist directory on disk.

- Branding file: `/usr/local/cosmian/ui/dist/branding.json`
- Theme assets: `/usr/local/cosmian/ui/dist/themes/<theme>/...`

All asset URLs in `branding.json` are URLs under `/ui/...` (for example: `/ui/themes/example/example-logo-light.svg`).

## Post-install customization (deb/rpm)

When the KMS server is installed from Linux packages, branding can be customized **after install** by editing files directly in the UI dist folder (no UI rebuild required).

- Default UI dist path (Linux): `/usr/local/cosmian/ui/dist/`
- Branding file: `/usr/local/cosmian/ui/dist/branding.json`
- Theme assets: `/usr/local/cosmian/ui/dist/themes/<theme>/...`

The packaging scripts preserve these files across upgrades by backing them up and restoring them (upgrade-safe customization).

In this repo, theme assets are stored under `ui/public/themes/` and the build step publishes them into `ui/dist/themes/`.

## Switch to the example theme

Edit `/usr/local/cosmian/ui/dist/branding.json` and point the URLs to the `example` theme assets:

```json
{
  "title": "Example",
  "faviconUrl": "/ui/themes/example/favicon-32x32.png",
  "logoAlt": "Example",
  "logoLightUrl": "/ui/themes/example/example-logo-light.svg",
  "logoDarkUrl": "/ui/themes/example/example-logo-dark.svg",
  "backgroundImageUrl": "/ui/themes/example/example-login-bg.jpg"
}
```

Restart the service (or clear browser cache) to see changes.

## Start from the blank theme

The `blank` theme is a minimal starter template with placeholder assets — copy
it as your starting point for a new white-label deployment:

```bash
# Copy the blank theme to the installed UI dist directory
cp -r /usr/local/cosmian/ui/dist/themes/blank /usr/local/cosmian/ui/dist/themes/acme

# Customise the copy
nano /usr/local/cosmian/ui/dist/themes/acme/branding.json
# Replace logo-light.svg, logo-dark.svg, favicon.svg, login-bg.svg with your assets

# Activate it by pointing branding.json to the new theme
cp /usr/local/cosmian/ui/dist/themes/acme/branding.json /usr/local/cosmian/ui/dist/branding.json
```

The blank theme ships the following placeholder files:

| File            | Purpose                                      |
|-----------------|----------------------------------------------|
| `branding.json` | Full example with every supported field      |
| `logo-light.svg`| Logo for light-mode header (dark text)      |
| `logo-dark.svg` | Logo for dark-mode header (white text)      |
| `favicon.svg`   | Browser tab icon                            |
| `login-bg.svg`  | Login page background (dark blue gradient)  |

## `branding.json` schema

Example:

```json
{
  "title": "Example",
  "faviconUrl": "/ui/themes/example/favicon-32x32.png",
  "logoAlt": "Example Key Management",
  "logoLightUrl": "/ui/themes/example/example-logo-light.svg",
  "logoDarkUrl": "/ui/themes/example/example-logo-dark.svg",
  "loginTitle": "Example",
  "loginSubtitle": "Welcome",
  "backgroundImageUrl": "/ui/themes/example/example-login-bg.jpg",
  "loginCardColor": "rgba(126,34,206,0.3)",
  "menuTheme": "dark",
  "tokens": {
    "light": { "colorPrimary": "#0057ff", "colorText": "#111827" },
    "dark": { "colorPrimary": "#7c3aed", "colorText": "#e5e7eb" }
  }
}
```

### Keys

- `title`: Sets `document.title`.
- `faviconUrl`: URL for the page favicon.
- `logoAlt`: Used as the header label and `<img alt>`.
- `logoLightUrl` / `logoDarkUrl`: Header logo depending on light/dark mode.
- `loginTitle` / `loginSubtitle`: Login page texts.
- `backgroundImageUrl`: Login background image.
- `loginCardColor`: CSS background color of the card overlaid on the login background. Accepts any CSS color value (e.g. `"rgba(0,87,255,0.3)"`, `"#0057ff4d"`). Defaults to `"rgba(126,34,206,0.3)"` (semi-transparent purple).
- `menuTheme`: `"light"` or `"dark"`.
- `tokens.light` / `tokens.dark`: Ant Design theme token overrides.

## Behavior and fallbacks

- If `/ui/branding.json` is missing or invalid, the UI uses built-in defaults.
- If a key is missing, the UI falls back to the default value.

## Notes

- The UI fetches `branding.json` on startup and applies title/favicon before React renders.
- `branding.json` is fetched with cache busting by default.

## About `branding.ts`

The UI branding loader/helpers live in `ui/src/branding.ts`.
It is a plain TypeScript module (no JSX), so it uses the `.ts` extension rather than `.tsx`.

## Upgrade behavior

Linux packages are designed so you can customize UI files in place.

- On upgrade: package maintainer scripts back up UI dist content to `/var/lib/cosmian/ui/` and restore it after installing the new version.
- If you want to reset to package defaults: remove your customized `branding.json` and/or `themes/<theme>/` overrides, then reinstall or restore from a clean package.
