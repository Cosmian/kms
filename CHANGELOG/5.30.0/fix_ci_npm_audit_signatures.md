## CI

### Bug Fixes
- The `Supply chain — npm audit` job installs `npm@11.11.0` before `mise run audit:npm`: the npm 10.9.9 bundled with Node 22 intermittently failed `npm audit signatures` with `EMISSINGSIGNATUREKEY` on `magic-string@1.4.5` (no `attestationKeyIds.length > 0` guard before the registry-key check)
