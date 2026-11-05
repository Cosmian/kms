# Supply-chain hardening (Web UI / npm)

## Security

### UI

- Block npm install scripts: `pnpm.onlyBuiltDependencies` is now empty (5 of its 9 entries were not even installed),
  `esbuild` and `@swc/core` are listed in `ignoredBuiltDependencies`, and `strict-dep-builds` fails the install on any
  new, unreviewed script ([#1265](https://github.com/Cosmian/kms/issues/1265))
- Refuse npm versions published less than 7 days ago (`minimum-release-age` in `ui/.npmrc`). An urgent fix for an
  advisory already on develop can skip it through exact-version `minimum-release-age-exclude[]` entries that cite the
  advisory (`npm-policy` hook); package names and patterns are rejected
- Bound the CVE `pnpm.overrides` with `^` instead of `>=`, so a lockfile refresh can no longer jump to a brand-new
  or next-major version
- Pin pnpm 10.34.9 by hash (`packageManager: pnpm@10.34.9+sha512.…`; exact-version cooldown exclusions need pnpm
  10.19+) and run it through Corepack everywhere (MISE tasks, test scripts, Windows CI) instead of an unverified
  `npm install -g pnpm`; every install uses `--frozen-lockfile`
- Drop the `moment` dependency in favour of `dayjs`, already used by Ant Design
- Bump the dev dependencies `vitest` to 5.0.5 (`@vitest/mocker`: GHSA-qxg6-89mg-rqv8, GHSA-xp26-3454-mjgp) and `knip`
  to 6.43.0 (`zod`: GHSA-mrhx-c7xc-m3w5), found by the new OSV-Scanner gate

### CI

- Run the `ui`, `wasm` and `spire` test types in a new `test-nix-js` job that receives no cloud or test secrets
  (read-only `GITHUB_TOKEN`, no persisted checkout credentials), since any npm dependency can read its environment
- Add the `npm-dependency-audit` job (`mise run audit:npm`): npm policy check, OSV-Scanner (SHA-256-pinned binary)
  on `ui/pnpm-lock.yaml`, and `npm audit signatures`. On a pull request OSV-Scanner fails only on advisories the base
  branch does not already have (and always on a malicious package), so an advisory already on develop no longer blocks
  unrelated PRs; the daily develop run fails on any advisory. `pnpm audit --prod` is informational
- Ignore the minimatch DoS GHSA-g3hv-75wg-m249 until 2027-01-02: it needs `optimizationLevel >= 2`, which no
  consumer sets, and its fix (minimatch 11) is not supported by eslint yet
- Add the `npm-policy` and `pnpm-frozen-lockfile` pre-commit hooks and the `npm-audit` pre-push hook

## Bug Fixes

### UI

- Set Attribute and Modify Attribute now send the selected date for `activation_date` and `deactivation_date`:
  `moment()` did not understand the Ant Design date picker value and sent the current day at midnight instead

## Documentation

- Document the npm dependency policy in `CONTRIBUTING.md`
