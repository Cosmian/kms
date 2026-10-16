# Supply-chain hardening (Web UI / npm)

## Security

### UI

- Block npm install scripts: `pnpm.onlyBuiltDependencies` is now empty (5 of its 9 entries were not even installed),
  `esbuild` and `@swc/core` are listed in `ignoredBuiltDependencies`, and `strict-dep-builds` fails the install on any
  new, unreviewed script ([#1265](https://github.com/Cosmian/kms/issues/1265))
- Refuse npm versions published less than 7 days ago (`minimum-release-age` in `ui/.npmrc`)
- Bound the CVE `pnpm.overrides` with `^` instead of `>=`, so a lockfile refresh can no longer jump to a brand-new
  or next-major version
- Pin pnpm by hash (`packageManager: pnpm@10.17.1+sha512.…`) and run it through Corepack everywhere (MISE tasks, test
  scripts, Windows CI) instead of an unverified `npm install -g pnpm`; every install uses `--frozen-lockfile`
- Drop the `moment` dependency in favour of `dayjs`, already used by Ant Design

### CI

- Run the `ui`, `wasm` and `spire` test types in a new `test-nix-js` job that receives no cloud or test secrets
  (read-only `GITHUB_TOKEN`, no persisted checkout credentials), since any npm dependency can read its environment
- Add the `npm-dependency-audit` job (`mise run audit:npm`): `pnpm audit --prod`, OSV-Scanner (SHA-256-pinned binary)
  on `ui/pnpm-lock.yaml`, and `npm audit signatures`
- Add the `npm` ecosystem to Dependabot for `/ui`, with a 7-day cooldown
- Add the `npm-policy` and `pnpm-frozen-lockfile` pre-commit hooks and the `npm-audit` pre-push hook
- Pin `azure/setup-helm` and `medyagh/setup-minikube` in `test_all.yml` to commit SHAs (required by the
  `github-actions-sha-pin` hook)

## Bug Fixes

### UI

- Set Attribute and Modify Attribute now send the selected date for `activation_date` and `deactivation_date`:
  `moment()` did not understand the Ant Design date picker value and sent the current day at midnight instead

## Documentation

- Document the npm dependency policy in `CONTRIBUTING.md`
