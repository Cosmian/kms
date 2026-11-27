## CI

- **Automated release workflow** (`release.yml`): new `workflow_dispatch` workflow that fully automates the release flow — creates the `release/<version>` branch from `develop`, bumps all versions via `release.sh --ci`, regenerates the CBOM (`generate_cbom.sh`), updates Nix vendor hashes on both Linux and macOS runners in parallel, triggers the packaging CI, retrieves SBOMs once packaging completes, commits everything, pushes the annotated tag, and finally performs the git-flow finalisation (merge into `main`, merge back into `develop`, delete release branch).
- **`release.sh`**: added `--ci` third argument that skips local pre-commit hooks (nix-build-all, cbom, release-docker-build-ui) while keeping all version-bump sed substitutions intact.
- **`packaging.yml`**: added `github.event_name == 'workflow_dispatch'` to the `if:` conditions of `docker`, `packages`, `publish-release`, and `publish-sbom` jobs so they execute when triggered by the release workflow dispatch.
- **`RELEASE.md`**: restructured documentation — automated flow is now primary; manual git-flow steps preserved as legacy fallback.
