## CI

- Fix nightly `package-and-commit-sbom` failing with `Could not find the dispatched packaging.yml run`: take the run ID from the URL printed by `gh workflow run` and, when none is printed, poll the run list for up to 3 minutes instead of a single query after a fixed 10 s sleep
