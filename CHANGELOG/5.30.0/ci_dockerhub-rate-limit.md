## CI

- Reduce Docker Hub pull-rate-limit exposure: authenticate Docker Hub pulls with the new `DOCKERHUB_USERNAME`/`DOCKERHUB_TOKEN` repository secrets (`test_all.yml` `test-nix` login step skipped when secrets are absent, e.g. fork PRs; `container.credentials` on `packages-test` and `alpine-native-build`), and collapse the `features`/`link` (`packages-test`) and `features` (`alpine-packages-test`) matrix axes into in-job loops so each leg pulls its base image once (`packages-test` 56 → 14 legs, `alpine-packages-test` 12 → 6 legs; same combinations still tested)
