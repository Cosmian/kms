# Changelog — develop branch

## Security

- Upgrade `mysql_async` from `0.36` to `0.37` and add `default-features = false` to drop the `derive` feature; this removes the transitive `mysql-common-derive → proc-macro-error2` chain and eliminates `RUSTSEC-2026-0173` from the dependency graph without requiring an advisory ignore.
