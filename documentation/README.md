# TL;DR

The main documentation of the KMS is in [docs/index.md](./docs/index.md)

## Rendering the documentation

This documentation is built with [mdBook](https://rust-lang.github.io/mdBook/).

Install the toolchain:

```sh
cargo install mdbook --version 0.4.52 --locked
cargo install mdbook-admonish --version 1.20.0
cargo install mdbook-mermaid --version 0.16.0
```

The mdBook `src/` is generated from `docs/` by the converter in the
`public_documentation` repository. To render this module standalone:

```sh
python3 <public_documentation>/migration/build_standalone.py .
mdbook serve     # live preview; static output is written to book/
```
