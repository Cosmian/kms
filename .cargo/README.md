### Optional: Faster compilation

You can add the following to your `.cargo/config.toml` to potentially speed up compilation on your local machine.

> **Note:** These flags are intentionally not set by default. The GitHub runners used to build the KMS Docker image have unpredictable CPU architectures, which causes error code 132 when running containers built with `target_cpu=native`. These flags are however passed explicitly in CI for macOS, Windows, Linux, and CentOS 7 builds via the `RUSTFLAGS` environment variable in `cargo_build.yml`.

```toml
[build]
# Speeds up Ristretto 25519 multiplication x 2
rustflags = [
  "--cfg",
  "curve25519_dalek_backend=\"simd\"",
  "-C",
  "target_cpu=native",
]

# Can increase link speed on systems that support mold
[target.x86_64-unknown-linux-gnu]
linker = "clang"
rustflags = ["-C", "link-arg=-fuse-ld=mold"]
```

### Optional: VS Code / rust-analyzer

Add the following to your `.vscode/settings.json` to prevent rust-analyzer from interfering with regular `cargo` builds, which also reduces overall compilation time:

```json
{
  "rust-analyzer.cargo.extraEnv": {
    "CARGO_TARGET_DIR": "target/rust-analyzer"
  }
}
```
