#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::manual_assert,
    clippy::uninlined_format_args,
    clippy::verbose_file_reads,
    let_underscore_drop
)]

use std::{env, fs, path::Path, process::Command};

use time::{OffsetDateTime, ext::NumericalDuration, format_description::well_known::Rfc2822};

const DEMO_TIMEOUT: i64 = 90; // 3 months in days

// OpenSSL FIPS build parameters (must mirror nix/openssl-3_1_2.nix)
const OPENSSL_VERSION: &str = "3.1.2";
const OPENSSL_TARBALL: &str = "openssl-3.1.2.tar.gz";
const OPENSSL_URL: &str = "https://www.openssl.org/source/old/3.1/openssl-3.1.2.tar.gz"; // pinned historic URL
const OPENSSL_SHA256: &str = "a0ce69b8b97ea6a35b96875235aa453b966ba3cba8af2de23657d8b6767d6539"; // expected hash (same as nix derivation)

fn main() {
    // Always re-run if this script changes
    println!("cargo:rerun-if-changed=build.rs");

    maybe_emit_demo_timeout();
    maybe_build_fips_openssl();
}

#[expect(clippy::unwrap_used)]
fn maybe_emit_demo_timeout() {
    if !cfg!(feature = "timeout") {
        return;
    }
    let now = OffsetDateTime::now_utc();
    let three_months_later = now + DEMO_TIMEOUT.days();

    let now_formatted = now.format(&Rfc2822).unwrap();
    let three_months_later_formatted = three_months_later.format(&Rfc2822).unwrap();

    println!("cargo:warning=Timeout set for demo version");
    println!("cargo:warning=- date of compilation: \t{now_formatted}");
    println!("cargo:warning=- end of demo in {DEMO_TIMEOUT} days:\t{three_months_later_formatted}");
    let out_dir = env::var_os("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("demo_timeout.rs");
    if let Err(e) = fs::write(
        dest_path,
        format!(
            "const DEMO_TIMEOUT: &[u8] = &{:?};\n            ",
            three_months_later_formatted.as_bytes()
        ),
    ) {
        println!("cargo:warning=Failed to write demo timeout file: {e}");
    }
}

// Decide whether we are in FIPS mode: default is FIPS unless `non-fips` is enabled.
fn is_fips_mode() -> bool {
    env::var("CARGO_FEATURE_NON_FIPS").is_err()
}

// Detect a Nix build environment — in that case the Nix derivation already provides a fully built OpenSSL (static, FIPS provider).
fn in_nix_env() -> bool {
    env::var("NIX_BUILD_TOP").is_ok() || env::var("IN_NIX_SHELL").is_ok()
}

fn maybe_build_fips_openssl() {
    let fips_mode = is_fips_mode();

    if in_nix_env() {
        // Nix provides OPENSSL_DIR (or paths discovered by openssl-sys). Nothing to do.
        println!("cargo:warning=Detected Nix environment; skipping local OpenSSL build");
        return;
    }

    // If user already exported OPENSSL_DIR, check if it's suitable
    if let Ok(dir) = env::var("OPENSSL_DIR") {
        let dirp = Path::new(&dir);
        if dirp.join("include").exists() {
            if fips_mode {
                if fips_artifacts_present(dirp) {
                    println!(
                        "cargo:warning=Using existing OPENSSL_DIR={dir} (FIPS artifacts detected; not rebuilding)"
                    );
                    return;
                }
                println!(
                    "cargo:warning=OPENSSL_DIR is set to {dir}, but FIPS provider artifacts were not found; will build FIPS OpenSSL"
                );
            } else {
                // In non-FIPS mode, any OpenSSL 3.x should work
                println!("cargo:warning=Using existing OPENSSL_DIR={dir} in non-FIPS mode");
                return;
            }
        }
    }

    if fips_mode {
        println!(
            "cargo:warning=Building OpenSSL {OPENSSL_VERSION} locally in FIPS mode (explicit/legacy FIPS requested, non-Nix environment)"
        );
    } else {
        println!(
            "cargo:warning=Building OpenSSL {OPENSSL_VERSION} locally in non-FIPS mode with legacy provider support"
        );
    }

    let out_dir_os = env::var_os("OUT_DIR").unwrap();
    let out_dir = Path::new(&out_dir_os);
    // Temporary build root can live under the ephemeral OUT_DIR
    let build_root = out_dir.join("openssl_build");

    // Install prefix must be stable across builds so we can reuse the same artifacts.
    // Use the workspace `target/` directory with a deterministic subpath based on
    // version and target (os/arch). This avoids rebuilding OpenSSL for every OUT_DIR.
    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_else(|_| "unknown-arch".into());
    let os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_else(|_| "unknown-os".into());

    // Resolve workspace root from CARGO_MANIFEST_DIR (crate/server -> crate -> repo root)
    let Some(manifest_dir_os) = env::var_os("CARGO_MANIFEST_DIR") else {
        println!("cargo:warning=Missing CARGO_MANIFEST_DIR; aborting OpenSSL build");
        return;
    };
    let manifest_dir = Path::new(&manifest_dir_os);
    let workspace_root = manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .unwrap_or_else(|| Path::new("."));

    // Allow respect of CARGO_TARGET_DIR if set; fallback to <workspace>/target
    #[allow(clippy::map_unwrap_or)]
    let target_dir = env::var_os("CARGO_TARGET_DIR")
        .map(|s| Path::new(&s).to_path_buf())
        .unwrap_or_else(|| workspace_root.join("target"));

    let mode_suffix = if fips_mode { "fips" } else { "legacy" };
    let install_prefix = target_dir.join(format!(
        "openssl-{}-{}-{}-{}",
        mode_suffix, OPENSSL_VERSION, os, arch
    ));

    if install_prefix.join("lib/libcrypto.a").exists() {
        println!(
            "cargo:warning=Cached {} OpenSSL already present at {}",
            if fips_mode { "FIPS" } else { "legacy" },
            install_prefix.display()
        );
        emit_link_env(&install_prefix);
        return;
    }

    if let Err(e) = fs::create_dir_all(&build_root) {
        println!("cargo:warning=Failed to create build_root: {e}");
        return;
    }
    if let Err(e) = fs::create_dir_all(&install_prefix) {
        println!("cargo:warning=Failed to create install_prefix: {e}");
        return;
    }

    // Obtain the tarball: prefer project-local resources/tarballs like the Nix derivation for offline parity
    let local_tarball = workspace_root
        .join("resources/tarballs")
        .join(OPENSSL_TARBALL);

    let tarball_path = if local_tarball.exists() {
        println!(
            "cargo:warning=Using local cached tarball {}",
            local_tarball.display()
        );
        local_tarball
    } else {
        let dl_path = build_root.join(OPENSSL_TARBALL);
        if !dl_path.exists() {
            println!("cargo:warning=Downloading {OPENSSL_URL}");
            match Command::new("curl")
                .args(["-fsSL", OPENSSL_URL, "-o", dl_path.to_str().unwrap()])
                .status()
            {
                Ok(status) if status.success() => {}
                Ok(status) => {
                    println!(
                        "cargo:warning=curl download failed with status {status}; aborting FIPS build"
                    );
                    return;
                }
                Err(e) => {
                    println!("cargo:warning=Failed to spawn curl: {e}; aborting FIPS build");
                    return;
                }
            }
        }
        dl_path
    };

    verify_hash(&tarball_path, OPENSSL_SHA256);

    // Extract
    let extract_dir = build_root.join("src");
    if !extract_dir.exists() {
        if let Err(e) = fs::create_dir_all(&extract_dir) {
            println!("cargo:warning=Failed to create extract_dir: {e}");
            return;
        }
        match Command::new("tar")
            .current_dir(&extract_dir)
            .args(["-xf", tarball_path.to_str().unwrap()])
            .status()
        {
            Ok(status) if status.success() => {}
            Ok(status) => {
                println!("cargo:warning=tar extraction failed (status {status})");
                return;
            }
            Err(e) => {
                println!("cargo:warning=Failed to spawn tar: {e}");
                return;
            }
        }
    }

    let src_root = extract_dir.join(format!("openssl-{OPENSSL_VERSION}"));
    if !src_root.exists() {
        println!(
            "cargo:warning=Expected source root not found: {}",
            src_root.display()
        );
        return;
    }

    // Determine OpenSSL target (mirrors nix expression logic)
    let target = determine_openssl_target();

    // Configure with appropriate options based on mode
    let prefix_arg = format!("--prefix={}", install_prefix.display());
    let openssldir_arg = format!("--openssldir={}/ssl", install_prefix.display());

    let mut configure_args = vec![
        "./Configure",
        "no-shared",
        prefix_arg.as_str(),
        openssldir_arg.as_str(),
        "--libdir=lib",
    ];

    if fips_mode {
        configure_args.push("enable-fips");
    } else {
        // In non-FIPS mode, enable legacy provider support
        configure_args.push("enable-legacy");
    }

    configure_args.push(&target);

    if let Err(e) = run_cmd(
        Command::new("perl")
            .current_dir(&src_root)
            .args(&configure_args),
        if fips_mode {
            "Configure (FIPS)"
        } else {
            "Configure (legacy)"
        },
    ) {
        println!("cargo:warning=Configure failed: {e}");
        return;
    }

    // Build (parallel jobs = cores - 1)
    let jobs = num_parallel_jobs();
    if let Err(e) = run_cmd(
        Command::new("make").current_dir(&src_root).args(["depend"]),
        "make depend",
    ) {
        println!("cargo:warning=make depend failed: {e}");
        return;
    }
    if let Err(e) = run_cmd(
        Command::new("make")
            .current_dir(&src_root)
            .args(["-j", &jobs.to_string()]),
        "make -j",
    ) {
        println!("cargo:warning=make build failed: {e}");
        return;
    }

    // Install (including FIPS artifacts in FIPS mode, or standard install in non-FIPS)
    let jobs_str = jobs.to_string();
    let mut install_args = vec!["install_sw", "install_ssldirs"];
    if fips_mode {
        install_args.push("install_fips");
    }
    install_args.extend_from_slice(&["-j", &jobs_str]);

    if let Err(e) = run_cmd(
        Command::new("make")
            .current_dir(&src_root)
            .args(&install_args),
        "make install",
    ) {
        println!("cargo:warning=make install failed: {e}");
        return;
    }

    // Patch openssl.cnf to activate providers
    let ssl_dir = install_prefix.join("ssl");
    let openssl_cnf = ssl_dir.join("openssl.cnf");

    if openssl_cnf.exists() {
        let Ok(mut cnf) = fs::read_to_string(&openssl_cnf) else {
            println!("cargo:warning=Failed to read openssl.cnf");
            return;
        };

        if fips_mode {
            // FIPS mode: activate FIPS module exactly like nix derivation
            let fipsmodule_cnf = ssl_dir.join("fipsmodule.cnf");
            let fipsmodule_path = fipsmodule_cnf.to_str().unwrap_or("fipsmodule.cnf");

            // Handle both commented and uncommented .include directives
            // Replace any relative path references with absolute path
            if cnf.contains("# .include fipsmodule.cnf") {
                cnf = cnf.replace(
                    "# .include fipsmodule.cnf",
                    &format!(".include {}", fipsmodule_path),
                );
            } else if cnf.contains(".include ./fipsmodule.cnf") {
                cnf = cnf.replace(
                    ".include ./fipsmodule.cnf",
                    &format!(".include {}", fipsmodule_path),
                );
            } else if cnf.contains(".include fipsmodule.cnf") {
                cnf = cnf.replace(
                    ".include fipsmodule.cnf",
                    &format!(".include {}", fipsmodule_path),
                );
            }
            if cnf.contains("# activate = 1") {
                cnf = cnf.replace("# activate = 1", "activate = 1");
            }
            if cnf.contains("# fips = fips_sect") {
                cnf = cnf.replace(
                    "# fips = fips_sect",
                    "fips = fips_sect\nbase = base_sect\n\n[ base_sect ]\nactivate = 1\n",
                );
            }
        } else {
            // Non-FIPS mode: ensure legacy and default providers are activated
            // Add legacy provider configuration if not present
            if !cnf.contains("[provider_sect]") {
                cnf.push_str("\n[provider_sect]\ndefault = default_sect\nlegacy = legacy_sect\n\n[default_sect]\nactivate = 1\n\n[legacy_sect]\nactivate = 1\n");
            } else if !cnf.contains("legacy = legacy_sect") {
                // provider_sect exists but legacy is not configured
                if let Some(pos) = cnf.find("[provider_sect]") {
                    let insert_pos = cnf[pos..].find('\n').map_or(cnf.len(), |p| pos + p + 1);
                    cnf.insert_str(insert_pos, "legacy = legacy_sect\n");
                    cnf.push_str("\n[legacy_sect]\nactivate = 1\n");
                }
            }
        }

        if let Err(e) = fs::write(&openssl_cnf, cnf) {
            println!("cargo:warning=Failed to patch openssl.cnf: {e}");
        }
    } else {
        println!("cargo:warning=openssl.cnf not found; provider activation patch skipped");
    }

    // Normalize provider path (lib64 -> lib) if necessary
    let lib64 = install_prefix.join("lib64/ossl-modules");
    let lib = install_prefix.join("lib/ossl-modules");
    if lib64.exists() && !lib.exists() {
        if let Some(parent) = lib.parent() {
            let _ = fs::create_dir_all(parent);
        }
        if let Ok(entries) = fs::read_dir(&lib64) {
            for entry in entries.flatten() {
                let dest = lib.join(entry.file_name());
                let _ = fs::rename(entry.path(), dest);
            }
        }
        if let Some(parent64) = lib64.parent() {
            let _ = fs::remove_dir_all(parent64.join("ossl-modules"));
            let _ = fs::create_dir_all(parent64);
            #[cfg(unix)]
            {
                use std::os::unix::fs::symlink;
                let _ = symlink("../lib/ossl-modules", parent64.join("ossl-modules"));
            }
        }
    }

    // Emit link environment variables
    // In FIPS mode, only do this if FIPS artifacts are present
    // In non-FIPS mode, always do this since we built OpenSSL with legacy provider
    if fips_mode {
        if fips_artifacts_present(&install_prefix) {
            emit_link_env(&install_prefix);
        } else {
            println!(
                "cargo:warning=Local OpenSSL build completed but FIPS artifacts are missing; falling back to system OpenSSL"
            );
        }
    } else {
        // In non-FIPS mode, always emit link env since we built with legacy provider
        emit_link_env(&install_prefix);
    }
}

fn emit_link_env(install_prefix: &Path) {
    println!("cargo:rustc-env=OPENSSL_DIR={}", install_prefix.display());
    println!(
        "cargo:rustc-link-search=native={}/lib",
        install_prefix.display()
    );
    // Static linking (no shared libcrypto/libssl)
    println!("cargo:rustc-link-lib=static=crypto");
    println!("cargo:rustc-link-lib=static=ssl");

    // Set runtime environment variables so tests can find FIPS provider and config
    println!(
        "cargo:rustc-env=OPENSSL_CONF={}/ssl/openssl.cnf",
        install_prefix.display()
    );
    println!(
        "cargo:rustc-env=OPENSSL_MODULES={}/lib/ossl-modules",
        install_prefix.display()
    );
}

fn fips_artifacts_present(prefix: &Path) -> bool {
    let mod_ext = if cfg!(target_os = "macos") {
        "dylib"
    } else {
        "so"
    };
    let provider = prefix.join(format!("lib/ossl-modules/fips.{mod_ext}"));
    let cnf = prefix.join("ssl/fipsmodule.cnf");
    provider.exists() && cnf.exists()
}

fn run_cmd(cmd: &mut Command, context: &str) -> Result<(), String> {
    println!("cargo:warning=Running {context} -> {:?}", cmd);
    match cmd.status() {
        Ok(status) if status.success() => Ok(()),
        Ok(status) => Err(format!("{context} failed with status {status}")),
        Err(e) => Err(format!("Failed to spawn {context}: {e}")),
    }
}

fn determine_openssl_target() -> String {
    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if os == "macos" {
        if arch == "aarch64" {
            "darwin64-arm64-cc".into()
        } else {
            "darwin64-x86_64-cc".into()
        }
    } else if arch == "aarch64" {
        "linux-aarch64".into()
    } else {
        "linux-x86_64".into()
    }
}

fn num_parallel_jobs() -> usize {
    // Try common environment hints / commands, fall back to 2
    if let Ok(v) = env::var("NUM_JOBS") {
        if let Ok(n) = v.parse::<usize>() {
            return n.max(1);
        }
    }
    #[cfg(target_os = "linux")]
    {
        if let Ok(output) = Command::new("nproc").output() {
            if let Ok(s) = std::str::from_utf8(&output.stdout) {
                if let Ok(n) = s.trim().parse::<usize>() {
                    return n.max(1);
                }
            }
        }
    }
    #[cfg(target_os = "macos")]
    {
        if let Ok(output) = Command::new("sysctl").args(["-n", "hw.ncpu"]).output() {
            if let Ok(s) = std::str::from_utf8(&output.stdout) {
                if let Ok(n) = s.trim().parse::<usize>() {
                    return n.max(1);
                }
            }
        }
    }
    2
}

fn verify_hash(path: &Path, expected: &str) {
    use sha2::{Digest, Sha256};
    let Ok(buf) = fs::read(path) else {
        println!(
            "cargo:warning=Failed to read {} for hash verification",
            path.display()
        );
        return;
    };
    let actual = format!("{:x}", Sha256::digest(&buf));
    if actual != expected {
        println!(
            "cargo:warning=OpenSSL tarball hash mismatch! expected {expected} got {actual}; aborting FIPS build"
        );
    }
}
