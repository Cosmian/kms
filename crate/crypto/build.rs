#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::uninlined_format_args,
    let_underscore_drop
)]

use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

const OPENSSL_MAIN_VERSION: &str = "3.6.0";
const OPENSSL_MAIN_TARBALL: &str = "openssl-3.6.0.tar.gz";
const OPENSSL_MAIN_URL: &str = "https://package.cosmian.com/openssl/openssl-3.6.0.tar.gz";
const OPENSSL_MAIN_SHA256: &str =
    "b6a5f44b7eb69e3fa35dbf15524405b44837a481d43d81daddde3ff21fcbb8e9";

const OPENSSL_FIPS_VERSION: &str = "3.1.2";
const OPENSSL_FIPS_TARBALL: &str = "openssl-3.1.2.tar.gz";
const OPENSSL_FIPS_URL: &str = "https://package.cosmian.com/openssl/openssl-3.1.2.tar.gz";
const OPENSSL_FIPS_SHA256: &str =
    "a0ce69b8b97ea6a35b96875235aa453b966ba3cba8af2de23657d8b6767d6539";

fn main() {
    println!("cargo:rerun-if-env-changed=OPENSSL_DIR");
    println!("cargo:rerun-if-env-changed=CARGO_TARGET_DIR");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_NON_FIPS");
    println!("cargo:rerun-if-changed=build.rs");

    // Skip OpenSSL build on Windows
    let os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if os == "windows" {
        println!("cargo:warning=Skipping OpenSSL build on Windows");
        return;
    }

    let fips_mode = env::var("CARGO_FEATURE_NON_FIPS").is_err();

    // Resolve workspace root: crate/crypto -> crate -> repo root
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let workspace_root = manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .unwrap_or(&manifest_dir)
        .to_path_buf();

    let target_dir = env::var_os("CARGO_TARGET_DIR").map_or_else(
        || workspace_root.join("target"),
        |s| Path::new(&s).to_path_buf(),
    );

    // Prefer Nix-provided OpenSSL if available; do not override its wrapper config
    if let Ok(dir) = env::var("OPENSSL_DIR") {
        let openssl_dir = PathBuf::from(&dir);
        let conf_path = openssl_dir.join("ssl").join("openssl.cnf");
        let modules_dir = openssl_dir.join("lib").join("ossl-modules");
        if conf_path.exists() && modules_dir.exists() {
            // Under Nix, runtime environment is configured by the dev shell/wrapper.
            // Do not emit OPENSSL_CONF here to avoid overriding wrapper config.
            // OPENSSL_MODULES is also provided by the shell, so no need to emit.
            println!("cargo:warning=Detected Nix environment; skipping local OpenSSL build");
            return;
        }
    }

    // Not in Nix or OPENSSL_DIR missing: build or reuse local OpenSSL
    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_else(|_| "unknown-arch".into());
    let os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_else(|_| "unknown-os".into());

    let main_prefix = if fips_mode {
        target_dir.join(format!("openssl-{}-{os}-{arch}", OPENSSL_MAIN_VERSION))
    } else {
        target_dir.join(format!(
            "openssl-non-fips-{}-{os}-{arch}",
            OPENSSL_MAIN_VERSION
        ))
    };
    let fipsprov_prefix = target_dir.join(format!(
        "openssl-fipsprov-{}-{os}-{arch}",
        OPENSSL_FIPS_VERSION
    ));

    let out_dir_os = env::var_os("OUT_DIR").unwrap();
    let out_dir = Path::new(&out_dir_os);
    let build_root = out_dir.join("openssl_build_crypto");
    let _ = fs::create_dir_all(&build_root);
    let _ = fs::create_dir_all(&main_prefix);
    if fips_mode {
        let _ = fs::create_dir_all(&fipsprov_prefix);
    }

    // Build main OpenSSL (3.6.0) if not present
    if !main_prefix.join("lib/libcrypto.a").exists() {
        let _ = build_and_install_openssl(
            &workspace_root,
            &build_root,
            OPENSSL_MAIN_VERSION,
            OPENSSL_MAIN_TARBALL,
            OPENSSL_MAIN_URL,
            OPENSSL_MAIN_SHA256,
            &main_prefix,
            // enable_fips=
            false,
            // enable_legacy=
            !fips_mode,
        );
    }

    // Always build FIPS provider (3.1.2) for test compatibility, regardless of feature flags
    // This ensures `cargo test` works for both FIPS and non-FIPS code paths
    if !fipsprov_prefix.join("lib/ossl-modules").exists() {
        let _ = build_and_install_openssl(
            &workspace_root,
            &build_root,
            OPENSSL_FIPS_VERSION,
            OPENSSL_FIPS_TARBALL,
            OPENSSL_FIPS_URL,
            OPENSSL_FIPS_SHA256,
            &fipsprov_prefix,
            // enable_fips=
            true,
            // enable_legacy=
            false,
        );
    }

    // Normalize provider layout and integrate FIPS provider/config into main prefix
    normalize_provider_layout(&main_prefix);
    normalize_provider_layout(&fipsprov_prefix);
    if fips_mode {
        integrate_assets_into_main(&main_prefix, Some(&fipsprov_prefix));
    }

    // Emit link + runtime env to use our local OpenSSL
    println!("cargo:rustc-env=OPENSSL_DIR={}", main_prefix.display());
    println!(
        "cargo:rustc-link-search=native={}/lib",
        main_prefix.display()
    );
    // Our OpenSSL build is configured with `no-shared`, but some environments (e.g. Nix)
    // may still provide dynamic libs. Prefer static when present, otherwise fall back
    // to dynamic to avoid link failures like "could not find native static library 'crypto'".
    let lib_dir = main_prefix.join("lib");
    let has_static_crypto = lib_dir.join("libcrypto.a").exists();
    let has_static_ssl = lib_dir.join("libssl.a").exists();
    if has_static_crypto && has_static_ssl {
        println!("cargo:rustc-link-lib=static=crypto");
        println!("cargo:rustc-link-lib=static=ssl");
    } else {
        println!(
            "cargo:warning=Static OpenSSL libs not found under {}; falling back to dynamic linking",
            lib_dir.display()
        );
        println!("cargo:rustc-link-lib=crypto");
        println!("cargo:rustc-link-lib=ssl");
    }
    println!(
        "cargo:rustc-env=OPENSSL_CONF={}/ssl/openssl.cnf",
        main_prefix.display()
    );
    println!(
        "cargo:rustc-env=OPENSSL_MODULES={}/lib/ossl-modules",
        main_prefix.display()
    );
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
    2
}

#[allow(clippy::manual_assert)]
fn verify_hash(path: &Path, expected: &str) {
    use sha2::{Digest, Sha256};
    if let Ok(buf) = fs::read(path) {
        let actual = format!("{:x}", Sha256::digest(&buf));
        if actual != expected {
            panic!("OpenSSL tarball hash mismatch: expected {expected} got {actual}");
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn build_and_install_openssl(
    workspace_root: &Path,
    build_root: &Path,
    version: &str,
    tarball: &str,
    url: &str,
    sha256: &str,
    install_prefix: &Path,
    enable_fips: bool,
    enable_legacy: bool,
) -> Result<(), String> {
    let local_tarball = workspace_root.join("resources/tarballs").join(tarball);
    let tarball_path = if local_tarball.exists() {
        println!(
            "cargo:warning=Using local cached tarball {}",
            local_tarball.display()
        );
        local_tarball
    } else {
        let dl_path = build_root.join(tarball);
        if !dl_path.exists() {
            println!("cargo:warning=Downloading {url}");
            run_cmd(
                Command::new("curl").args(["-fsSL", url, "-o", dl_path.to_str().unwrap()]),
                "curl",
            )?;
        }
        dl_path
    };
    if !sha256.is_empty() {
        verify_hash(&tarball_path, sha256);
    }

    let extract_dir = build_root.join(format!("src-{version}"));
    if !extract_dir.exists() {
        fs::create_dir_all(&extract_dir).map_err(|e| format!("mkdir extract_dir: {e}"))?;
        run_cmd(
            Command::new("tar")
                .current_dir(&extract_dir)
                .args(["-xf", tarball_path.to_str().unwrap()]),
            "tar -xf",
        )?;
    }
    let src_root = extract_dir.join(format!("openssl-{version}"));
    if !src_root.exists() {
        return Err(format!(
            "Expected source root not found: {}",
            src_root.display()
        ));
    }

    let target = determine_openssl_target();
    let prefix_arg = format!("--prefix={}", install_prefix.display());
    let openssldir_arg = format!("--openssldir={}/ssl", install_prefix.display());
    let mut configure_args = vec![
        "./Configure",
        "no-shared",
        prefix_arg.as_str(),
        openssldir_arg.as_str(),
        "--libdir=lib",
        &target,
    ];
    if enable_fips {
        configure_args.insert(1, "enable-fips");
    }
    if enable_legacy {
        configure_args.insert(1, "enable-legacy");
    }
    run_cmd(
        Command::new("perl")
            .current_dir(&src_root)
            .args(&configure_args),
        "Configure",
    )?;

    let jobs = num_parallel_jobs().to_string();
    run_cmd(
        Command::new("make").current_dir(&src_root).args(["depend"]),
        "make depend",
    )?;
    run_cmd(
        Command::new("make")
            .current_dir(&src_root)
            .args(["-j", &jobs]),
        "make -j",
    )?;

    let mut install_args = vec!["install_sw", "install_ssldirs", "-j", &jobs];
    if enable_fips {
        install_args.insert(0, "install_fips");
    }
    run_cmd(
        Command::new("make")
            .current_dir(&src_root)
            .args(&install_args),
        "make install",
    )?;

    // Patch openssl.cnf for provider activation depending on mode
    let ssl_dir = install_prefix.join("ssl");
    let openssl_cnf = ssl_dir.join("openssl.cnf");
    if let Ok(mut cnf) = fs::read_to_string(&openssl_cnf) {
        if enable_fips {
            let fipsmodule_cnf = ssl_dir.join("fipsmodule.cnf");
            let fipsmodule_path = fipsmodule_cnf.to_str().unwrap_or("fipsmodule.cnf");
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
        }
        if enable_legacy {
            if !cnf.contains("[provider_sect]") {
                cnf.push_str("\n[provider_sect]\ndefault = default_sect\nlegacy = legacy_sect\n\n[default_sect]\nactivate = 1\n\n[legacy_sect]\nactivate = 1\n");
            } else if !cnf.contains("legacy = legacy_sect") {
                if let Some(pos) = cnf.find("[provider_sect]") {
                    let insert_pos = cnf[pos..].find('\n').map_or(cnf.len(), |p| pos + p + 1);
                    cnf.insert_str(insert_pos, "legacy = legacy_sect\n");
                    cnf.push_str("\n[legacy_sect]\nactivate = 1\n");
                }
            }
        }
        let _ = fs::write(&openssl_cnf, cnf);
    }

    Ok(())
}

fn normalize_provider_layout(install_prefix: &Path) {
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
        }
    }
}

fn integrate_assets_into_main(main_prefix: &Path, fipsprov_prefix: Option<&Path>) {
    let _ = fs::create_dir_all(main_prefix.join("lib/ossl-modules"));
    let _ = fs::create_dir_all(main_prefix.join("ssl"));
    let mod_ext = if cfg!(target_os = "macos") {
        "dylib"
    } else {
        "so"
    };
    if let Some(fips_prefix) = fipsprov_prefix {
        let _ = fs::copy(
            fips_prefix.join(format!("lib/ossl-modules/fips.{mod_ext}")),
            main_prefix.join(format!("lib/ossl-modules/fips.{mod_ext}")),
        );
        let _ = fs::copy(
            fips_prefix.join("ssl/openssl.cnf"),
            main_prefix.join("ssl/openssl.cnf"),
        );
        let _ = fs::copy(
            fips_prefix.join("ssl/fipsmodule.cnf"),
            main_prefix.join("ssl/fipsmodule.cnf"),
        );
    }
}
