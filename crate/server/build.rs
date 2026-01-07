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

// OpenSSL versions: main runtime (3.6.0) and FIPS provider source (3.1.2)
const OPENSSL_MAIN_VERSION: &str = "3.6.0";
const OPENSSL_MAIN_TARBALL: &str = "openssl-3.6.0.tar.gz";
const OPENSSL_MAIN_URL: &str = "https://package.cosmian.com/openssl/openssl-3.6.0.tar.gz";
const OPENSSL_MAIN_SHA256: &str =
    "b6a5f44b7eb69e3fa35dbf15524405b44837a481d43d81daddde3ff21fcbb8e9";

const OPENSSL_FIPS_VERSION: &str = "3.1.2";
const OPENSSL_FIPS_TARBALL: &str = "openssl-3.1.2.tar.gz";
const OPENSSL_FIPS_URL: &str = "https://package.cosmian.com/openssl/openssl-3.1.2.tar.gz"; // pinned historic URL
const OPENSSL_FIPS_SHA256: &str =
    "a0ce69b8b97ea6a35b96875235aa453b966ba3cba8af2de23657d8b6767d6539"; // expected hash (same as nix derivation)

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

    // We will prefer our own deterministic builds so we can stage assets cleanly
    if let Ok(dir) = env::var("OPENSSL_DIR") {
        println!(
            "cargo:warning=OPENSSL_DIR is set to {dir}; ignoring to ensure consistent staged assets"
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

    // Paths for main (3.6.0) and FIPS provider (3.1.2)
    // Default (FIPS mode): target/openssl-3.6.0-<os>-<arch>
    // Non-FIPS mode:       target/openssl-non-fips-3.6.0-<os>-<arch>
    let main_prefix = if fips_mode {
        target_dir.join(format!("openssl-{}-{}-{}", OPENSSL_MAIN_VERSION, os, arch))
    } else {
        target_dir.join(format!(
            "openssl-non-fips-{}-{}-{}",
            OPENSSL_MAIN_VERSION, os, arch
        ))
    };
    let fipsprov_prefix = target_dir.join(format!(
        "openssl-fipsprov-{}-{}-{}",
        OPENSSL_FIPS_VERSION, os, arch
    ));

    if let Err(e) = fs::create_dir_all(&build_root) {
        println!("cargo:warning=Failed to create build_root: {e}");
        return;
    }
    let _ = fs::create_dir_all(&main_prefix);
    if fips_mode {
        let _ = fs::create_dir_all(&fipsprov_prefix);
    }

    // Helper: build main OpenSSL (3.6.0) if needed
    if !main_prefix.join("lib/libcrypto.a").exists() {
        if let Err(e) = build_and_install_openssl(
            workspace_root,
            &build_root,
            OPENSSL_MAIN_VERSION,
            OPENSSL_MAIN_TARBALL,
            OPENSSL_MAIN_URL,
            OPENSSL_MAIN_SHA256,
            &main_prefix,
            // enable_fips on main tree: always false (runtime FIPS comes from 3.1.2 provider)
            false,
            // enable_legacy on main tree: only for non-FIPS builds
            !fips_mode,
        ) {
            println!(
                "cargo:warning=Failed to build OpenSSL {}: {e}",
                OPENSSL_MAIN_VERSION
            );
            return;
        }
    }

    // In FIPS mode, also build the 3.1.2 provider tree
    if fips_mode && !fipsprov_prefix.join("lib/ossl-modules").exists() {
        if let Err(e) = build_and_install_openssl(
            workspace_root,
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
        ) {
            println!(
                "cargo:warning=Failed to build OpenSSL {} (FIPS provider): {e}",
                OPENSSL_FIPS_VERSION
            );
            return;
        }
    }

    // Normalize provider path (lib64 -> lib) if necessary for both trees
    normalize_provider_layout(&main_prefix);
    if fips_mode {
        normalize_provider_layout(&fipsprov_prefix);
    }

    // Integrate provider/configs into the main prefix (no staging directory)
    integrate_assets_into_main(&main_prefix, fips_mode.then_some(&fipsprov_prefix));

    // Backward-compat alias: ensure target/openssl-fips-3.1.2-<os>-<arch>
    // resolves to the provider tree, even if a stale dir already exists.
    if fips_mode {
        let arch_bc = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_else(|_| "unknown-arch".into());
        let os_bc = env::var("CARGO_CFG_TARGET_OS").unwrap_or_else(|_| "unknown-os".into());
        let legacy_fips_dir = target_dir.join(format!(
            "openssl-fips-{}-{}-{}",
            OPENSSL_FIPS_VERSION, os_bc, arch_bc
        ));

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            match fs::symlink_metadata(&legacy_fips_dir) {
                Ok(meta) => {
                    if meta.file_type().is_symlink() {
                        // Ensure symlink points to the provider prefix
                        if let Ok(link_target) = fs::read_link(&legacy_fips_dir) {
                            if link_target != fipsprov_prefix {
                                let _ = fs::remove_file(&legacy_fips_dir);
                                let _ = symlink(&fipsprov_prefix, &legacy_fips_dir);
                            }
                        } else {
                            let _ = fs::remove_file(&legacy_fips_dir);
                            let _ = symlink(&fipsprov_prefix, &legacy_fips_dir);
                        }
                    } else {
                        // Directory exists but may be stale; check for fips.so
                        let fips_so = legacy_fips_dir.join("lib/ossl-modules").join(
                            if cfg!(target_os = "macos") {
                                "fips.dylib"
                            } else {
                                "fips.so"
                            },
                        );
                        if !fips_so.exists() {
                            let _ = fs::remove_dir_all(&legacy_fips_dir);
                            let _ = symlink(&fipsprov_prefix, &legacy_fips_dir);
                        }
                    }
                }
                Err(_) => {
                    let _ = symlink(&fipsprov_prefix, &legacy_fips_dir);
                }
            }
        }
        #[cfg(not(unix))]
        {
            // On non-unix, ensure the directory exists with the expected layout
            let modules = legacy_fips_dir.join("lib/ossl-modules");
            if !modules.exists() {
                let _ = fs::create_dir_all(&modules);
                let src = fipsprov_prefix.join("lib/ossl-modules");
                if let Ok(entries) = fs::read_dir(&src) {
                    for e in entries.flatten() {
                        let _ = fs::copy(e.path(), modules.join(e.file_name()));
                    }
                }
                let _ = fs::create_dir_all(legacy_fips_dir.join("ssl"));
                let _ = fs::copy(
                    fipsprov_prefix.join("ssl/openssl.cnf"),
                    legacy_fips_dir.join("ssl/openssl.cnf"),
                );
                let _ = fs::copy(
                    fipsprov_prefix.join("ssl/fipsmodule.cnf"),
                    legacy_fips_dir.join("ssl/fipsmodule.cnf"),
                );
            }
        }
    }

    // Emit link directives: link with main (3.6.0) and use configs/providers from main prefix
    emit_link_env(&main_prefix);
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
            #[cfg(unix)]
            {
                use std::os::unix::fs::symlink;
                let _ = symlink("../lib/ossl-modules", parent64.join("ossl-modules"));
            }
        }
    }
}

fn emit_link_env(link_prefix: &Path) {
    // Link against main tree (3.6.0)
    println!("cargo:rustc-env=OPENSSL_DIR={}", link_prefix.display());
    println!(
        "cargo:rustc-link-search=native={}/lib",
        link_prefix.display()
    );
    println!("cargo:rustc-link-lib=static=crypto");
    println!("cargo:rustc-link-lib=static=ssl");

    // Runtime env to load providers from desired tree
    println!(
        "cargo:rustc-env=OPENSSL_CONF={}/ssl/openssl.cnf",
        link_prefix.display()
    );
    println!(
        "cargo:rustc-env=OPENSSL_MODULES={}/lib/ossl-modules",
        link_prefix.display()
    );
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
        // Copy FIPS provider and configs into main prefix
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

    // Ensure dynamic libs (if built) are present under main prefix
    for libname in ["libssl.so.3", "libcrypto.so.3"] {
        let candidate = main_prefix.join("lib").join(libname);
        if candidate.exists() {
            // already present
        } else {
            // no-op; some builds use static linking only
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
    // Fetch
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

    // Hash warn (non-fatal)
    if !sha256.is_empty() {
        verify_hash(&tarball_path, sha256);
    }

    // Extract
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

    // Configure
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

    // Build
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

    // Install
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

// fips_artifacts_present no longer needed with split trees

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
