//! Diagnostic binary that dynamically loads `libcosmian_pkcs11.so` (or `.dylib` / `.dll`)
//! and walks through the standard PKCS#11 API sequence to verify that:
//!
//! * the shared library opens without error,
//! * `ckms.toml` is found and parsed correctly (caught by `C_GetFunctionList`),
//! * the KMS server at the URL declared in `ckms.toml` is reachable (caught when
//!   `C_FindObjects` triggers the first REST call).
//!
//! Nothing in this crate depends on `cosmian_pkcs11` — the library is exercised
//! purely through the C PKCS#11 ABI using `libloading` and `pkcs11-sys`.

#![allow(
    unsafe_code,
    clippy::print_stdout,          // diagnostic binary — stdout output is intentional
    clippy::multiple_crate_versions,
    clippy::cargo_common_metadata,
    clippy::exhaustive_structs,    // clap derive structs are internal only
    clippy::std_instead_of_core,
)]

use std::{env, ffi::c_void, path::PathBuf, ptr};

use clap::Parser;
use cosmian_pkcs11_verify::{
    call_find_objects, call_get_function_list, call_get_slot_list, call_login, call_open_session,
    check_rv,
};
use libloading::Library;
use pkcs11_sys::CK_FUNCTION_LIST;

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

/// Verify that `libcosmian_pkcs11.so` is loadable and can communicate with
/// the Cosmian KMS server.
#[derive(Parser)]
#[command(
    name = "cosmian_pkcs11_verify",
    version,
    about = "Verify that libcosmian_pkcs11.so loads and communicates with the KMS server"
)]
struct Cli {
    /// Path to the PKCS#11 shared library (`libcosmian_pkcs11.so` / `.dylib` / `.dll`).
    /// Can be supplied via the `COSMIAN_PKCS11_LIB` environment variable instead.
    #[arg(long, env = "COSMIAN_PKCS11_LIB", value_name = "PATH")]
    so_path: PathBuf,

    /// Explicit path to `ckms.toml`.  When set, the `CKMS_CONF` environment
    /// variable is written before the library is loaded so that the provider
    /// picks up this configuration file.
    #[arg(long, value_name = "PATH")]
    conf: Option<PathBuf>,

    /// Bearer token (OIDC/JWT) to pass to `C_Login`.
    /// Required when `ckms.toml` has `pkcs11_use_pin_as_access_token = true`.
    /// Can also be supplied via the `COSMIAN_PKCS11_TOKEN` environment variable.
    #[arg(long, value_name = "JWT", env = "COSMIAN_PKCS11_TOKEN")]
    token: Option<String>,
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn main() {
    if let Err(e) = run() {
        eprintln!("\n{e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let cli = Cli::parse();

    // ── Step A: Determine which ckms.toml will be used ──────────────────────
    describe_config(&cli);

    // Set CKMS_CONF *before* opening the .so so that C_GetFunctionList can
    // read the requested configuration path.
    if let Some(ref conf_path) = cli.conf {
        // Safety: single-threaded at this point; no other threads are running yet,
        // so mutating the environment is safe.
        unsafe { env::set_var("CKMS_CONF", conf_path) };
    }

    // ── Step B: Load the shared library ────────────────────────────────────
    println!("[load] Opening: {}", cli.so_path.display());
    let lib = unsafe { Library::new(&cli.so_path) }.map_err(|e| {
        format!(
            "FAIL [load]: cannot open '{}': {e}\n  \
             Hint: make sure the path is correct and the library has the right \
             architecture for this platform.",
            cli.so_path.display()
        )
    })?;
    println!("[load] OK: shared library opened");
    println!();

    // ── Step C: C_GetFunctionList ───────────────────────────────────────────
    // This is where the provider reads ckms.toml and builds the KmsClient.
    // Any configuration or network-init error surfaces here as CKR_FUNCTION_FAILED.
    let func_list_ptr = call_get_function_list(&lib)?;

    // Safety: C_GetFunctionList returned CKR_OK and wrote a non-null pointer;
    // the function list lives for the duration of `lib` (i.e. this function).
    let func_list: &CK_FUNCTION_LIST = unsafe { &*func_list_ptr };

    println!("[C_GetFunctionList] OK: ckms.toml parsed");
    println!();

    // ── Step D: C_Initialize ────────────────────────────────────────────────
    let c_initialize = func_list
        .C_Initialize
        .ok_or_else(|| "FAIL [C_Initialize]: not present in function list".to_owned())?;
    let rv = unsafe { c_initialize(ptr::null_mut::<c_void>()) };
    check_rv(rv, "C_Initialize")?;
    println!("[C_Initialize] OK");
    println!();

    // ── Step E: C_GetSlotList ───────────────────────────────────────────────
    let slot_id = call_get_slot_list(func_list)?;
    println!("[C_GetSlotList] OK: using slot ID {slot_id}");
    println!();

    // ── Step F: C_OpenSession ───────────────────────────────────────────────
    let session = call_open_session(func_list, slot_id)?;
    println!("[C_OpenSession] OK: session opened on slot {slot_id}");
    println!();

    // ── Step F½: C_Login (when --token / COSMIAN_PKCS11_TOKEN is supplied) ───
    if let Some(ref token) = cli.token {
        call_login(func_list, session, token)?;
        println!("[C_Login] OK: session authenticated with provided token");
        println!();
    }

    // ── Steps G–I: Enumerate objects by class (triggers first KMS REST call) ─
    let found_count = call_find_objects(func_list, session);
    println!("[C_FindObjects] OK: {found_count} PKCS#11 object(s) visible on KMS");
    println!();

    // ── Step J: C_CloseSession ──────────────────────────────────────────────
    let c_close_session = func_list
        .C_CloseSession
        .ok_or_else(|| "FAIL [C_CloseSession]: not present in function list".to_owned())?;
    let rv = unsafe { c_close_session(session) };
    check_rv(rv, "C_CloseSession")?;
    println!("[C_CloseSession] OK");

    // ── Step K: C_Finalize ──────────────────────────────────────────────────
    let c_finalize = func_list
        .C_Finalize
        .ok_or_else(|| "FAIL [C_Finalize]: not present in function list".to_owned())?;
    let rv = unsafe { c_finalize(ptr::null_mut::<c_void>()) };
    check_rv(rv, "C_Finalize")?;
    println!("[C_Finalize] OK");

    println!();
    println!("All checks passed.");

    Ok(())
}

// ---------------------------------------------------------------------------
// Step A helper – describe config location
// ---------------------------------------------------------------------------

fn describe_config(cli: &Cli) {
    if let Some(ref p) = cli.conf {
        println!("[conf] Will use --conf: {}", p.display());
    } else if let Ok(v) = env::var("CKMS_CONF") {
        println!("[conf] Will use CKMS_CONF env: {v}");
    } else {
        // Check alongside the .so
        let adjacent = cli
            .so_path
            .parent()
            .map(|d| d.join("ckms.toml"))
            .filter(|p| p.exists());

        if let Some(ref p) = adjacent {
            println!("[conf] Will use ckms.toml adjacent to .so: {}", p.display());
        } else {
            // Default search order mirrors ClientConfig::location()
            let home_conf = env::var("HOME")
                .ok()
                .map(|h| PathBuf::from(h).join(".cosmian").join("ckms.toml"));
            let system_conf = PathBuf::from("/etc/cosmian/ckms.toml");

            if home_conf.as_ref().is_some_and(|p| p.exists()) {
                println!(
                    "[conf] Will use default home config: {}",
                    home_conf
                        .as_ref()
                        .map_or_else(PathBuf::new, Clone::clone)
                        .display()
                );
            } else if system_conf.exists() {
                println!("[conf] Will use system config: {}", system_conf.display());
            } else {
                println!(
                    "[conf] WARNING: no ckms.toml found at any standard location \
                     (~/.cosmian/ckms.toml, /etc/cosmian/ckms.toml).\n  \
                     C_GetFunctionList will fail unless CKMS_CONF is set or \
                     a ckms.toml sits next to the .so."
                );
            }
        }
    }
    println!();
}
