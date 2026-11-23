---
name: 'FFI exports'
description: 'Rules for cdylibs loaded into foreign host processes (PKCS#11 provider, CNG KSP)'
applyTo: 'crate/clients/pkcs11/**/*.rs, crate/clients/cng/**/*.rs'
---

# FFI exports (PKCS#11 provider, CNG KSP)

These libraries run inside foreign host processes (e.g. Oracle TDE, SAP ASE, `ssh-agent`, Windows `NCrypt` callers): an uncaught panic or abort terminates the host.

- Run every exported `extern "C"` / `extern "system"` body inside `ffi_guard` (`cryptoki_fn!` for PKCS#11, explicit wrapper for hand-written exports). On panic, latch the module as faulted, leak the panic payload with `std::mem::forget` so payload `Drop` cannot abort, and return an error (`CKR_GENERAL_ERROR`).
- Build and ship these cdylibs with `panic = "unwind"` (`--profile pkcs11-provider`), enforced at compile time via `#[cfg(panic = "abort")] compile_error!(...)`. Under `release` (`panic = "abort"`) `catch_unwind` is a no-op.
- No `process::abort`, `process::exit`, `println!` / `eprintln!` (they panic on broken pipes), or panicking lazy initialization: cache the `Result` (`RUNTIME` in `crate/clients/pkcs11/provider/src/kms_object.rs`).
- Null-check every caller pointer (`not_null!` / `is_null()`) before dereferencing or calling `slice::from_raw_parts*`. `ffi_guard` cannot catch undefined behavior, and std's debug UB checks call `panic_nounwind`.
- Every `unsafe` block carries a `// SAFETY:` comment naming the caller contract clause it relies on; keep one pointer operation per block where practical; every `unsafe extern` export documents pointer preconditions under `# Safety`; write `static mut` tables only inside `Once::call_once`.
- Allocate and free on the same side: handles handed to the host via `Box::into_raw` are freed only by our own free entry point (`Box::from_raw`).
- Test panicking bodies and post-fault refusal in isolated child processes because the fault latch is process-wide (`crate/clients/pkcs11/module/src/tests.rs::panic_boundary`).
- Legacy exception: the Windows CNG KSP (`crate/clients/cng/`) does not yet wrap exports in a panic guard or build with an unwind profile; fix any touched path without regressing existing behavior.
