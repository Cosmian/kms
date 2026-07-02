//! HSM symmetric key rotation tests using bare keyset name.
//!
//! Tests that `ckms sym keys re-key --key-id <keyset_name>` works for
//! 3 consecutive rotations without the `hsm::slot::` prefix.

use cosmian_logger::log_init;
use test_kms_server::{
    TestClientOptions, TestsContext, hsm_config_path, start_test_server_with_patch,
};
use uuid::Uuid;

use crate::{
    error::result::CosmianResult,
    tests::{
        shared::destroy,
        symmetric::{create_key::create_symmetric_key, rekey::rekey_symmetric_key},
        utils::{owner_config, run_ckms},
    },
};

/// Read the `HSM_SLOT_ID` env var (same value used by the test server).
/// Returns `None` when the variable is absent so callers can skip the test.
fn hsm_slot_id() -> Option<usize> {
    std::env::var("HSM_SLOT_ID").ok()?.parse().ok()
}

/// Test: 3 consecutive re-keys using the HSM base UID as the stable keyset handle.
///
/// For HSM keys, `rotate_name` must be the full base UID (`hsm::<slot>::<key_id>`),
/// not just the bare key name.  This ensures uniqueness across HSM slots when
/// multiple slots host keys with the same local name.
///
/// Steps:
/// 1. Create AES-256 key on HSM with explicit UID `hsm::<slot>::<name>`
/// 2. Set rotation-name = `hsm::<slot>::<name>` (the key's full base UID)
/// 3. Re-key 3× using the base UID `hsm::<slot>::<name>` (no `@N` suffix)
///    The dispatcher routes to `rekey_hsm_symmetric` which selectively redirects
///    stable-handle requests (no @N) to the latest generation.
/// 4. Assert each re-key returns a distinct UID
/// 5. Cleanup all 4 generations
pub(crate) fn test_hsm_rekey_by_bare_keyset_name(ctx: &TestsContext) -> CosmianResult<()> {
    log_init(None);
    let owner_client_conf_path = owner_config(ctx);
    let Some(slot) = hsm_slot_id() else {
        println!("  HSM_SLOT_ID not set — skipping test");
        return Ok(());
    };

    // Use a unique keyset name per test run to avoid collisions with stale state
    let keyset_name = format!("ckms_rk_{}", Uuid::new_v4().as_simple());
    let hsm_uid = format!("hsm::{slot}::{keyset_name}");

    // ── Step 1: Create gen-0 on HSM ─────────────────────────────────────
    let gen0_id = create_symmetric_key(
        &owner_client_conf_path,
        &["--algorithm", "aes", "--number-of-bits", "256", &hsm_uid],
    )?;
    assert_eq!(
        gen0_id, hsm_uid,
        "server should echo back the requested UID"
    );
    println!("  gen-0: {gen0_id}");

    // ── Step 2: Set rotation name = full base UID ───────────────────────
    let args = vec![
        "sym",
        "keys",
        "set-rotation-policy",
        "--key-id",
        &gen0_id,
        "--rotation-name",
        &hsm_uid,
    ];
    let output = run_ckms(&owner_client_conf_path, &args)?;
    assert!(
        output.contains("Rotation policy set successfully"),
        "set-rotation-policy failed: {output}"
    );

    // ── Step 3: First re-key using base UID (stable handle) ─────────────
    let gen1_id = rekey_symmetric_key(&owner_client_conf_path, &hsm_uid)?;
    println!("  gen-1: {gen1_id}");
    assert_ne!(gen1_id, gen0_id, "gen-1 must differ from gen-0");
    assert!(
        gen1_id.contains("@1"),
        "gen-1 UID should contain @1, got: {gen1_id}"
    );

    // ── Step 4: Second re-key using base UID (stable handle) ────────────
    let gen2_id = rekey_symmetric_key(&owner_client_conf_path, &hsm_uid)?;
    println!("  gen-2: {gen2_id}");
    assert_ne!(gen2_id, gen1_id, "gen-2 must differ from gen-1");
    assert!(
        gen2_id.contains("@2"),
        "gen-2 UID should contain @2, got: {gen2_id}"
    );

    // ── Step 5: Third re-key using base UID (stable handle) ─────────────
    let gen3_id = rekey_symmetric_key(&owner_client_conf_path, &hsm_uid)?;
    println!("  gen-3: {gen3_id}");
    assert_ne!(gen3_id, gen2_id, "gen-3 must differ from gen-2");
    assert!(
        gen3_id.contains("@3"),
        "gen-3 UID should contain @3, got: {gen3_id}"
    );

    // ── Cleanup ─────────────────────────────────────────────────────────
    for uid in [&gen0_id, &gen1_id, &gen2_id, &gen3_id] {
        destroy(&owner_client_conf_path, "sym", uid, true).ok();
    }

    println!("  ✓ 3 consecutive bare-name HSM re-keys succeeded");
    Ok(())
}

#[tokio::test]
async fn test_hsm_rekey_bare_keyset_name() -> CosmianResult<()> {
    let Some(slot) = hsm_slot_id() else {
        // HSM_SLOT_ID not set in this environment — skip gracefully.
        return Ok(());
    };
    let config_path = hsm_config_path("three_softhsm2.toml");
    let ctx = start_test_server_with_patch(
        &config_path,
        move |config| {
            config.hsm.hsm_slot = vec![slot];
        },
        TestClientOptions::default(),
    )
    .await
    .map_err(|e| crate::error::CosmianError::Default(e.to_string()))?;
    test_hsm_rekey_by_bare_keyset_name(&ctx)
}
