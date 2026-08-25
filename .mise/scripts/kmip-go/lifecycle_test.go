package kmip_go_tests

// Key lifecycle and state transition tests driven by ovh/kmip-go.
//
// These tests validate the KMIP key state machine (PreActive → Active →
// Deactivated → Destroyed) and cryptographic usage mask enforcement.
//
// Spec references: OASIS KMIP 1.4 specification (kmip/v1.4/ in this repo).

import (
    "fmt"
    "testing"

    "github.com/ovh/kmip-go"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

// ─── 1. Key state transitions ────────────────────────────────────────────────

// TestLifecycle_PreActiveCannotEncrypt verifies that a key in PreActive state
// cannot be used for encryption.
//
// Spec: KMIP 1.4 §4.5, §3.22.
func TestLifecycle_PreActiveCannotEncrypt(t *testing.T) {
    client := newClient(t, kmip.V1_4)

    // Create key but do NOT activate it (stays PreActive)
    resp, err := client.Create().
        AES(256, kmip.CryptographicUsageEncrypt|kmip.CryptographicUsageDecrypt).
        WithName("preactive-no-encrypt").
        ExecContext(tctx(t))
    require.NoError(t, err, "Create must succeed")
    id := resp.UniqueIdentifier
    t.Cleanup(func() { cleanupKey(t, client, id) })

    // Verify the key is in PreActive state
    stateVal := singleAttributeValue(t, client, id, kmip.AttributeNameState)
    assert.Equal(t, fmt.Sprint(kmip.StatePreActive), fmt.Sprint(stateVal),
        "Key must be in PreActive state before Activate")

    // Attempt to encrypt — must fail
    _, err = client.Encrypt(id).
        WithCryptographicParameters(kmip.AES_GCM).
        Data([]byte("test data")).
        ExecContext(tctx(t))
    assert.Errorf(t, err,
        "Encrypt MUST fail on a PreActive key (KMIP 1.4 §4.5: operation requires Active state)")
}

// TestLifecycle_DeactivatedCannotEncrypt verifies that a key in Deactivated
// state cannot be used for encryption.
//
// Spec: KMIP 1.4 §4.5, §3.22.
func TestLifecycle_DeactivatedCannotEncrypt(t *testing.T) {
    client := newClient(t, kmip.V1_4)
    id := createAES256(t, client, "deactivated-no-encrypt")
    activateKey(t, client, id)

    // Revoke the key → transitions to Deactivated
    _, err := client.Revoke(id).
        WithRevocationReasonCode(kmip.RevocationReasonCodeCessationOfOperation).
        ExecContext(tctx(t))
    require.NoError(t, err, "Revoke must succeed")

    // Verify the key is Deactivated
    stateVal := singleAttributeValue(t, client, id, kmip.AttributeNameState)
    assert.Equal(t, fmt.Sprint(kmip.StateDeactivated), fmt.Sprint(stateVal),
        "Key must be in Deactivated state after Revoke")

    // Attempt to encrypt — must fail
    _, err = client.Encrypt(id).
        WithCryptographicParameters(kmip.AES_GCM).
        Data([]byte("test data")).
        ExecContext(tctx(t))
    assert.Errorf(t, err,
        "Encrypt MUST fail on a Deactivated key (KMIP 1.4 §4.5)")
}

// TestLifecycle_DestroyedCannotBeRetrieved verifies that a Destroyed key
// cannot be retrieved via Get.
//
// Spec: KMIP 1.4 §4.6, §3.22.
func TestLifecycle_DestroyedCannotBeRetrieved(t *testing.T) {
    client := newClient(t, kmip.V1_4)

    // Create a fresh key (not using createAES256 which auto-cleans up)
    resp, err := client.Create().
        AES(256, kmip.CryptographicUsageEncrypt|kmip.CryptographicUsageDecrypt).
        WithName("destroyed-get").
        ExecContext(tctx(t))
    require.NoError(t, err, "Create must succeed")
    id := resp.UniqueIdentifier

    // Destroy immediately (PreActive keys can be destroyed without Revoke)
    _, err = client.Destroy(id).ExecContext(tctx(t))
    require.NoError(t, err, "Destroy must succeed")

    // Attempt to Get the destroyed key — must fail
    _, err = client.Get(id).ExecContext(tctx(t))
    assert.Errorf(t, err,
        "Get MUST fail on a Destroyed key (KMIP 1.4 §4.6)")
}

// ─── 2. Revocation reasons ───────────────────────────────────────────────────

// TestRevocation_Reasons verifies that different revocation reasons are accepted
// and correctly reflected in the key state.
//
// Spec: KMIP 1.4 §4.14.
func TestRevocation_Reasons(t *testing.T) {
    reasons := []struct {
        name   string
        reason kmip.RevocationReasonCode
    }{
        {"KeyCompromise", kmip.RevocationReasonCodeKeyCompromise},
        {"CACompromise", kmip.RevocationReasonCodeCACompromise},
        {"AffiliationChanged", kmip.RevocationReasonCodeAffiliationChanged},
        {"Superseded", kmip.RevocationReasonCodeSuperseded},
        {"CessationOfOperation", kmip.RevocationReasonCodeCessationOfOperation},
    }

    for _, tc := range reasons {
        tc := tc
        t.Run(tc.name, func(t *testing.T) {
            client := newClient(t, kmip.V1_4)
            id := createAES256(t, client, "revoke-"+tc.name)
            activateKey(t, client, id)

            _, err := client.Revoke(id).
                WithRevocationReasonCode(tc.reason).
                ExecContext(tctx(t))
            require.NoError(t, err, "Revoke(%s) must succeed", tc.name)

            // Verify state is Compromised for compromise reasons, Deactivated otherwise
            stateVal := singleAttributeValue(t, client, id, kmip.AttributeNameState)
            switch tc.reason {
            case kmip.RevocationReasonCodeKeyCompromise, kmip.RevocationReasonCodeCACompromise:
                assert.Equal(t, fmt.Sprint(kmip.StateCompromised), fmt.Sprint(stateVal),
                    "Revocation reason %s must set state to Compromised", tc.name)
            default:
                assert.Equal(t, fmt.Sprint(kmip.StateDeactivated), fmt.Sprint(stateVal),
                    "Revocation reason %s must set state to Deactivated", tc.name)
            }
        })
    }
}

// ─── 3. Destroy without Revoke (PreActive) ───────────────────────────────────

// TestLifecycle_DestroyPreActive verifies that a PreActive key can be destroyed
// directly without prior revocation.
//
// Spec: KMIP 1.4 §4.4.
func TestLifecycle_DestroyPreActive(t *testing.T) {
    client := newClient(t, kmip.V1_4)

    resp, err := client.Create().
        AES(256, kmip.CryptographicUsageEncrypt|kmip.CryptographicUsageDecrypt).
        WithName("destroy-preactive").
        ExecContext(tctx(t))
    require.NoError(t, err, "Create must succeed")
    id := resp.UniqueIdentifier

    // Destroy without Revoke — must succeed for PreActive keys
    _, err = client.Destroy(id).ExecContext(tctx(t))
    assert.NoError(t, err,
        "Destroy on a PreActive key must succeed without prior Revoke (KMIP 1.4 §4.4)")
}

// ─── 4. Full lifecycle: Create → Activate → Revoke → Destroy ─────────────────

// TestLifecycle_FullCycle verifies the complete key lifecycle:
// Create (PreActive) → Activate (Active) → Revoke (Deactivated) → Destroy.
//
// Spec: KMIP 1.4 §4.1, §4.14, §4.4.
func TestLifecycle_FullCycle(t *testing.T) {
    client := newClient(t, kmip.V1_4)

    // Create
    resp, err := client.Create().
        AES(256, kmip.CryptographicUsageEncrypt|kmip.CryptographicUsageDecrypt).
        WithName("full-lifecycle").
        ExecContext(tctx(t))
    require.NoError(t, err, "Create must succeed")
    id := resp.UniqueIdentifier

    // Verify PreActive
    assert.Equal(t, fmt.Sprint(kmip.StatePreActive),
        fmt.Sprint(singleAttributeValue(t, client, id, kmip.AttributeNameState)),
        "New key must be PreActive")

    // Activate
    _, err = client.Activate(id).ExecContext(tctx(t))
    require.NoError(t, err, "Activate must succeed")
    assert.Equal(t, fmt.Sprint(kmip.StateActive),
        fmt.Sprint(singleAttributeValue(t, client, id, kmip.AttributeNameState)),
        "Key must be Active after Activate")

    // Revoke
    _, err = client.Revoke(id).
        WithRevocationReasonCode(kmip.RevocationReasonCodeCessationOfOperation).
        ExecContext(tctx(t))
    require.NoError(t, err, "Revoke must succeed")
    assert.Equal(t, fmt.Sprint(kmip.StateDeactivated),
        fmt.Sprint(singleAttributeValue(t, client, id, kmip.AttributeNameState)),
        "Key must be Deactivated after Revoke")

    // Destroy
    _, err = client.Destroy(id).ExecContext(tctx(t))
    require.NoError(t, err, "Destroy must succeed")

    // Verify destroyed
    _, err = client.Get(id).ExecContext(tctx(t))
    assert.Errorf(t, err, "Get must fail after Destroy")
}
