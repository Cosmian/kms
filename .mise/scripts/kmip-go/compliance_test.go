package kmip_go_tests

import (
    "fmt"
    "testing"
    "time"

    "github.com/ovh/kmip-go"
    "github.com/ovh/kmip-go/payloads"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

// ─── DiscoverVersions ─────────────────────────────────────────────────────────

// TestDiscoverVersions verifies that the server advertises at least KMIP 1.0–1.4.
func TestDiscoverVersions(t *testing.T) {
    client := newClient(t, kmip.V1_4)

    // DiscoverVersions uses the low-level Request API.
    resp, err := client.Request(tctx(t), &payloads.DiscoverVersionsRequestPayload{})
    require.NoError(t, err, "DiscoverVersions")

    dvResp, ok := resp.(*payloads.DiscoverVersionsResponsePayload)
    require.True(t, ok, "expected DiscoverVersionsResponsePayload, got %T", resp)

    reported := make(map[string]bool)
    for _, v := range dvResp.ProtocolVersion {
        key := fmt.Sprintf("%d.%d", v.ProtocolVersionMajor, v.ProtocolVersionMinor)
        reported[key] = true
        t.Logf("server advertises KMIP %s", key)
    }
    for _, want := range []string{"1.0", "1.1", "1.2", "1.3", "1.4"} {
        assert.True(t, reported[want], "server should advertise KMIP %s", want)
    }
}

// ─── Query ────────────────────────────────────────────────────────────────────

// TestQuery_V14 verifies the server's Query response includes required operations.
func TestQuery_V14(t *testing.T) {
    client := newClient(t, kmip.V1_4)

    resp, err := client.Query().Operations().ExecContext(tctx(t))
    require.NoError(t, err)

    ops := make(map[kmip.Operation]bool)
    for _, op := range resp.Operations {
        ops[op] = true
    }
    t.Logf("server supports %d operations", len(ops))

    for _, required := range []kmip.Operation{
        kmip.OperationCreate,
        kmip.OperationGet,
        kmip.OperationDestroy,
        kmip.OperationActivate,
        kmip.OperationRevoke,
        kmip.OperationLocate,
        kmip.OperationGetAttributes,
    } {
        assert.True(t, ops[required], "Query should report %v as supported", required)
    }
}

// ─── AES-256 full lifecycle (all KMIP versions) ───────────────────────────────

// TestAES256Lifecycle runs create → activate → get → getAttributeList →
// getAttributes → locate → (cleanup revokes+destroys) for each KMIP 1.0–1.4.
func TestAES256Lifecycle(t *testing.T) {
    for _, ver := range allVersions {
        ver := ver
        t.Run(fmt.Sprintf("V%s", versionName(ver)), func(t *testing.T) {
            t.Parallel()
            client := newClient(t, ver)

            id := createAES256(t, client, "lifecycle")
            activateKey(t, client, id)

            // Get — must succeed and return SymmetricKey
            getResp, err := client.Get(id).ExecContext(tctx(t))
            require.NoError(t, err, "Get")
            assert.Equal(t, kmip.ObjectTypeSymmetricKey, getResp.ObjectType)

            // GetAttributeList — must include standard attributes
            names := getAttrList(t, client, id)
            t.Logf("KMIP %s: GetAttributeList → %v", versionName(ver), names)
            assert.True(t, hasAttr(names, "Unique Identifier"), "must include Unique Identifier")
            assert.True(t, hasAttr(names, "State"), "must include State")
            assert.True(t, hasAttr(names, "Cryptographic Algorithm"), "must include Cryptographic Algorithm")

            // GetAttributes — State should be returned
            attrResp, err := client.GetAttributes(id, kmip.AttributeNameState).ExecContext(tctx(t))
            require.NoError(t, err, "GetAttributes")
            hasState := false
            for _, a := range attrResp.Attribute {
                if a.AttributeName == kmip.AttributeNameState {
                    hasState = true
                    t.Logf("KMIP %s: State = %v", versionName(ver), a.AttributeValue)
                }
            }
            assert.True(t, hasState, "GetAttributes should return State")

            // Locate by UniqueIdentifier
            locResp, err := client.Locate().
                WithAttribute(kmip.AttributeNameUniqueIdentifier, id).
                ExecContext(tctx(t))
            require.NoError(t, err, "Locate")
            found := false
            for _, uid := range locResp.UniqueIdentifier {
                if uid == id {
                    found = true
                    break
                }
            }
            assert.True(t, found, "Locate should find the key by UniqueIdentifier")
            // Revoke + Destroy via t.Cleanup registered in createAES256
        })
    }
}

// ─── RSA-2048 key pair lifecycle ──────────────────────────────────────────────

// TestRSA2048KeyPairLifecycle_V14 creates an RSA-2048 key pair at KMIP 1.4.
func TestRSA2048KeyPairLifecycle_V14(t *testing.T) {
    client := newClient(t, kmip.V1_4)

    resp, err := client.CreateKeyPair().
        RSA(2048, kmip.CryptographicUsageSign, kmip.CryptographicUsageVerify).
        WithName("kmip-go-rsa2048").
        ExecContext(tctx(t))
    require.NoError(t, err, "CreateKeyPair RSA-2048")

    privID := resp.PrivateKeyUniqueIdentifier
    pubID := resp.PublicKeyUniqueIdentifier
    require.NotEmpty(t, privID)
    require.NotEmpty(t, pubID)
    t.Logf("RSA-2048: private=%s public=%s", privID, pubID)

    t.Cleanup(func() {
        cleanupKey(t, client, privID)
        cleanupKey(t, client, pubID)
    })

    for _, tc := range []struct {
        id   string
        want kmip.ObjectType
    }{{privID, kmip.ObjectTypePrivateKey}, {pubID, kmip.ObjectTypePublicKey}} {
        g, err := client.Get(tc.id).ExecContext(tctx(t))
        require.NoError(t, err, "Get %s", tc.id)
        assert.Equal(t, tc.want, g.ObjectType)
    }
}

// ─── Locate by Name ───────────────────────────────────────────────────────────

// TestLocateByName_V14 verifies that Locate can find a key by its Name attribute.
func TestLocateByName_V14(t *testing.T) {
    client := newClient(t, kmip.V1_4)

    uniqueName := fmt.Sprintf("kmip-go-locate-%d", time.Now().UnixNano())
    resp, err := client.Create().
        AES(256, kmip.CryptographicUsageEncrypt|kmip.CryptographicUsageDecrypt).
        WithName(uniqueName).
        ExecContext(tctx(t))
    require.NoError(t, err)
    id := resp.UniqueIdentifier
    t.Cleanup(func() { cleanupKey(t, client, id) })
    activateKey(t, client, id)

    locResp, err := client.Locate().WithName(uniqueName).ExecContext(tctx(t))
    require.NoError(t, err, "Locate by Name")

    found := false
    for _, uid := range locResp.UniqueIdentifier {
        if uid == id {
            found = true
            break
        }
    }
    assert.True(t, found, "Locate by Name=%q should find key %s", uniqueName, id)
}

// ─── Batch operations ─────────────────────────────────────────────────────────

// TestBatch_CreateActivateRevoke_V14 exercises the batch request API by sending
// GetAttributes + Locate in one KMIP message for a pre-created key.
func TestBatch_CreateActivateRevoke_V14(t *testing.T) {
    client := newClient(t, kmip.V1_4)

    name := fmt.Sprintf("kmip-go-batch-%d", time.Now().UnixNano())
    createResp, err := client.Create().
        AES(256, kmip.CryptographicUsageEncrypt|kmip.CryptographicUsageDecrypt).
        WithName(name).
        ExecContext(tctx(t))
    require.NoError(t, err)
    id := createResp.UniqueIdentifier
    t.Cleanup(func() { cleanupKey(t, client, id) })
    activateKey(t, client, id)

    // Use the low-level Batch API: send GetAttributes + Locate in one round-trip.
    getAttrsPl, err := client.GetAttributes(id, kmip.AttributeNameState).Build()
    require.NoError(t, err)
    locatePl, err := client.Locate().WithName(name).Build()
    require.NoError(t, err)

    batchResult, err := client.Batch(tctx(t), getAttrsPl, locatePl)
    require.NoError(t, err, "batch request")

    pls, err := batchResult.Unwrap()
    require.NoError(t, err, "batch result unwrap")
    require.Len(t, pls, 2, "expected 2 batch items")

    gaResp, ok := pls[0].(*payloads.GetAttributesResponsePayload)
    require.True(t, ok, "item[0] should be GetAttributesResponsePayload, got %T", pls[0])
    hasState := false
    for _, a := range gaResp.Attribute {
        if a.AttributeName == kmip.AttributeNameState {
            hasState = true
            t.Logf("batch: State = %v", a.AttributeValue)
        }
    }
    assert.True(t, hasState, "batch GetAttributes should include State")

    locResp, ok := pls[1].(*payloads.LocateResponsePayload)
    require.True(t, ok, "item[1] should be LocateResponsePayload, got %T", pls[1])
    found := false
    for _, uid := range locResp.UniqueIdentifier {
        if uid == id {
            found = true
        }
    }
    assert.True(t, found, "batch Locate should find the key by name")
}
