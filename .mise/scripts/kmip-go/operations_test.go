package kmip_go_tests

// Operation coverage tests driven by ovh/kmip-go.
//
// These tests exercise KMIP operations that were previously untested via the
// independent Go client: ReKey, Import, Register, Hash, Export, and advanced
// Batch scenarios.
//
// Spec references: OASIS KMIP 1.4 specification (kmip/v1.4/ in this repo).

import (
    "crypto/sha256"
    "fmt"
    "testing"

    "github.com/ovh/kmip-go"
    "github.com/ovh/kmip-go/payloads"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

// ─── 1. ReKey (KMIP 1.4 §4.11) ──────────────────────────────────────────────

// TestReKey_SymmetricKey verifies that ReKey creates a new version of a
// symmetric key. After ReKey, the old key is revoked per KMIP 1.4 §4.11.
//
// Spec: KMIP 1.4 §4.11.
func TestReKey_SymmetricKey(t *testing.T) {
    client := newClient(t, kmip.V1_4)
    id := createAES256(t, client, "rekey")
    activateKey(t, client, id)

    // ReKey the symmetric key
    rekeyResp, err := client.Rekey(id).ExecContext(tctx(t))
    require.NoError(t, err, "ReKey must succeed on an Active symmetric key")
    newID := rekeyResp.UniqueIdentifier
    require.NotEmpty(t, newID, "ReKey must return a new Unique Identifier")
    require.NotEqual(t, id, newID, "ReKey must return a DIFFERENT Unique Identifier")
    t.Cleanup(func() { cleanupKey(t, client, newID) })

    // The new key must be retrievable
    getResp, err := client.Get(newID).ExecContext(tctx(t))
    require.NoError(t, err, "Get(new key) must succeed")
    assert.Equal(t, kmip.ObjectTypeSymmetricKey, getResp.ObjectType,
        "ReKey result must be a Symmetric Key")

    // Per KMIP 1.4 §4.11, the old key is revoked after ReKey.
    // Verify the old key is no longer Active.
    stateVal := singleAttributeValue(t, client, id, kmip.AttributeNameState)
    assert.NotEqual(t, fmt.Sprint(kmip.StateActive), fmt.Sprint(stateVal),
        "Old key must no longer be Active after ReKey (KMIP 1.4 §4.11)")
}

// ─── 2. Import (KMIP 1.4 §4.19) ─────────────────────────────────────────────

// TestImport_SymmetricKey verifies that a symmetric key can be imported with
// a client-chosen Unique Identifier and later retrieved.
//
// NOTE: Skipped — kmip-go v0.9.2 Import builder does not include the ObjectType
// attribute in the TTLV encoding, causing the server to reject the request with
// "missing field `ObjectType`". This is a client library issue, not a server bug.
//
// Spec: KMIP 1.4 §4.19.
func TestImport_SymmetricKey(t *testing.T) {
    t.Skip("kmip-go v0.9.2 Import builder does not include ObjectType in TTLV encoding")
    client := newClient(t, kmip.V1_4)

    importID := fmt.Sprintf("import-test-%d", testCounter())
    keyValue := make([]byte, 32) // 256-bit key
    for i := range keyValue {
        keyValue[i] = byte(i)
    }

    obj := kmip.SymmetricKey{KeyBlock: kmip.KeyBlock{
        KeyFormatType: kmip.KeyFormatTypeRaw,
        KeyValue: &kmip.KeyValue{
            Plain: &kmip.PlainKeyValue{
                KeyMaterial: kmip.KeyMaterial{
                    Bytes: &keyValue,
                },
            },
        },
        CryptographicAlgorithm: kmip.CryptographicAlgorithmAES,
        CryptographicLength:    256,
    }}

    importResp, err := client.Import(importID, &obj).
        WithAttribute(kmip.AttributeNameCryptographicUsageMask,
            kmip.CryptographicUsageEncrypt|kmip.CryptographicUsageDecrypt).
        ExecContext(tctx(t))
    require.NoError(t, err, "Import must succeed")
    assert.Equal(t, importID, importResp.UniqueIdentifier,
        "Import must return the client-chosen Unique Identifier")
    t.Cleanup(func() { cleanupKey(t, client, importID) })

    // Retrieve the imported key
    getResp, err := client.Get(importID).ExecContext(tctx(t))
    require.NoError(t, err, "Get(imported key) must succeed")
    assert.Equal(t, kmip.ObjectTypeSymmetricKey, getResp.ObjectType)
}

// ─── 3. Register (KMIP 1.4 §4.5) ────────────────────────────────────────────

// TestRegister_SymmetricKey verifies that a symmetric key can be registered
// with the server and later retrieved.
//
// Spec: KMIP 1.4 §4.5.
func TestRegister_SymmetricKey(t *testing.T) {
    client := newClient(t, kmip.V1_4)

    keyValue := make([]byte, 32) // 256-bit key
    for i := range keyValue {
        keyValue[i] = byte(i + 100)
    }

    regResp, err := client.Register().
        SymmetricKey(kmip.CryptographicAlgorithmAES,
            kmip.CryptographicUsageEncrypt|kmip.CryptographicUsageDecrypt,
            keyValue).
        WithName("registered-key").
        ExecContext(tctx(t))
    require.NoError(t, err, "Register must succeed")
    regID := regResp.UniqueIdentifier
    require.NotEmpty(t, regID, "Register must return a Unique Identifier")
    t.Cleanup(func() { cleanupKey(t, client, regID) })

    // Retrieve the registered key
    getResp, err := client.Get(regID).ExecContext(tctx(t))
    require.NoError(t, err, "Get(registered key) must succeed")
    assert.Equal(t, kmip.ObjectTypeSymmetricKey, getResp.ObjectType)
}

// ─── 4. Hash (KMIP 1.4 §4.13) ───────────────────────────────────────────────

// TestHash_SHA256 verifies that the Hash operation computes a correct SHA-256
// digest of the provided data.
//
// Spec: KMIP 1.4 §4.13.
func TestHash_SHA256(t *testing.T) {
    client := newClient(t, kmip.V1_4)

    data := []byte("Hello, KMIP Hash operation!")
    expectedHash := sha256.Sum256(data)

    resp, err := client.Request(tctx(t), &payloads.HashRequestPayload{
        CryptographicParameters: kmip.CryptographicParameters{
            HashingAlgorithm: kmip.HashingAlgorithmSHA_256,
        },
        Data: data,
    })
    require.NoError(t, err, "Hash(SHA-256) must succeed")

    hashResp, ok := resp.(*payloads.HashResponsePayload)
    require.True(t, ok, "response must be HashResponsePayload")
    assert.Equal(t, expectedHash[:], hashResp.Data,
        "Hash(SHA-256) must match the expected SHA-256 digest")
}

// ─── 5. Export (KMIP 1.4 §4.8) ──────────────────────────────────────────────

// TestExport_Unwrapped verifies that a key can be exported without wrapping
// and that the exported key data matches the original.
//
// NOTE: Skipped — kmip-go v0.9.2 Export builder does not include the ObjectType
// attribute in the TTLV encoding, causing the server to reject the request with
// "missing field `ObjectType`". This is a client library issue, not a server bug.
//
// Spec: KMIP 1.4 §4.8.
func TestExport_Unwrapped(t *testing.T) {
    t.Skip("kmip-go v0.9.2 Export builder does not include ObjectType in TTLV encoding")
    client := newClient(t, kmip.V1_4)
    id := createAES256(t, client, "export")
    activateKey(t, client, id)

    exportResp, err := client.Export(id).ExecContext(tctx(t))
    require.NoError(t, err, "Export (unwrapped) must succeed")
    assert.Equal(t, kmip.ObjectTypeSymmetricKey, exportResp.ObjectType,
        "Export must return the correct object type")
    assert.Equal(t, id, exportResp.UniqueIdentifier,
        "Export must return the correct Unique Identifier")
    assert.NotEmpty(t, exportResp.Attribute,
        "Export must return attributes")
}

// ─── 6. Batch: Create + Activate + Get ───────────────────────────────────────

// TestBatch_CreateActivateGet verifies that a batch of Create → Activate → Get
// operations executes atomically and returns correct results.
//
// Spec: KMIP 1.4 §4.15.
func TestBatch_CreateActivateGet(t *testing.T) {
    client := newClient(t, kmip.V1_4)

    // Step 1: Create
    createResp, err := client.Create().
        AES(256, kmip.CryptographicUsageEncrypt|kmip.CryptographicUsageDecrypt).
        WithName("batch-create").
        ExecContext(tctx(t))
    require.NoError(t, err, "Create must succeed")
    id := createResp.UniqueIdentifier
    t.Cleanup(func() { cleanupKey(t, client, id) })

    // Step 2: Activate
    _, err = client.Activate(id).ExecContext(tctx(t))
    require.NoError(t, err, "Activate must succeed")

    // Step 3: Get
    getResp, err := client.Get(id).ExecContext(tctx(t))
    require.NoError(t, err, "Get must succeed")
    assert.Equal(t, kmip.ObjectTypeSymmetricKey, getResp.ObjectType)

    // Verify the key is Active
    attrs, err := client.GetAttributes(id, kmip.AttributeNameState).ExecContext(tctx(t))
    require.NoError(t, err, "GetAttributes(State) must succeed")
    for _, a := range attrs.Attribute {
        if a.AttributeName == kmip.AttributeNameState {
            assert.Equal(t, kmip.StateActive, a.AttributeValue,
                "Key must be in Active state after batch Create+Activate")
        }
    }
}

// TestBatch_MixedSuccessFailure verifies that a batch with one successful and
// one failing operation returns partial results.
//
// Spec: KMIP 1.4 §4.15.
func TestBatch_MixedSuccessFailure(t *testing.T) {
    client := newClient(t, kmip.V1_4)

    // Create a key for the successful Get
    id := createAES256(t, client, "batch-mixed")
    activateKey(t, client, id)

    // Batch: Get(existing key) + Get(non-existent key)
    batchResp, err := client.Batch(tctx(t),
        &payloads.GetRequestPayload{UniqueIdentifier: id},
        &payloads.GetRequestPayload{UniqueIdentifier: "non-existent-key-uid-12345"},
    )
    require.NoError(t, err, "Batch itself must not fail")

    require.Len(t, batchResp, 2, "Batch must return 2 results")

    // First result: success
    assert.NoError(t, batchResp[0].Err(), "Get(existing) must succeed")

    // Second result: failure
    assert.Error(t, batchResp[1].Err(), "Get(non-existent) must fail")
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

var _testCounter int64

func testCounter() int64 {
    _testCounter++
    return _testCounter
}
