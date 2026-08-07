package kmip_go_tests

// Locate operation tests with complex filters driven by ovh/kmip-go.
//
// These tests validate the Locate operation with various attribute filters,
// including multi-filter queries and edge cases.
//
// Spec references: OASIS KMIP 1.4 §4.9.

import (
	"testing"

	"github.com/ovh/kmip-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ─── 1. Locate by ObjectType ─────────────────────────────────────────────────

// TestLocate_ByObjectType verifies that Locate can filter by ObjectType and
// returns only matching objects.
//
// Spec: KMIP 1.4 §4.9.
func TestLocate_ByObjectType(t *testing.T) {
	client := newClient(t, kmip.V1_4)
	id := createAES256(t, client, "locate-objtype")
	activateKey(t, client, id)

	resp, err := client.Locate().
		WithAttribute(kmip.AttributeNameObjectType, kmip.ObjectTypeSymmetricKey).
		ExecContext(tctx(t))
	require.NoError(t, err, "Locate by ObjectType must succeed")
	assert.Contains(t, resp.UniqueIdentifier, id,
		"Locate(ObjectType=SymmetricKey) must return the AES key just created")
}

// ─── 2. Locate by State ──────────────────────────────────────────────────────

// TestLocate_ByState verifies that Locate can filter by key State.
//
// Spec: KMIP 1.4 §4.9.
func TestLocate_ByState(t *testing.T) {
	client := newClient(t, kmip.V1_4)
	id := createAES256(t, client, "locate-state")
	activateKey(t, client, id)

	resp, err := client.Locate().
		WithAttribute(kmip.AttributeNameState, kmip.StateActive).
		WithAttribute(kmip.AttributeNameObjectType, kmip.ObjectTypeSymmetricKey).
		ExecContext(tctx(t))
	require.NoError(t, err, "Locate by State must succeed")
	assert.Contains(t, resp.UniqueIdentifier, id,
		"Locate(State=Active) must return the activated key")
}

// ─── 3. Locate with multiple filters ─────────────────────────────────────────

// TestLocate_MultipleFilters verifies that Locate with multiple attribute
// filters returns only keys matching ALL filters (AND semantics).
//
// Spec: KMIP 1.4 §4.9.
func TestLocate_MultipleFilters(t *testing.T) {
	client := newClient(t, kmip.V1_4)

	// Create two keys with different object groups
	createResp1, err := client.Create().
		AES(256, kmip.CryptographicUsageEncrypt|kmip.CryptographicUsageDecrypt).
		WithName("locate-multi-1").
		WithAttribute(kmip.AttributeNameObjectGroup, "multi-filter-group").
		ExecContext(tctx(t))
	require.NoError(t, err)
	id1 := createResp1.UniqueIdentifier
	activateKey(t, client, id1)
	t.Cleanup(func() { cleanupKey(t, client, id1) })

	createResp2, err := client.Create().
		AES(256, kmip.CryptographicUsageEncrypt|kmip.CryptographicUsageDecrypt).
		WithName("locate-multi-2").
		WithAttribute(kmip.AttributeNameObjectGroup, "other-group").
		ExecContext(tctx(t))
	require.NoError(t, err)
	id2 := createResp2.UniqueIdentifier
	activateKey(t, client, id2)
	t.Cleanup(func() { cleanupKey(t, client, id2) })

	// Locate with ObjectGroup + CryptographicAlgorithm
	resp, err := client.Locate().
		WithAttribute(kmip.AttributeNameObjectGroup, "multi-filter-group").
		WithAttribute(kmip.AttributeNameCryptographicAlgorithm, kmip.CryptographicAlgorithmAES).
		ExecContext(tctx(t))
	require.NoError(t, err, "Locate with multiple filters must succeed")

	assert.Contains(t, resp.UniqueIdentifier, id1,
		"Locate must return key with matching ObjectGroup + Algorithm")
	assert.NotContains(t, resp.UniqueIdentifier, id2,
		"Locate must NOT return key with different ObjectGroup")
}

// ─── 4. Locate returns empty when no match ───────────────────────────────────

// TestLocate_NoMatch verifies that Locate returns an empty result set when
// no keys match the filter criteria.
//
// Spec: KMIP 1.4 §4.9.
func TestLocate_NoMatch(t *testing.T) {
	client := newClient(t, kmip.V1_4)

	resp, err := client.Locate().
		WithAttribute(kmip.AttributeNameObjectGroup, "nonexistent-group-xyz-12345").
		ExecContext(tctx(t))
	require.NoError(t, err, "Locate with no match must not error")
	assert.Empty(t, resp.UniqueIdentifier,
		"Locate must return empty result when no keys match")
}

// ─── 5. Locate by Name ───────────────────────────────────────────────────────

// TestLocate_ByName verifies that Locate can filter by key Name.
//
// Spec: KMIP 1.4 §4.9.
func TestLocate_ByName(t *testing.T) {
	client := newClient(t, kmip.V1_4)

	uniqueName := sanitiseName("locate-by-name-unique-" + t.Name())
	resp, err := client.Create().
		AES(256, kmip.CryptographicUsageEncrypt|kmip.CryptographicUsageDecrypt).
		WithName(uniqueName).
		ExecContext(tctx(t))
	require.NoError(t, err)
	id := resp.UniqueIdentifier
	activateKey(t, client, id)
	t.Cleanup(func() { cleanupKey(t, client, id) })

	locateResp, err := client.Locate().
		WithAttribute(kmip.AttributeNameName, kmip.Name{
			NameValue: uniqueName,
			NameType:  kmip.NameTypeUninterpretedTextString,
		}).
		ExecContext(tctx(t))
	require.NoError(t, err, "Locate by Name must succeed")
	assert.Contains(t, locateResp.UniqueIdentifier, id,
		"Locate(Name) must return the key with the matching name")
}

// ─── 6. Locate by UniqueIdentifier ───────────────────────────────────────────

// TestLocate_ByUniqueIdentifier verifies that Locate can filter by
// UniqueIdentifier (effectively a point lookup).
//
// Spec: KMIP 1.4 §4.9.
func TestLocate_ByUniqueIdentifier(t *testing.T) {
	client := newClient(t, kmip.V1_4)
	id := createAES256(t, client, "locate-uid")
	activateKey(t, client, id)

	resp, err := client.Locate().
		WithAttribute(kmip.AttributeNameUniqueIdentifier, id).
		ExecContext(tctx(t))
	require.NoError(t, err, "Locate by UniqueIdentifier must succeed")
	assert.Contains(t, resp.UniqueIdentifier, id,
		"Locate(UniqueIdentifier) must return the specified key")
}
