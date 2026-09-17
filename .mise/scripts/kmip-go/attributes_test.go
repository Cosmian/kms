package kmip_go_tests

// Attribute-focused compliance tests driven by ovh/kmip-go.
//
// The Go client decodes every attribute into a strongly typed Go value using the
// TTLV type mandated by the KMIP specification. That makes it a far stricter
// oracle than the repository's own XML profile vectors, which compare *decoded
// Rust structs* and are therefore blind to wire-type errors (an `Integer` that
// should have been an `Interval` deserialises into the same `i32`).
//
// Three families of checks live here:
//
//  1. Decodability — every attribute the server may return must decode cleanly
//     with the spec-mandated TTLV type (catches wire-type regressions).
//  2. Mutability   — the KMIP "Attribute Rules" tables (KMIP 1.4 §3.x, KMIP 2.1
//     §4.x) state, for each attribute, whether a client may modify or delete it.
//     Read-only attributes must be rejected, and must not be silently altered.
//  3. Round-trip   — client-modifiable attributes must survive
//     Add → Get → Modify → Get → Delete → Get.
//
// Spec references are the OASIS KMIP specification HTML files under kmip/ in
// this repository.

import (
    "fmt"
    "strings"
    "testing"
    "time"

    "github.com/ovh/kmip-go"
    "github.com/ovh/kmip-go/kmipclient"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

// ─── 1. Decodability of every attribute ──────────────────────────────────────

// TestAllAttributes_DecodeWithoutError requests every attribute known to
// ovh/kmip-go, one at a time, and asserts the response decodes.
//
// A decode failure means the server emitted a TTLV type that contradicts the
// specification — for example `Lease Time` as `Integer` when KMIP 1.4 §3.20
// Table 99 mandates `Interval`, or `RNG Parameters.Cryptographic Length` as
// `LongInteger` when KMIP 1.4 Table 39 mandates `Integer`.
//
// A fresh connection is used per attribute: a TTLV decode error leaves unread
// bytes in the stream, so reusing the connection would desynchronise framing
// and turn one real failure into a cascade of phantom ones.
func TestAllAttributes_DecodeWithoutError(t *testing.T) {
    setup := newClient(t, kmip.V1_4)
    id := createAES256(t, setup, "decode-all")
    activateKey(t, setup, id)

    for _, attrName := range kmip.AllAttributeNames {
        attrName := attrName
        t.Run(subtestName(string(attrName)), func(t *testing.T) {
            client := newClient(t, kmip.V1_4)
            resp, err := client.GetAttributes(id, attrName).ExecContext(tctx(t))
            require.NoErrorf(t, err,
                "GetAttributes(%q) must decode with the TTLV type mandated by the KMIP "+
                    "specification; a type mismatch here is a server wire-format bug",
                attrName)
            for _, a := range resp.Attribute {
                t.Logf("%s = %v", a.AttributeName, a.AttributeValue)
            }
        })
    }
}

// TestAllAttributes_DecodeWithoutError_AllVersions repeats the decodability
// sweep across every KMIP version, using only the attributes that exist in each
// version. A wire-type bug may be introduced by a version-specific conversion
// path, so per-version coverage matters.
func TestAllAttributes_DecodeWithoutError_AllVersions(t *testing.T) {
    for _, ver := range allVersions {
        ver := ver
        t.Run("V"+versionName(ver), func(t *testing.T) {
            setup := newClient(t, ver)
            id := createAES256(t, setup, "decode-ver")
            activateKey(t, setup, id)

            for _, attrName := range kmip.AllAttributeNames {
                if attributeMinorVersion(attrName) > ver.ProtocolVersionMinor {
                    continue // not defined in this version — server must not return it
                }
                client := newClient(t, ver)
                _, err := client.GetAttributes(id, attrName).ExecContext(tctx(t))
                assert.NoErrorf(t, err,
                    "KMIP %s: GetAttributes(%q) must decode cleanly",
                    versionName(ver), attrName)
            }
        })
    }
}

// ─── 2. Wire-type assertions for structurally typed attributes ───────────────

// TestLeaseTime_IsInterval asserts that `Lease Time` is encoded as a TTLV
// Interval (0x0A), not an Integer (0x02).
//
// Spec: KMIP 1.4 §3.20 Table 99 "Lease Time | Interval";
// KMIP 2.1 §4.29 Table 88 states the same.
//
// The Go client models Lease Time as time.Duration and decodes strictly, so a
// wrong wire type surfaces as "Got Integer but expected Interval".
func TestLeaseTime_IsInterval(t *testing.T) {
    for _, ver := range allVersions {
        ver := ver
        t.Run("V"+versionName(ver), func(t *testing.T) {
            client := newClient(t, ver)
            id := createAES256(t, client, "lease")
            activateKey(t, client, id)

            probe := newClient(t, ver)
            resp, err := probe.GetAttributes(id, kmip.AttributeNameLeaseTime).ExecContext(tctx(t))
            require.NoErrorf(t, err,
                "KMIP %s: 'Lease Time' must be encoded as TTLV Interval "+
                    "(KMIP 1.4 §3.20 Table 99), not Integer",
                versionName(ver))

            for _, a := range resp.Attribute {
                d, ok := a.AttributeValue.(time.Duration)
                require.Truef(t, ok, "Lease Time must decode to time.Duration, got %T", a.AttributeValue)
                assert.Positive(t, d, "Lease Time should be a positive interval")
                t.Logf("KMIP %s Lease Time = %s", versionName(ver), d)
            }
        })
    }
}

// TestRandomNumberGenerator_CryptographicLengthIsInteger asserts that the
// `Cryptographic Length` field *inside* the RNG Parameters structure is encoded
// as a TTLV Integer (0x02), not a LongInteger (0x03).
//
// Spec: KMIP 1.4 Table 39 "RNG Parameters Structure — Cryptographic Length |
// Integer"; KMIP 2.1 Table 388 states the same.
//
// Note this is a *different* field from the top-level `Cryptographic Length`
// attribute (KMIP 1.4 §3.5), which is correctly an Integer. Only the nested one
// is affected, which is exactly the kind of asymmetry a typed client catches.
func TestRandomNumberGenerator_CryptographicLengthIsInteger(t *testing.T) {
    // Random Number Generator was introduced in KMIP 1.3 (§3.44).
    for _, ver := range []kmip.ProtocolVersion{kmip.V1_3, kmip.V1_4} {
        ver := ver
        t.Run("V"+versionName(ver), func(t *testing.T) {
            client := newClient(t, ver)
            id := createAES256(t, client, "rng")
            activateKey(t, client, id)

            probe := newClient(t, ver)
            resp, err := probe.GetAttributes(id, kmip.AttributeNameRandomNumberGenerator).
                ExecContext(tctx(t))
            require.NoErrorf(t, err,
                "KMIP %s: RNG Parameters.CryptographicLength must be TTLV Integer "+
                    "(KMIP 1.4 Table 39), not LongInteger",
                versionName(ver))

            for _, a := range resp.Attribute {
                rng, ok := a.AttributeValue.(kmip.RNGParameters)
                require.Truef(t, ok, "expected kmip.RNGParameters, got %T", a.AttributeValue)
                t.Logf("KMIP %s RNG = alg=%v len=%v", versionName(ver),
                    rng.RNGAlgorithm, rng.CryptographicLength)
            }
        })
    }
}

// ─── 3. Read-only enforcement ────────────────────────────────────────────────

// readOnlyAttr describes an attribute the KMIP "Attribute Rules" table marks as
// not modifiable by a client, together with a value used to attempt tampering.
type readOnlyAttr struct {
    name    kmip.AttributeName
    specRef string
    value   any
}

// readOnlyAttrs lists attributes whose rules table says
// "Modifiable by client: No". A conformant server MUST reject AddAttribute,
// ModifyAttribute and DeleteAttribute on each of them.
var readOnlyAttrs = []readOnlyAttr{
    {kmip.AttributeNameUniqueIdentifier, "KMIP 1.4 §3.1", "hijacked-unique-identifier"},
    {kmip.AttributeNameObjectType, "KMIP 1.4 §3.3", kmip.ObjectTypePrivateKey},
    {kmip.AttributeNameCryptographicLength, "KMIP 1.4 §3.5", int32(64)},
    {kmip.AttributeNameState, "KMIP 1.4 §3.22", kmip.StateCompromised},
    {kmip.AttributeNameInitialDate, "KMIP 1.4 §3.23", time.Date(1999, 1, 1, 0, 0, 0, 0, time.UTC)},
    {kmip.AttributeNameLastChangeDate, "KMIP 1.4 §3.38", time.Date(1999, 1, 1, 0, 0, 0, 0, time.UTC)},
    {kmip.AttributeNameOriginalCreationDate, "KMIP 1.4 §3.43", time.Date(1999, 1, 1, 0, 0, 0, 0, time.UTC)},
    {kmip.AttributeNameAlwaysSensitive, "KMIP 1.4 §3.49", true},
    {kmip.AttributeNameNeverExtractable, "KMIP 1.4 §3.51", true},
    {kmip.AttributeNameFresh, "KMIP 1.4 §3.34", false},
    {kmip.AttributeNameDigest, "KMIP 1.4 §3.17", kmip.Digest{}},
}

// TestReadOnlyAttributes_ModifyRejected asserts the server refuses
// ModifyAttribute on every attribute the spec marks read-only for clients.
//
// Accepting such a request lets a client rewrite server-managed provenance —
// e.g. back-dating `Initial Date` to defeat an audit trail, or lowering
// `Cryptographic Length` so the metadata understates the real key strength.
func TestReadOnlyAttributes_ModifyRejected(t *testing.T) {
    for _, ro := range readOnlyAttrs {
        ro := ro
        t.Run(subtestName(string(ro.name)), func(t *testing.T) {
            client := newClient(t, kmip.V1_4)
            id := createAES256(t, client, "ro-modify")
            activateKey(t, client, id)

            _, err := client.ModifyAttribute(id, ro.name, ro.value).ExecContext(tctx(t))
            assert.Errorf(t, err,
                "ModifyAttribute(%q) MUST be rejected: %s marks it "+
                    "'Modifiable by client: No'", ro.name, ro.specRef)
        })
    }
}

// TestReadOnlyAttributes_NotTampered is the defence-in-depth counterpart of the
// test above: even if the server answers Success, the stored value MUST NOT
// change. This catches a server that acknowledges the request but is expected
// to ignore it, and — more importantly — one that actually applies it.
func TestReadOnlyAttributes_NotTampered(t *testing.T) {
    tamperable := []readOnlyAttr{
        {kmip.AttributeNameInitialDate, "KMIP 1.4 §3.23", time.Date(1999, 1, 1, 0, 0, 0, 0, time.UTC)},
        {kmip.AttributeNameCryptographicLength, "KMIP 1.4 §3.5", int32(64)},
        {kmip.AttributeNameOriginalCreationDate, "KMIP 1.4 §3.43", time.Date(1999, 1, 1, 0, 0, 0, 0, time.UTC)},
    }

    for _, ro := range tamperable {
        ro := ro
        t.Run(subtestName(string(ro.name)), func(t *testing.T) {
            client := newClient(t, kmip.V1_4)
            id := createAES256(t, client, "ro-tamper")
            activateKey(t, client, id)

            before := singleAttributeValue(t, client, id, ro.name)
            require.NotNil(t, before, "%s must have a value before tampering", ro.name)

            // The modification may legitimately fail — that is the expected path.
            _, _ = client.ModifyAttribute(id, ro.name, ro.value).ExecContext(tctx(t))

            after := singleAttributeValue(t, newClient(t, kmip.V1_4), id, ro.name)
            assert.Equalf(t, fmt.Sprint(before), fmt.Sprint(after),
                "%s MUST NOT be altered by a client ModifyAttribute (%s: "+
                    "'Modifiable by client: No'); was %v, became %v",
                ro.name, ro.specRef, before, after)
        })
    }
}

// TestReadOnlyAttributes_DeleteRejected asserts DeleteAttribute is refused for
// attributes marked "Deletable by client: No".
func TestReadOnlyAttributes_DeleteRejected(t *testing.T) {
    for _, ro := range readOnlyAttrs {
        ro := ro
        t.Run(subtestName(string(ro.name)), func(t *testing.T) {
            client := newClient(t, kmip.V1_4)
            id := createAES256(t, client, "ro-delete")
            activateKey(t, client, id)

            _, err := client.DeleteAttribute(id, ro.name).ExecContext(tctx(t))
            assert.Errorf(t, err,
                "DeleteAttribute(%q) MUST be rejected: %s marks it "+
                    "'Deletable by client: No'", ro.name, ro.specRef)
        })
    }
}

// ─── 4. Client-modifiable attribute round-trip ───────────────────────────────

// writableAttr describes an attribute a client may add, modify and delete.
type writableAttr struct {
    name     kmip.AttributeName
    specRef  string
    initial  any
    modified any
}

// writableAttrs lists attributes whose rules table says
// "Modifiable by client: Yes" and "Deletable by client: Yes".
var writableAttrs = []writableAttr{
    {kmip.AttributeNameObjectGroup, "KMIP 1.4 §3.33", "group-alpha", "group-beta"},
    {kmip.AttributeNameContactInformation, "KMIP 1.4 §3.37", "alice@acme.com", "bob@acme.com"},
    {kmip.AttributeNameDescription, "KMIP 1.4 §3.46", "first description", "second description"},
    {kmip.AttributeNameComment, "KMIP 1.4 §3.47", "first comment", "second comment"},
}

// TestWritableAttributes_AddGetModifyGetDelete exercises the full client-side
// attribute lifecycle and asserts the server reflects each step.
func TestWritableAttributes_AddGetModifyGetDelete(t *testing.T) {
    for _, wa := range writableAttrs {
        wa := wa
        t.Run(subtestName(string(wa.name)), func(t *testing.T) {
            client := newClient(t, kmip.V1_4)
            id := createAES256(t, client, "rw")
            activateKey(t, client, id)

            // Add
            _, err := client.AddAttribute(id, wa.name, wa.initial).ExecContext(tctx(t))
            require.NoErrorf(t, err, "AddAttribute(%q) — %s says client-modifiable", wa.name, wa.specRef)

            got := singleAttributeValue(t, client, id, wa.name)
            assert.Equalf(t, fmt.Sprint(wa.initial), fmt.Sprint(got),
                "%s must read back the value that was just added", wa.name)

            // Modify
            _, err = client.ModifyAttribute(id, wa.name, wa.modified).ExecContext(tctx(t))
            require.NoErrorf(t, err, "ModifyAttribute(%q)", wa.name)

            got = singleAttributeValue(t, client, id, wa.name)
            assert.Equalf(t, fmt.Sprint(wa.modified), fmt.Sprint(got),
                "%s must read back the modified value", wa.name)

            // Delete
            _, err = client.DeleteAttribute(id, wa.name).ExecContext(tctx(t))
            require.NoErrorf(t, err,
                "DeleteAttribute(%q) must succeed and return a well-formed response "+
                    "containing the deleted Attribute (KMIP 1.4 §4.16 Table 205)", wa.name)

            got = singleAttributeValue(t, newClient(t, kmip.V1_4), id, wa.name)
            assert.Nilf(t, got, "%s must be absent after DeleteAttribute", wa.name)
        })
    }
}

// TestDeleteAttribute_ResponseIsWellFormed isolates the DeleteAttribute
// response shape.
//
// KMIP 1.4 §4.16 Table 205 requires the response payload to carry BOTH the
// Unique Identifier AND the deleted Attribute. Omitting the Attribute produces a
// truncated payload that strict clients cannot decode ("unexpected end of
// data"). Note KMIP 2.1 §6.1.13 Table 203 requires only the Unique Identifier,
// so this is a KMIP 1.x-specific requirement.
func TestDeleteAttribute_ResponseIsWellFormed(t *testing.T) {
    client := newClient(t, kmip.V1_4)
    id := createAES256(t, client, "del-shape")
    activateKey(t, client, id)

    const value = "group-to-delete"
    _, err := client.AddAttribute(id, kmip.AttributeNameObjectGroup, value).ExecContext(tctx(t))
    require.NoError(t, err, "AddAttribute(Object Group)")

    resp, err := client.DeleteAttribute(id, kmip.AttributeNameObjectGroup).ExecContext(tctx(t))
    require.NoError(t, err,
        "DeleteAttribute response must decode: KMIP 1.4 §4.16 Table 205 requires "+
            "the payload to contain the deleted Attribute in addition to the Unique Identifier")

    assert.Equal(t, id, resp.UniqueIdentifier, "response must echo the Unique Identifier")
    assert.Equalf(t, kmip.AttributeNameObjectGroup, resp.Attribute.AttributeName,
        "response must name the deleted attribute (KMIP 1.4 Table 205)")
    assert.Equal(t, value, fmt.Sprint(resp.Attribute.AttributeValue),
        "response must carry the deleted attribute's value")
}

// ─── 5. Custom (vendor) attributes ───────────────────────────────────────────

// TestCustomAttribute_Roundtrip validates custom attributes, which KMIP 1.x
// carries as Custom Attribute (§3.39) and which MUST use the "x-" or "y-"
// prefix convention.
func TestCustomAttribute_Roundtrip(t *testing.T) {
    client := newClient(t, kmip.V1_4)
    id := createAES256(t, client, "custom")
    activateKey(t, client, id)

    const attr = kmip.AttributeName("x-Cosmian-Test")
    const value = "custom-value-1"

    _, err := client.AddAttribute(id, attr, value).ExecContext(tctx(t))
    require.NoError(t, err, "AddAttribute(%q) — custom attributes use the x- prefix (KMIP 1.4 §3.39)", attr)

    got := singleAttributeValue(t, client, id, attr)
    require.NotNil(t, got, "custom attribute %q must be readable after being added", attr)
    assert.Contains(t, fmt.Sprint(got), value, "custom attribute must round-trip its value")
}

// TestCustomAttribute_DeleteByName verifies that deleting a custom attribute by
// name actually removes it.
//
// The KMIP 1.x wire form references a custom attribute by its full name
// ("x-Foo"), whereas the server stores it as a vendor attribute. If the two
// naming conventions disagree, the lookup misses and DeleteAttribute silently
// succeeds without deleting anything — a no-op that no status code reveals.
// KMIP 1.4 §4.16 also requires the response to name the deleted attribute, so a
// missing echo is the visible symptom of a missed lookup.
func TestCustomAttribute_DeleteByName(t *testing.T) {
    client := newClient(t, kmip.V1_4)
    id := createAES256(t, client, "custom-del")
    activateKey(t, client, id)

    const attr = kmip.AttributeName("x-Cosmian-Deletable")
    const value = "value-to-delete"

    _, err := client.AddAttribute(id, attr, value).ExecContext(tctx(t))
    require.NoError(t, err, "AddAttribute(%q)", attr)
    require.NotNil(t, singleAttributeValue(t, client, id, attr),
        "custom attribute must exist before deletion")

    resp, err := client.DeleteAttribute(id, attr).ExecContext(tctx(t))
    require.NoError(t, err, "DeleteAttribute(%q)", attr)
    assert.Equalf(t, attr, resp.Attribute.AttributeName,
        "DeleteAttribute must echo the deleted custom attribute (KMIP 1.4 §4.16 Table 205); "+
            "an empty echo means the server never found it and the delete was a no-op")

    assert.Nil(t, singleAttributeValue(t, newClient(t, kmip.V1_4), id, attr),
        "custom attribute %q must be gone after DeleteAttribute", attr)
}

// ─── 6. Attribute-driven Locate ──────────────────────────────────────────────

// TestLocate_ByObjectGroup verifies that an attribute set by the client is
// usable as a Locate filter — Locate matches on attribute values (KMIP 1.4
// §4.9), so an attribute that reads back correctly must also be searchable.
func TestLocate_ByObjectGroup(t *testing.T) {
    client := newClient(t, kmip.V1_4)
    id := createAES256(t, client, "locate-grp")
    activateKey(t, client, id)

    group := fmt.Sprintf("cosmian-group-%d", time.Now().UnixNano())
    _, err := client.AddAttribute(id, kmip.AttributeNameObjectGroup, group).ExecContext(tctx(t))
    require.NoError(t, err, "AddAttribute(Object Group)")

    resp, err := client.Locate().
        WithAttribute(kmip.AttributeNameObjectGroup, group).
        ExecContext(tctx(t))
    require.NoError(t, err, "Locate by Object Group")

    assert.Containsf(t, resp.UniqueIdentifier, id,
        "Locate filtered on Object Group=%q must return the key that carries it "+
            "(KMIP 1.4 §4.9)", group)
}

// TestLocate_ByCryptographicAlgorithm verifies Locate on a server-set attribute.
func TestLocate_ByCryptographicAlgorithm(t *testing.T) {
    client := newClient(t, kmip.V1_4)
    id := createAES256(t, client, "locate-alg")
    activateKey(t, client, id)

    resp, err := client.Locate().
        WithAttribute(kmip.AttributeNameCryptographicAlgorithm, kmip.CryptographicAlgorithmAES).
        WithAttribute(kmip.AttributeNameObjectType, kmip.ObjectTypeSymmetricKey).
        ExecContext(tctx(t))
    require.NoError(t, err, "Locate by Cryptographic Algorithm")
    assert.Contains(t, resp.UniqueIdentifier, id,
        "Locate on CryptographicAlgorithm=AES must return the AES key just created")
}

// ─── 7. Sensitive / AlwaysSensitive state machine ────────────────────────────

// TestSensitive_AlwaysSensitiveLatches validates the KMIP 2.1 §4.3 rule, which
// KMIP 1.4 §3.49 words identically: AlwaysSensitive is True only while Sensitive
// has *always* been True, and latches to False the moment Sensitive is ever set
// to False — it can never return to True.
func TestSensitive_AlwaysSensitiveLatches(t *testing.T) {
    client := newClient(t, kmip.V1_4)
    id := createAES256(t, client, "sensitive-latch")
    activateKey(t, client, id)

    // Keys are created non-sensitive by default, so AlwaysSensitive starts False.
    assert.Equal(t, "false", fmt.Sprint(singleAttributeValue(t, client, id, kmip.AttributeNameAlwaysSensitive)),
        "a key created non-Sensitive must have AlwaysSensitive=false (KMIP 1.4 §3.49)")

    // Turning Sensitive on must NOT resurrect AlwaysSensitive.
    _, err := client.ModifyAttribute(id, kmip.AttributeNameSensitive, true).ExecContext(tctx(t))
    require.NoError(t, err, "ModifyAttribute(Sensitive=true) — §3.48 marks it client-modifiable")

    assert.Equal(t, "true", fmt.Sprint(singleAttributeValue(t, client, id, kmip.AttributeNameSensitive)),
        "Sensitive must reflect the value just set")
    assert.Equal(t, "false", fmt.Sprint(singleAttributeValue(t, client, id, kmip.AttributeNameAlwaysSensitive)),
        "AlwaysSensitive MUST stay false once Sensitive has ever been false "+
            "(KMIP 1.4 §3.49 / KMIP 2.1 §4.3) — it is latching, not a mirror of Sensitive")
}

// ─── 8. Extractable / NeverExtractable state machine (KMIP 2.1 §4.33, KMIP 1.4 §3.50) ──

// TestExtractable_SetAtCreation verifies the Extractable attribute is correctly
// set and that NeverExtractable is its complement.
//
// Spec: KMIP 2.1 §4.33, KMIP 1.4 §3.50.
func TestExtractable_SetAtCreation(t *testing.T) {
    // Case 1: default creation → Extractable=true, NeverExtractable=false
    t.Run("Default_ExtractableTrue", func(t *testing.T) {
        client := newClient(t, kmip.V1_4)
        id := createAES256(t, client, "ext-default")
        activateKey(t, client, id)

        assert.Equal(t, "true", fmt.Sprint(singleAttributeValue(t, client, id, kmip.AttributeNameExtractable)),
            "Extractable should default to true")
        assert.Equal(t, "false", fmt.Sprint(singleAttributeValue(t, client, id, kmip.AttributeNameNeverExtractable)),
            "NeverExtractable should be false when Extractable is true")
    })

    // Case 2: ModifyAttribute(Extractable=false) → NeverExtractable=true
    t.Run("Modify_ExtractableFalse", func(t *testing.T) {
        client := newClient(t, kmip.V1_4)
        id := createAES256(t, client, "ext-modify-false")
        activateKey(t, client, id)

        _, err := client.ModifyAttribute(id, kmip.AttributeNameExtractable, false).ExecContext(tctx(t))
        require.NoError(t, err, "ModifyAttribute(Extractable=false) must succeed")

        assert.Equal(t, "false", fmt.Sprint(singleAttributeValue(t, client, id, kmip.AttributeNameExtractable)),
            "Extractable should be false after ModifyAttribute")
        assert.Equal(t, "true", fmt.Sprint(singleAttributeValue(t, client, id, kmip.AttributeNameNeverExtractable)),
            "NeverExtractable should be true when Extractable is set to false")
    })
}

// TestExtractable_NeverExtractableLatches verifies the KMIP 2.1 §4.33 / KMIP 1.4
// §3.50 state machine: NeverExtractable latches to False the moment Extractable
// is ever set to True — it can never return to True.
//
// State machine:
//   - ModifyAttribute(Extractable=false) → NeverExtractable=true
//   - ModifyAttribute(Extractable=true) → NeverExtractable=false (latches)
//   - ModifyAttribute(Extractable=false) → NeverExtractable stays false
//
// Spec: KMIP 2.1 §4.33, KMIP 1.4 §3.50.
func TestExtractable_NeverExtractableLatches(t *testing.T) {
    client := newClient(t, kmip.V1_4)
    id := createAES256(t, client, "never-ext-latch")
    activateKey(t, client, id)

    // ModifyAttribute(Extractable=false) → NeverExtractable=true
    _, err := client.ModifyAttribute(id, kmip.AttributeNameExtractable, false).ExecContext(tctx(t))
    require.NoError(t, err, "ModifyAttribute(Extractable=false)")

    assert.Equal(t, "true", fmt.Sprint(singleAttributeValue(t, client, id, kmip.AttributeNameNeverExtractable)),
        "NeverExtractable should be true when Extractable is set to false")

    // ModifyAttribute(Extractable=true) → NeverExtractable latches to false
    _, err = client.ModifyAttribute(id, kmip.AttributeNameExtractable, true).ExecContext(tctx(t))
    require.NoError(t, err, "ModifyAttribute(Extractable=true)")

    assert.Equal(t, "true", fmt.Sprint(singleAttributeValue(t, client, id, kmip.AttributeNameExtractable)),
        "Extractable should be true after ModifyAttribute")
    assert.Equal(t, "false", fmt.Sprint(singleAttributeValue(t, client, id, kmip.AttributeNameNeverExtractable)),
        "NeverExtractable should latch to false when Extractable set to true")

    // ModifyAttribute(Extractable=false) → NeverExtractable stays false
    _, err = client.ModifyAttribute(id, kmip.AttributeNameExtractable, false).ExecContext(tctx(t))
    require.NoError(t, err, "ModifyAttribute(Extractable=false)")

    assert.Equal(t, "false", fmt.Sprint(singleAttributeValue(t, client, id, kmip.AttributeNameExtractable)),
        "Extractable should be false again")
    assert.Equal(t, "false", fmt.Sprint(singleAttributeValue(t, client, id, kmip.AttributeNameNeverExtractable)),
        "NeverExtractable should stay false (latched) even after Extractable set back to false")
}

// TestSensitiveFalse_ForcesExtractableTrue verifies the KMIP spec constraint
// that Sensitive=false forces Extractable=true (KMIP 2.1 §4.3, KMIP 1.4 §3.48).
//
// Spec: KMIP 2.1 §4.3, KMIP 1.4 §3.48.
func TestSensitiveFalse_ForcesExtractableTrue(t *testing.T) {
    client := newClient(t, kmip.V1_4)
    id := createAES256(t, client, "sens-forces-ext")
    activateKey(t, client, id)

    // Set Sensitive=false → Extractable should be forced to true
    _, err := client.ModifyAttribute(id, kmip.AttributeNameSensitive, false).ExecContext(tctx(t))
    require.NoError(t, err, "ModifyAttribute(Sensitive=false)")

    assert.Equal(t, "false", fmt.Sprint(singleAttributeValue(t, client, id, kmip.AttributeNameSensitive)),
        "Sensitive should be false")
    assert.Equal(t, "true", fmt.Sprint(singleAttributeValue(t, client, id, kmip.AttributeNameExtractable)),
        "Extractable should be forced to true when Sensitive is false (KMIP 1.4 §3.48)")
    assert.Equal(t, "false", fmt.Sprint(singleAttributeValue(t, client, id, kmip.AttributeNameNeverExtractable)),
        "NeverExtractable should be false when Extractable is true")
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

// singleAttributeValue returns the value of one attribute, or nil when absent.
func singleAttributeValue(
    t *testing.T, client *kmipclient.Client, id string, name kmip.AttributeName,
) any {
    t.Helper()
    resp, err := client.GetAttributes(id, name).ExecContext(tctx(t))
    require.NoErrorf(t, err, "GetAttributes(%q)", name)
    for _, a := range resp.Attribute {
        if strings.EqualFold(string(a.AttributeName), string(name)) {
            return a.AttributeValue
        }
    }
    return nil
}

// attributeMinorVersion returns the KMIP 1.x minor version that first defines
// the attribute (OASIS KMIP Specification, Section 3 "Attributes"). Attributes
// present since KMIP 1.0 return 0.
func attributeMinorVersion(name kmip.AttributeName) int32 {
    switch name {
    case kmip.AttributeNameCertificateLength,
        kmip.AttributeNameFresh,
        kmip.AttributeNameX509CertificateIdentifier,
        kmip.AttributeNameX509CertificateSubject,
        kmip.AttributeNameX509CertificateIssuer,
        kmip.AttributeNameDigitalSignatureAlgorithm:
        return 1
    case kmip.AttributeNameAlternativeName,
        kmip.AttributeNameKeyValuePresent,
        kmip.AttributeNameKeyValueLocation,
        kmip.AttributeNameOriginalCreationDate:
        return 2
    case kmip.AttributeNameRandomNumberGenerator:
        return 3
    case kmip.AttributeNamePKCS_12FriendlyName,
        kmip.AttributeNameDescription,
        kmip.AttributeNameComment,
        kmip.AttributeNameSensitive,
        kmip.AttributeNameAlwaysSensitive,
        kmip.AttributeNameExtractable,
        kmip.AttributeNameNeverExtractable:
        return 4
    default:
        return 0
    }
}

// subtestName makes an attribute name safe and readable as a Go subtest name.
func subtestName(s string) string {
    return strings.NewReplacer(" ", "_", ".", "", "#", "").Replace(s)
}
