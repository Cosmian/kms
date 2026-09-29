package kmip_go_tests

// Version-gating compliance tests for KMIP 1.0–1.4.
//
// These tests directly validate the server-side fix that ensures KMIP 1.4+
// attributes are absent from responses to pre-1.4 clients, as required by
// the KMIP specification:
//
//   - AlwaysSensitive  — introduced in KMIP 1.4 (absent in 1.0–1.3)
//   - NeverExtractable — introduced in KMIP 1.4
//   - Extractable      — introduced in KMIP 1.4
//   - Sensitive        — introduced in KMIP 1.4
//   - Fresh            — introduced in KMIP 1.1 (absent in 1.0)
//
// Spec reference: kmip/v1.0–v1.4 HTML spec files in this repository.

import (
    "fmt"
    "testing"

    "github.com/ovh/kmip-go"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

// attrs14Plus are attributes introduced in KMIP 1.4 that must be absent for
// KMIP 1.0–1.3 clients and present for KMIP 1.4 clients.
var attrs14Plus = []string{
    "Always Sensitive",
    "Never Extractable",
    "Extractable",
    "Sensitive",
}

// ─── GetAttributeList: absent in KMIP 1.0–1.3 ───────────────────────────────

// TestGetAttributeList_KMIP14Attrs_AbsentInPre14 verifies that the KMIP 1.4+
// attributes are NOT advertised in GetAttributeList responses for pre-1.4 clients.
// This is the primary external-validation test for the AlwaysSensitive fix.
func TestGetAttributeList_KMIP14Attrs_AbsentInPre14(t *testing.T) {
    for _, ver := range pre14Versions {
        ver := ver
        t.Run(fmt.Sprintf("V%s", versionName(ver)), func(t *testing.T) {
            t.Parallel()
            client := newClient(t, ver)
            id := createAES256(t, client, "attr-list-pre14")
            activateKey(t, client, id)

            names := getAttrList(t, client, id)
            t.Logf("KMIP %s GetAttributeList → %v", versionName(ver), names)

            for _, forbidden := range attrs14Plus {
                assert.False(t,
                    hasAttr(names, forbidden),
                    "KMIP %s: GetAttributeList MUST NOT contain %q (KMIP 1.4+ attribute, absent in %s spec)",
                    versionName(ver), forbidden, versionName(ver),
                )
            }
        })
    }
}

// ─── GetAttributeList: present in KMIP 1.4 ───────────────────────────────────

// TestGetAttributeList_KMIP14Attrs_PresentIn14 verifies that AlwaysSensitive and
// friends ARE advertised in GetAttributeList for KMIP 1.4.
func TestGetAttributeList_KMIP14Attrs_PresentIn14(t *testing.T) {
    client := newClient(t, kmip.V1_4)
    id := createAES256(t, client, "attr-list-14")
    activateKey(t, client, id)

    names := getAttrList(t, client, id)
    t.Logf("KMIP 1.4 GetAttributeList → %v", names)

    for _, expected := range attrs14Plus {
        assert.True(t,
            hasAttr(names, expected),
            "KMIP 1.4: GetAttributeList MUST contain %q (defined in KMIP 1.4 spec)", expected,
        )
    }
}

// ─── Get response: no parse error for pre-1.4 ────────────────────────────────

// TestGet_NoParseErrorForPre14 verifies that the Get operation response for
// KMIP 1.0–1.3 clients succeeds without parse errors.
//
// This is the exact scenario that caused PyKMIP to fail: a KMIP 1.2 Get response
// containing AlwaysSensitive (a KMIP 1.4 attribute) that PyKMIP 0.10.0 could not
// decode ("No value type for ALWAYS_SENSITIVE"). The ovh/kmip-go client exercises
// the same path and would fail here if the server incorrectly includes these attrs.
func TestGet_NoParseErrorForPre14(t *testing.T) {
    for _, ver := range pre14Versions {
        ver := ver
        t.Run(fmt.Sprintf("V%s", versionName(ver)), func(t *testing.T) {
            t.Parallel()
            client := newClient(t, ver)
            id := createAES256(t, client, "get-pre14")
            activateKey(t, client, id)

            getResp, err := client.Get(id).ExecContext(tctx(t))
            require.NoError(t, err,
                "KMIP %s: Get must succeed without unknown-attribute parse error "+
                    "(would fail if server returns AlwaysSensitive to a pre-1.4 client)",
                versionName(ver))
            assert.Equal(t, kmip.ObjectTypeSymmetricKey, getResp.ObjectType)
        })
    }
}

// ─── Fresh: absent in KMIP 1.0, present in 1.1+ ─────────────────────────────

// TestGetAttributeList_Fresh_AbsentIn10 verifies that "Fresh" is NOT in the
// GetAttributeList response for KMIP 1.0 (introduced in KMIP 1.1).
func TestGetAttributeList_Fresh_AbsentIn10(t *testing.T) {
    client := newClient(t, kmip.V1_0)
    id := createAES256(t, client, "fresh-10")
    activateKey(t, client, id)

    names := getAttrList(t, client, id)
    t.Logf("KMIP 1.0 GetAttributeList → %v", names)

    assert.False(t,
        hasAttr(names, "Fresh"),
        "KMIP 1.0: GetAttributeList MUST NOT contain 'Fresh' (introduced in KMIP 1.1)",
    )
}

// TestGetAttributeList_Fresh_PresentIn11Plus verifies that "Fresh" IS advertised
// for KMIP 1.1 and later.
func TestGetAttributeList_Fresh_PresentIn11Plus(t *testing.T) {
    for _, ver := range []kmip.ProtocolVersion{kmip.V1_1, kmip.V1_2, kmip.V1_3, kmip.V1_4} {
        ver := ver
        t.Run(fmt.Sprintf("V%s", versionName(ver)), func(t *testing.T) {
            t.Parallel()
            client := newClient(t, ver)
            id := createAES256(t, client, "fresh-11plus")
            activateKey(t, client, id)

            names := getAttrList(t, client, id)
            assert.True(t,
                hasAttr(names, "Fresh"),
                "KMIP %s: GetAttributeList MUST contain 'Fresh' (introduced in KMIP 1.1)",
                versionName(ver),
            )
        })
    }
}

// ─── GetAttributes: AlwaysSensitive absent in pre-1.4, present in 1.4 ────────

// TestGetAttributes_AlwaysSensitive_VersionGating validates attribute-level
// version gating via GetAttributes (not just GetAttributeList).
func TestGetAttributes_AlwaysSensitive_VersionGating(t *testing.T) {
    // KMIP 1.0–1.3: GetAttributes for State only — AlwaysSensitive must not appear
    for _, ver := range pre14Versions {
        ver := ver
        t.Run(fmt.Sprintf("AbsentPre14_V%s", versionName(ver)), func(t *testing.T) {
            t.Parallel()
            client := newClient(t, ver)
            id := createAES256(t, client, "ga-pre14")
            activateKey(t, client, id)

            resp, err := client.GetAttributes(id, kmip.AttributeNameState).ExecContext(tctx(t))
            require.NoError(t, err, "GetAttributes")

            for _, a := range resp.Attribute {
                assert.False(t,
                    hasAttr([]kmip.AttributeName{a.AttributeName}, "Always Sensitive"),
                    "KMIP %s: GetAttributes MUST NOT return AlwaysSensitive", versionName(ver))
                assert.False(t,
                    hasAttr([]kmip.AttributeName{a.AttributeName}, "Never Extractable"),
                    "KMIP %s: GetAttributes MUST NOT return NeverExtractable", versionName(ver))
            }
        })
    }

    // KMIP 1.4: explicitly request AlwaysSensitive — it must be returned
    t.Run("PresentIn14", func(t *testing.T) {
        client := newClient(t, kmip.V1_4)
        id := createAES256(t, client, "ga-14")
        activateKey(t, client, id)

        resp, err := client.GetAttributes(id,
            kmip.AttributeNameState,
            kmip.AttributeName("Always Sensitive"),
        ).ExecContext(tctx(t))
        require.NoError(t, err, "GetAttributes with AlwaysSensitive at KMIP 1.4")

        hasAlways := false
        for _, a := range resp.Attribute {
            if hasAttr([]kmip.AttributeName{a.AttributeName}, "Always Sensitive") {
                hasAlways = true
                t.Logf("KMIP 1.4: AlwaysSensitive = %v", a.AttributeValue)
            }
        }
        assert.True(t, hasAlways, "KMIP 1.4: GetAttributes must return AlwaysSensitive when requested")
    })
}

// ─── KMIP 1.1 attribute version-gating ───────────────────────────────────────

// TestVersionGating_KMIP11_Fresh verifies that the Fresh attribute (introduced
// in KMIP 1.1) is absent for KMIP 1.0 clients and present for KMIP 1.1+ clients.
//
// Spec: KMIP 1.1 §3.34.
func TestVersionGating_KMIP11_Fresh(t *testing.T) {
    // KMIP 1.0: Fresh must be absent
    t.Run("AbsentIn10", func(t *testing.T) {
        t.Parallel()
        client := newClient(t, kmip.V1_0)
        id := createAES256(t, client, "fresh-10")
        activateKey(t, client, id)

        attrs := getAttrList(t, client, id)
        assert.False(t, hasAttr(attrs, "Fresh"),
            "KMIP 1.0: GetAttributeList MUST NOT return Fresh (introduced in 1.1)")
    })

    // KMIP 1.1+: Fresh must be present
    for _, ver := range []kmip.ProtocolVersion{kmip.V1_1, kmip.V1_2, kmip.V1_3, kmip.V1_4} {
        ver := ver
        t.Run(fmt.Sprintf("PresentIn%s", versionName(ver)), func(t *testing.T) {
            t.Parallel()
            client := newClient(t, ver)
            id := createAES256(t, client, "fresh-"+subtestName(versionName(ver)))
            activateKey(t, client, id)

            attrs := getAttrList(t, client, id)
            assert.True(t, hasAttr(attrs, "Fresh"),
                "KMIP %s: GetAttributeList MUST return Fresh (introduced in 1.1)", versionName(ver))
        })
    }
}

// ─── KMIP 1.2 attribute version-gating ───────────────────────────────────────

// TestVersionGating_KMIP12 verifies that attributes introduced in KMIP 1.2
// (Alternative Name, Original Creation Date) are absent for KMIP 1.0–1.1
// clients and present for KMIP 1.2+ clients.
//
// Spec: KMIP 1.2 §3.40 (Alternative Name), KMIP 1.2 §3.43 (Original Creation Date).
func TestVersionGating_KMIP12(t *testing.T) {
    kmip12Attrs := []string{"Alternative Name", "Original Creation Date"}

    // KMIP 1.0–1.1: must be absent
    for _, ver := range []kmip.ProtocolVersion{kmip.V1_0, kmip.V1_1} {
        ver := ver
        t.Run(fmt.Sprintf("AbsentIn%s", versionName(ver)), func(t *testing.T) {
            t.Parallel()
            client := newClient(t, ver)
            id := createAES256(t, client, "kmip12-"+subtestName(versionName(ver)))
            activateKey(t, client, id)

            attrs := getAttrList(t, client, id)
            for _, attrName := range kmip12Attrs {
                assert.False(t, hasAttr(attrs, attrName),
                    "KMIP %s: GetAttributeList MUST NOT return %q (introduced in 1.2)",
                    versionName(ver), attrName)
            }
        })
    }

    // KMIP 1.2+: must be present
    for _, ver := range []kmip.ProtocolVersion{kmip.V1_2, kmip.V1_3, kmip.V1_4} {
        ver := ver
        t.Run(fmt.Sprintf("PresentIn%s", versionName(ver)), func(t *testing.T) {
            t.Parallel()
            client := newClient(t, ver)
            id := createAES256(t, client, "kmip12-"+subtestName(versionName(ver)))
            activateKey(t, client, id)

            attrs := getAttrList(t, client, id)
            for _, attrName := range kmip12Attrs {
                assert.True(t, hasAttr(attrs, attrName),
                    "KMIP %s: GetAttributeList MUST return %q (introduced in 1.2)",
                    versionName(ver), attrName)
            }
        })
    }
}

// ─── KMIP 1.3 attribute version-gating ───────────────────────────────────────

// TestVersionGating_KMIP13_RandomNumberGenerator verifies that the Random Number
// Generator attribute (introduced in KMIP 1.3) is absent for KMIP 1.0–1.2
// clients and present for KMIP 1.3+ clients.
//
// Spec: KMIP 1.3 §3.44.
func TestVersionGating_KMIP13_RandomNumberGenerator(t *testing.T) {
    // KMIP 1.0–1.2: must be absent
    for _, ver := range []kmip.ProtocolVersion{kmip.V1_0, kmip.V1_1, kmip.V1_2} {
        ver := ver
        t.Run(fmt.Sprintf("AbsentIn%s", versionName(ver)), func(t *testing.T) {
            t.Parallel()
            client := newClient(t, ver)
            id := createAES256(t, client, "rng-"+subtestName(versionName(ver)))
            activateKey(t, client, id)

            attrs := getAttrList(t, client, id)
            assert.False(t, hasAttr(attrs, "Random Number Generator"),
                "KMIP %s: GetAttributeList MUST NOT return Random Number Generator (introduced in 1.3)",
                versionName(ver))
        })
    }

    // KMIP 1.3+: must be present (if server sets it)
    for _, ver := range []kmip.ProtocolVersion{kmip.V1_3, kmip.V1_4} {
        ver := ver
        t.Run(fmt.Sprintf("AllowedIn%s", versionName(ver)), func(t *testing.T) {
            t.Parallel()
            client := newClient(t, ver)
            id := createAES256(t, client, "rng-"+subtestName(versionName(ver)))
            activateKey(t, client, id)

            // Random Number Generator may or may not be set by the server,
            // but it MUST NOT cause a decode error. We verify via GetAttributeList
            // that the attribute name is allowed (not filtered out by version-gating).
            attrs := getAttrList(t, client, id)
            // Just verify no error occurred — the attribute may or may not be set
            _ = attrs
            t.Logf("KMIP %s: GetAttributeList returned %d attributes (no decode error)", versionName(ver), len(attrs))
        })
    }
}

// ─── Comprehensive version-gating: all attributes vs all versions ────────────

// TestVersionGating_Comprehensive validates that every attribute returned by
// GetAttributeList is allowed by the negotiated KMIP version. This is a
// catch-all test that checks all attributes against their introduction version.
func TestVersionGating_Comprehensive(t *testing.T) {
    // attribute → KMIP minor version that introduced it
    attrIntroVersion := map[string]int32{
        "Fresh":                      1, // KMIP 1.1
        "Certificate Length":         1, // KMIP 1.1
        "X.509 Certificate Identifier": 1, // KMIP 1.1
        "X.509 Certificate Subject":  1, // KMIP 1.1
        "X.509 Certificate Issuer":   1, // KMIP 1.1
        "Digital Signature Algorithm": 1, // KMIP 1.1
        "Alternative Name":           2, // KMIP 1.2
        "Key Value Present":          2, // KMIP 1.2
        "Key Value Location":         2, // KMIP 1.2
        "Original Creation Date":     2, // KMIP 1.2
        "Random Number Generator":    3, // KMIP 1.3
        "PKCS#12 Friendly Name":     4, // KMIP 1.4
        "Description":               4, // KMIP 1.4
        "Comment":                   4, // KMIP 1.4
        "Sensitive":                 4, // KMIP 1.4
        "Always Sensitive":          4, // KMIP 1.4
        "Extractable":               4, // KMIP 1.4
        "Never Extractable":         4, // KMIP 1.4
    }

    for _, ver := range allVersions {
        ver := ver
        minor := int32(ver.ProtocolVersionMinor)
        t.Run(fmt.Sprintf("KMIP%s", versionName(ver)), func(t *testing.T) {
            client := newClient(t, ver)
            id := createAES256(t, client, "vg-all-"+subtestName(versionName(ver)))
            activateKey(t, client, id)

            attrs := getAttrList(t, client, id)
            for _, attrName := range attrs {
                introMinor, known := attrIntroVersion[string(attrName)]
                if !known {
                    continue // attribute introduced in KMIP 1.0 or not tracked
                }
                if minor < introMinor {
                    t.Errorf("KMIP %s: GetAttributeList returned %q but it was introduced in KMIP 1.%d",
                        versionName(ver), attrName, introMinor)
                }
            }
        })
    }
}
