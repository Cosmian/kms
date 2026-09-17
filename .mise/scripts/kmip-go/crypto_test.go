package kmip_go_tests

import (
    "bytes"
    "fmt"
    "testing"

    "github.com/ovh/kmip-go"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

// ─── AES-GCM Encrypt/Decrypt round-trip ──────────────────────────────────────

// TestEncryptDecryptAES_GCM_V14 creates an AES-256-GCM key at KMIP 1.4,
// encrypts a plaintext, then decrypts it and verifies the round-trip.
func TestEncryptDecryptAES_GCM_V14(t *testing.T) {
    client := newClient(t, kmip.V1_4)
    id := createAES256(t, client, "enc-dec")
    activateKey(t, client, id)

    plaintext := []byte("Hello, KMIP 1.4 compliance test!")

    // Encrypt
    encResp, err := client.Encrypt(id).
        WithCryptographicParameters(kmip.AES_GCM).
        Data(plaintext).
        ExecContext(tctx(t))
    require.NoError(t, err, "Encrypt")
    require.NotEmpty(t, encResp.Data, "encrypted data must not be empty")

    t.Logf("encrypted %d→%d bytes, IV=%d, tag=%d",
        len(plaintext), len(encResp.Data),
        len(encResp.IVCounterNonce),
        len(encResp.AuthenticatedEncryptionTag))

    // Decrypt
    decResp, err := client.Decrypt(id).
        WithCryptographicParameters(kmip.AES_GCM).
        WithIvCounterNonce(encResp.IVCounterNonce).
        WithAuthTag(encResp.AuthenticatedEncryptionTag).
        Data(encResp.Data).
        ExecContext(tctx(t))
    require.NoError(t, err, "Decrypt")
    assert.True(t, bytes.Equal(plaintext, decResp.Data),
        "decrypt round-trip mismatch:\n  want %q\n  got  %q", plaintext, decResp.Data)
}

// TestEncryptDecryptAES_GCM_MultiVersion verifies Encrypt/Decrypt for KMIP versions
// that have fully compatible AES-GCM handling.
//
// Versions skipped:
//   - V1.1, V1.3: ovh/kmip-go version-gates AuthenticatedEncryptionTag to v1.4+, so
//     the GCM tag cannot be recovered from the response for these versions.
//     V1.2 works because the KMS server appends the tag to the ciphertext for ≤1.2
//     (and the server also extracts it from the data on decrypt).
func TestEncryptDecryptAES_GCM_MultiVersion(t *testing.T) {
    // V1.1 and V1.3 are skipped: ovh/kmip-go omits AuthenticatedEncryptionTag
    // in responses for versions < 1.4 (field is annotated version=v1.4..).
    // V1.2 works because the server appends the tag to ciphertext for ≤1.2 and
    // strips it on the decrypt request (perform_request_tweaks).
    for _, ver := range []kmip.ProtocolVersion{kmip.V1_2, kmip.V1_4} {
        ver := ver
        t.Run(fmt.Sprintf("V%s", versionName(ver)), func(t *testing.T) {
            t.Parallel()
            client := newClient(t, ver)
            id := createAES256(t, client, "enc-multi")
            activateKey(t, client, id)

            plaintext := []byte("KMIP encrypt test payload")

            encResp, err := client.Encrypt(id).
                WithCryptographicParameters(kmip.AES_GCM).
                Data(plaintext).
                ExecContext(tctx(t))
            require.NoError(t, err, "Encrypt KMIP %s", versionName(ver))

            decResp, err := client.Decrypt(id).
                WithCryptographicParameters(kmip.AES_GCM).
                WithIvCounterNonce(encResp.IVCounterNonce).
                WithAuthTag(encResp.AuthenticatedEncryptionTag).
                Data(encResp.Data).
                ExecContext(tctx(t))
            require.NoError(t, err, "Decrypt KMIP %s", versionName(ver))
            assert.True(t, bytes.Equal(plaintext, decResp.Data),
                "round-trip failed at KMIP %s", versionName(ver))
        })
    }
}

// ─── RSA-2048 Sign/Verify ─────────────────────────────────────────────────────

// TestSignVerify_RSA2048_PSS_V14 creates an RSA-2048 key pair, signs a digest
// with PSS padding, then verifies the signature.
func TestSignVerify_RSA2048_PSS_V14(t *testing.T) {
    client := newClient(t, kmip.V1_4)

    kpResp, err := client.CreateKeyPair().
        RSA(2048, kmip.CryptographicUsageSign, kmip.CryptographicUsageVerify).
        WithName("kmip-go-sign-test").
        ExecContext(tctx(t))
    require.NoError(t, err, "CreateKeyPair RSA-2048")

    privID := kpResp.PrivateKeyUniqueIdentifier
    pubID := kpResp.PublicKeyUniqueIdentifier
    t.Cleanup(func() {
        cleanupKey(t, client, privID)
        cleanupKey(t, client, pubID)
    })

    _, err = client.Activate(privID).ExecContext(tctx(t))
    require.NoError(t, err, "Activate private key")
    _, err = client.Activate(pubID).ExecContext(tctx(t))
    require.NoError(t, err, "Activate public key")

    data := []byte("KMIP 1.4 sign/verify compliance test payload")
    signParams := kmip.CryptographicParameters{
        CryptographicAlgorithm:    kmip.CryptographicAlgorithmRSA,
        HashingAlgorithm:          kmip.HashingAlgorithmSHA_256,
        DigitalSignatureAlgorithm: kmip.DigitalSignatureAlgorithmRSASSA_PSS,
    }

    // Sign
    signResp, err := client.Sign(privID).
        WithCryptographicParameters(signParams).
        Data(data).
        ExecContext(tctx(t))
    require.NoError(t, err, "Sign")
    require.NotEmpty(t, signResp.SignatureData, "signature must not be empty")
    t.Logf("RSA-2048 PSS signature: %d bytes", len(signResp.SignatureData))

    // Verify
    verResp, err := client.SignatureVerify(pubID).
        WithCryptographicParameters(signParams).
        Data(data).
        Signature(signResp.SignatureData).
        ExecContext(tctx(t))
    require.NoError(t, err, "SignatureVerify")
    assert.Equal(t, kmip.ValidityIndicatorValid, verResp.ValidityIndicator,
        "signature should be Valid")
}

// ─── EC P-256 key pair ────────────────────────────────────────────────────────

// TestCreateKeyPair_EC_P256_V14 creates an EC P-256 key pair and verifies both
// keys are accessible with the correct object types.
func TestCreateKeyPair_EC_P256_V14(t *testing.T) {
    client := newClient(t, kmip.V1_4)

    resp, err := client.CreateKeyPair().
        ECDSA(kmip.RecommendedCurveP_256,
            kmip.CryptographicUsageSign,
            kmip.CryptographicUsageVerify).
        WithName("kmip-go-ec-test").
        ExecContext(tctx(t))
    require.NoError(t, err, "CreateKeyPair EC P-256")

    privID := resp.PrivateKeyUniqueIdentifier
    pubID := resp.PublicKeyUniqueIdentifier
    require.NotEmpty(t, privID)
    require.NotEmpty(t, pubID)
    t.Logf("EC P-256 key pair: private=%s public=%s", privID, pubID)

    t.Cleanup(func() {
        cleanupKey(t, client, privID)
        cleanupKey(t, client, pubID)
    })

    for _, tc := range []struct {
        id   string
        want kmip.ObjectType
    }{{privID, kmip.ObjectTypePrivateKey}, {pubID, kmip.ObjectTypePublicKey}} {
        g, err := client.Get(tc.id).ExecContext(tctx(t))
        require.NoError(t, err)
        assert.Equal(t, tc.want, g.ObjectType)
    }
}
