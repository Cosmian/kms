// Package kmip_go_tests provides integration tests for the Cosmian KMS server
// using the ovh/kmip-go client library as an independent KMIP implementation.
//
// These tests validate KMIP 1.0–1.4 protocol compliance, including version-gating
// of attributes introduced in specific KMIP versions (e.g. AlwaysSensitive in 1.4).
//
// Prerequisites:
//   - KMS server running on 127.0.0.1:15696 (socket server, mTLS)
//   - Server uses test_data/certificates/client_server/server/ TLS certificate
//   - Client authenticates with test_data/certificates/client_server/owner/ cert
//
// Run via: go test -v -count=1 ./... -timeout 120s
// Or via:  mise run test:kmip-go
package kmip_go_tests

import (
    "context"
    "crypto/tls"
    "crypto/x509"
    "fmt"
    "os"
    "path/filepath"
    "runtime"
    "strings"
    "testing"
    "time"

    "github.com/ovh/kmip-go"
    "github.com/ovh/kmip-go/kmipclient"
    "github.com/stretchr/testify/require"
)

// ─── Certificate paths ────────────────────────────────────────────────────────

// repoRoot returns the absolute path to the KMS repository root.
// Walks upward from this file's location to find the Cargo.toml + crate/ pair.
func repoRoot() string {
    if v := os.Getenv("KMIP_GO_REPO_ROOT"); v != "" {
        return v
    }
    _, file, _, _ := runtime.Caller(0)
    dir := filepath.Dir(file)
    for {
        if _, err := os.Stat(filepath.Join(dir, "Cargo.toml")); err == nil {
            if _, err2 := os.Stat(filepath.Join(dir, "crate")); err2 == nil {
                return dir
            }
        }
        parent := filepath.Dir(dir)
        if parent == dir {
            cwd, _ := os.Getwd()
            return cwd
        }
        dir = parent
    }
}

func certPath(rel string) string { return filepath.Join(repoRoot(), rel) }

const (
    kmipAddr      = "127.0.0.1:15696"
    caCertRel     = "test_data/certificates/client_server/ca/ca.crt"
    clientCertRel = "test_data/certificates/client_server/owner/owner.client.acme.com.crt"
    clientKeyRel  = "test_data/certificates/client_server/owner/owner.client.acme.com.key"
)

// ─── Client helpers ───────────────────────────────────────────────────────────

// newClient dials the KMS socket server with mTLS, enforcing the given KMIP
// protocol version. The connection is closed via t.Cleanup.
//
// The test certificates use legacy CN-only naming without IP SANs; we build a
// custom TLS config that trusts the test CA while disabling hostname verification
// (test-only — production deployments must use properly signed certificates).
func newClient(t *testing.T, version kmip.ProtocolVersion) *kmipclient.Client {
    t.Helper()
    caPath := certPath(caCertRel)
    certFile := certPath(clientCertRel)
    keyFile := certPath(clientKeyRel)
    for _, p := range []string{caPath, certFile, keyFile} {
        if _, err := os.Stat(p); err != nil {
            t.Fatalf("cert file not found: %s (set KMIP_GO_REPO_ROOT)", p)
        }
    }

    // Load test CA
    caPEM, err := os.ReadFile(caPath)
    if err != nil {
        t.Fatalf("read CA cert: %v", err)
    }
    pool := x509.NewCertPool()
    pool.AppendCertsFromPEM(caPEM)

    // Load client cert+key
    clientCert, err := tls.LoadX509KeyPair(certFile, keyFile)
    if err != nil {
        t.Fatalf("load client cert/key: %v", err)
    }

    // The test server cert is a legacy CN-only cert without IP SANs. Go ≥ 1.15
    // rejects such certs unless we use InsecureSkipVerify. This is acceptable in
    // test context; production deployments use properly signed certificates.
    tlsCfg := &tls.Config{
        RootCAs:            pool,
        Certificates:       []tls.Certificate{clientCert},
        InsecureSkipVerify: true, //nolint:gosec // test-only: legacy CN cert without IP SANs
        MinVersion:         tls.VersionTLS12,
    }

    client, err := kmipclient.Dial(
        kmipAddr,
        kmipclient.WithTlsConfig(tlsCfg),
        kmipclient.EnforceVersion(version),
    )
    require.NoError(t, err, "connect to KMS (KMIP %s)", versionName(version))
    t.Cleanup(func() { _ = client.Close() })
    return client
}

// tctx returns a test-scoped context that is cancelled when the test ends.
func tctx(t *testing.T) context.Context {
    t.Helper()
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    t.Cleanup(cancel)
    return ctx
}

// versionName returns a human-readable KMIP version string (e.g. "1.4").
func versionName(v kmip.ProtocolVersion) string {
    return fmt.Sprintf("%d.%d", v.ProtocolVersionMajor, v.ProtocolVersionMinor)
}

// allVersions lists the KMIP versions this suite exercises.
var allVersions = []kmip.ProtocolVersion{
    kmip.V1_0, kmip.V1_1, kmip.V1_2, kmip.V1_3, kmip.V1_4,
}

// pre14Versions are versions where KMIP 1.4+ attributes must be absent.
var pre14Versions = []kmip.ProtocolVersion{kmip.V1_0, kmip.V1_1, kmip.V1_2, kmip.V1_3}

// ─── Key lifecycle helpers ────────────────────────────────────────────────────

// createAES256 creates a 256-bit AES key and registers a t.Cleanup that
// revokes then destroys the key when the test ends.
func createAES256(t *testing.T, client *kmipclient.Client, nameSuffix string) string {
    t.Helper()
    name := sanitiseName(fmt.Sprintf("kmip-go-%s-%s-%d", t.Name(), nameSuffix, time.Now().UnixNano()))
    resp, err := client.Create().
        AES(256, kmip.CryptographicUsageEncrypt|kmip.CryptographicUsageDecrypt).
        WithName(name).
        ExecContext(tctx(t))
    require.NoError(t, err, "Create AES-256")
    id := resp.UniqueIdentifier
    t.Logf("created key id=%s", id)
    t.Cleanup(func() { cleanupKey(t, client, id) })
    return id
}

// activateKey transitions a key to the Active state.
func activateKey(t *testing.T, client *kmipclient.Client, id string) {
    t.Helper()
    _, err := client.Activate(id).ExecContext(tctx(t))
    require.NoError(t, err, "Activate %s", id)
}

// cleanupKey revokes then destroys a key; errors are logged only (cleanup may
// run after the test has already failed).
func cleanupKey(t *testing.T, client *kmipclient.Client, id string) {
    t.Helper()
    ctx := context.Background()
    if _, err := client.Revoke(id).
        WithRevocationReasonCode(kmip.RevocationReasonCodeKeyCompromise).
        ExecContext(ctx); err != nil {
        t.Logf("cleanup revoke %s: %v", id, err)
    }
    if _, err := client.Destroy(id).ExecContext(ctx); err != nil {
        t.Logf("cleanup destroy %s: %v", id, err)
    }
}

// getAttrList returns the attribute names from GetAttributeList for a key.
// Returns []kmip.AttributeName (which is type string).
func getAttrList(t *testing.T, client *kmipclient.Client, id string) []kmip.AttributeName {
    t.Helper()
    resp, err := client.GetAttributeList(id).ExecContext(tctx(t))
    require.NoError(t, err, "GetAttributeList %s", id)
    return resp.AttributeName
}

// hasAttr checks whether attrName (case-insensitive) appears in a slice of
// kmip.AttributeName values.
func hasAttr(names []kmip.AttributeName, attrName string) bool {
    norm := strings.ToLower(attrName)
    for _, n := range names {
        if strings.ToLower(string(n)) == norm {
            return true
        }
    }
    return false
}

// sanitiseName replaces characters that are invalid in KMIP key names.
func sanitiseName(s string) string {
    return strings.NewReplacer("/", "_", " ", "_", ":", "_").Replace(s)
}
