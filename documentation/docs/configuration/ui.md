# KMS User Interface

The **KMS User Interface (UI)** is a web-based application served from the **KMS server**, allowing users to perform key management operations easily.

[TOC]

## Accessing the User Interface

Once the **KMS server** is running, open the following URL in your browser:

```plaintext
https://YOUR_KMS_URL/ui
```

Replace `YOUR_KMS_URL` with the actual KMS server address.

If the KMS is running behind a reverse proxy, set [`kms_public_url`](server_configuration_file.md#manual-configuration) in the server configuration to the public-facing URL — this is required for the OIDC redirect flow to work correctly.

The UI bundle is served from the path configured by [`ui_index_html_folder`](server_configuration_file.md#manual-configuration) (defaults to the built-in bundle shipped with the server).

## Authentication Configuration

The UI automatically detects the authentication method configured on the KMS server and adapts its login flow accordingly:

- **OIDC Authentication**: The UI presents a **LOGIN** button that redirects to the identity provider. See [Configuring OIDC Authentication](#configuring-oidc-authentication) below.
- **Certificate Authentication**: The UI presents an **ACCESS KMS** button. The browser negotiates the [mTLS](tls.md) handshake and submits the client certificate automatically. If no valid certificate is available, the login page is shown again with an error. See [Configuring Certificate Authentication](#configuring-certificate-authentication-mtls) below.
- **No authentication configured**: No login is required — the UI takes you directly to the key management interface. However, a warning banner is displayed:

    !!! warning
    To remove the warning "Authentication is disabled on this KMS server", configure an [authentication method like explained in the next sections](#authentication-configuration).

---

### Configuring OIDC Authentication

To enable authentication via **OIDC**, configure the KMS UI with details from the selected **OIDC compliant tenant**.

#### 1. Using the Configuration File (`.toml`)

Add the following section to your **KMS configuration file**:

```toml
[ui_config.ui_oidc_auth]
ui_oidc_client_id = "your_client_id"
ui_oidc_client_secret = "your_client_secret"  # (optional)
ui_oidc_issuer_url = "https://your_oidc_issuer_url"
ui_oidc_logout_url = "https://your_oidc_logout_url"
```

If your KMS is accessible behind a proxy, also specify the public KMS URL in the generic section:

```toml
kms_public_url = "your_kms_public_url"
```

You may also need to register the following URIs in your Identity Provider (IdP) application settings:

- Allowed redirect/callback URI: `https://YOUR_KMS_URL/ui/callback`
- Application Login URI: `https://YOUR_KMS_URL/ui/login`
- Logout URI: `https://YOUR_KMS_URL/ui/login`

#### 2. Using Command-Line Arguments

```bash
--ui-oidc-client-id "your_client_id" \
--ui-oidc-client-secret "your_client_secret" \
--ui-oidc-issuer-url "https://your_oidc_issuer_url" \
--ui-oidc-logout-url "https://your_oidc_logout_url"
```

!!! note
    The UI login flow always uses PKCE (`code_challenge_method=S256`). The client secret is optional — see the [PKCE Authentication guide](pkce_authentication.md) for per-provider configuration instructions.

!!! note
    API Token authentication is not supported by the UI.

---

### Configuring Certificate Authentication (mTLS)

When the KMS server is started with mutual TLS and a client CA (`clients_ca_cert_file`), the UI switches to certificate-based login. See [Enabling TLS](tls.md) for server-side configuration.

The browser handles the mTLS handshake transparently: Chrome presents the client certificate during the TLS handshake and the KMS server extracts the **`Subject CN`** of the certificate and uses it as the KMS **username**. For example, a certificate with `CN=alice` identifies the user as `alice` for all access-control decisions.

Users who have no valid client certificate installed will see a "CERT identity verification failed" error on the login page.

#### Step 1 — Obtain your client certificate

The client certificate must be **signed by the CA configured in `clients_ca_cert_file`** on the server. Obtain it from your PKI or administrator. If you are using the KMS setup wizard, it generates a `client.crt` + `client.key` pair automatically.

#### Step 2 — Convert PEM to PKCS#12 (if needed)

Browsers import certificates as **PKCS#12 (`.p12`)** bundles. If you have separate PEM files, convert them:

```bash
openssl pkcs12 -export \
  -certpbe PBE-SHA1-3DES -keypbe PBE-SHA1-3DES -macalg sha1 \
  -in client.crt \
  -inkey client.key \
  -certfile ca.crt \
  -out client.p12 \
  -passout pass:your-password
```

!!! warning "macOS / Chrome compatibility"
    OpenSSL 3.x generates PKCS#12 files with AES-256 ciphers by default. macOS
    Security.framework (which Chrome on macOS uses) **cannot import** that format.
    The `-certpbe PBE-SHA1-3DES -keypbe PBE-SHA1-3DES -macalg sha1` flags select
    the older 3DES format that macOS accepts.

If you already have a `.p12` file generated by the KMS wizard (`client.p12`), skip this step — it is already in the correct format.

#### Step 3 — Install the certificate in the browser

=== "Linux (Chrome)"

    1. Open [`chrome://settings/certificates`](chrome://settings/certificates)
       (or **Settings → Privacy and security → Security → Manage certificates**).
    2. Go to the **Your certificates** tab.
    3. Click **Import**, select `client.p12`, and enter the password when prompted.

=== "macOS (Chrome / Safari)"

    Chrome and Safari on macOS read client certificates from the **system keychain** — do not use Chrome's built-in certificate manager.

    1. Double-click `client.p12` in Finder, or run:
       ```bash
       security import client.p12 -k ~/Library/Keychains/login.keychain-db
       ```
    2. Open **Keychain Access**, find your certificate under **My Certificates**.
    3. Double-click the certificate → expand **Trust** → set **"When using this certificate"** to **Always Trust** (or ensure the signing CA is already trusted).

=== "Windows (Chrome / Edge)"

    Chrome and Edge on Windows read client certificates from the **Windows Certificate Store**.

    1. Double-click `client.p12` → follow the Import Wizard → store in **Personal**.
    2. If the signing CA is not already trusted, also import `ca.crt` into **Trusted Root Certification Authorities** using `certmgr.msc`.

!!! tip
    After installing or changing a client certificate, **fully close and relaunch the browser**. Browsers cache TLS session state and will not renegotiate with the new certificate until all windows are closed.

!!! warning "Certificate CN = KMS username"
    The **Common Name (CN)** of the client certificate becomes the KMS username. Make sure the CN matches the identity you want to use for access control. A wildcard CN (`*`) is explicitly rejected by the server.

---
