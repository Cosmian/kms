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

The browser handles the mTLS handshake transparently. Users that have no valid client certificate installed will see an error message on the login page until they install a client certificate issued by the CA specified in `clients_ca_cert_file`.

#### Loading a client certificate in the browser

The steps below are for Google Chrome, but the process is similar in other browsers:

1. Alternatively, open [`chrome://settings/certificates`](chrome://settings/certificates) (**Chrome Settings** → **Privacy and security → Security → Manage certificates**.)
2. Go to the **Your certificates** tab.
3. Click **Import** and select your `.p12` (PKCS#12) certificate bundle.
4. Enter the certificate password when prompted.


!!! tip
    If your browser does not prompt for a certificate, or authentication keeps failing after installing the certificate, **close all windows completely and relaunch**. Browsers typically cache TLS session state and will not re-negotiate with the new certificate until they restart.

!!! note "macOS and Windows"
    On macOS, use **Keychain Access** to import the `.p12` bundle — Chrome reads client certificates directly from the system keychain. On Windows, use the system **Certificate Manager** (`certmgr.msc`).

---

