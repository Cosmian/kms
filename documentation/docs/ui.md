# KMS User Interface

The **KMS User Interface (UI)** is a web-based application served from the **KMS server**, allowing users to perform key management operations easily.


## Authentication Configuration

The UI follows the **KMS server’s authentication** method. The authentication requirements depend on the server mode:

- **Admin Mode**: No authentication is required.
- **Certificate Authentication**: The browser must be configured with the appropriate client certificate.
- **OIDC Authentication**: If **OIDC (OpenID Connect)** is used, the UI must be configured with the appropriate tenant settings in the **KMS configuration file** or via **command-line arguments**.

### Configuring OIDC Authentication

To enable authentication via **OIDC**, you must configure the KMS UI with details from the selected **OIDC compliant tenant**.

#### 1. Using the Configuration File (`.toml`)

Add the following section to your **KMS configuration file**:

```toml
[ui_config.ui_oidc_auth]
ui_oidc_client_id = "your_client_id"
ui_oidc_client_secret = "your_client_secret"  # (optional)
ui_oidc_issuer_url = "https://your_oidc_issuer_url"
ui_oidc_logout_url = "https://your_oidc_logout_url"
```

If your KMS is accessible behind a proxy, you need to also specify the public KMS URL from the generic section of
the TOML file:

```toml
kms_public_url = "your_kms_public_url"
```


#### 2. Using Command-Line Arguments

Alternatively, provide OIDC settings as command-line arguments when starting the KMS server:

```bash
--ui-oidc-client-id "your_client_id" \
--ui-oidc-client-secret "your_client_secret" \
--ui-oidc-issuer-url "https://your_oidc_issuer_url" \
--ui-oidc-logout-url "https://your_oidc_logout_url"
```

Note: API Token authentication is not currently supported by the UI.

## Accessing the User Interface

Once the **KMS server** is running, you can access the UI by opening the following URL in your browser:

```plaintext
https://YOUR_KMS_URL/ui
```

Replace `YOUR_KMS_URL` with the actual KMS server address.
