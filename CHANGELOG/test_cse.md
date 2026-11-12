## Features

### CLI
- `ckms login oauth` saves the `refresh_token` returned by the Identity Provider (scope `offline_access`) in `[http_config.oauth2_conf]`; `ckms login oauth --refresh` exchanges it for a new token without a browser
- `Oauth2LoginConfig` redacts `client_secret` and `refresh_token` in its `Debug` output

### CI
- Add read-only remote tests against `cse.cosmian.com` and `cse.test.cosmian.com` (`mise run test:cloud:google-cse-remote`, secret `CSE_CKMS_CONF_TOML`): KMS login by refresh token, Gmail CSE identities and key pairs
