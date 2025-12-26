use cosmian_kms_server::config::IdpAuthConfig;

// Test auth0 Config
pub(crate) const AUTH0_JWT_ISSUER_URI: &str = "https://demo-kms.eu.auth0.com/";
pub(crate) const AUTH0_TOKEN: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjdTbW5SbV9NbmM0YVo0bVNQR19uVSJ9.eyJlbWFpbCI6InRlY2hAY29zbWlhbi5jb20iLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsImlzcyI6Imh0dHBzOi8vZGVtby1rbXMuZXUuYXV0aDAuY29tLyIsImF1ZCI6Ikt3bm9Cb212MDRWdENzMmpqMUk2MmdyRnd4OExORE9sIiwic3ViIjoiYXV0aDB8Njg3ZTUwY2NlYzIzYzU2MzNhNzFiNTRlIiwiaWF0IjoxNzUzMTA4Njg1LCJleHAiOjMxNTUzNTMxMDg2ODUsInNpZCI6Im5nQm9qY1RHTXdGN1RXMTBIcGdkREZxQjFsSWh0RGYxIiwibm9uY2UiOiJOOU9jUS1BUEtzcEg5b3hWdnByUGV3In0.OssdvoPzOTiZ03pQN8eijHM-DRjVKj4vj7gt8_qqZIXhU-hvLB-7uJ8nRhKj8WSgyjMTLW__TkFTEVlqHL-vGRI3L-TIPrCAyKe37cBywqiLXIgYSKhijh23OFd7NizpeSiF_fjR3AGfRL80NCASwKVATexOI7WM8vI4rkZWh1Yrj9bIFRbtdK9YcdHz6fOrYp-K1hyIDnQ5fTaizpZhZuTTkGC1xBegn0JpZcyeUWsYPxh_9ICw0GRplYkA4ZX_QPcRReJqCVlK3dwuFvM545xz9IPlDaaa1APsa-KMQZBoVbdg9mwxg_sxkO235aC7qvX1v4fOhxjNIkFgBcm6EA";

// This user token is used to test privileged user functionalities, it belongs to a non-privileged user.
pub(crate) const AUTH0_TOKEN_USER: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjdTbW5SbV9NbmM0YVo0bVNQR19uVSJ9.eyJlbWFpbCI6InVzZXIuY2xpZW50QGFjbWUuY29tIiwiZW1haWxfdmVyaWZpZWQiOmZhbHNlLCJpc3MiOiJodHRwczovL2RlbW8ta21zLmV1LmF1dGgwLmNvbS8iLCJhdWQiOiJLd25vQm9tdjA0VnRDczJqajFJNjJnckZ3eDhMTkRPbCIsInN1YiI6ImF1dGgwfDY4N2U1MDM4YWFkNmJlNmZhOGEyYjI0OCIsImlhdCI6MTc1MzEwODU1NCwiZXhwIjozMTU1MzUzMTA4NTU0LCJzaWQiOiJmaFpMcWRXNkxIdmxhU0tyeG5kckZIbzNneFpTUDZGWiIsIm5vbmNlIjoiNTA4SjRub29hRU45WUptSFdUdl9xdyJ9.kA4BBNF2C8tTCtAIi84yMIOUiASkT0oAHICxXbPCnCb6C9Tuv1wG-oqhuNXg7_Btq-iO0gxd5iVDBE2JC8FpJipWSouT_NhNufopPL3n6PHIhXrdiZMRX676WcDY7h7chTNAX7KjQevc0ei-udecVvx96k8Dh362XHaVRVdSjcLJdl2IvWLyYBOlCU93dOSXKHRgs60TOi-JL0FevrkwQz-LCIFuWU7TEgzNRlL5gqzcRs5X25NBjIljzyIWg7yvdS_Yry2LR7blrO1IKkCwRuBgrhrX-w9aSX1qSy_hy6GCSuy_fpO8lP0FCynuENm2eIZKyZ6uRUbxILOqY5_q8w";

pub(crate) fn get_multiple_jwt_config() -> IdpAuthConfig {
    // Other examples of JWT issuers and JWKS URIs:
    // --jwt-auth-provider="https://accounts.google.com,https://www.googleapis.com/oauth2/v3/certs,kacls-migration,996739510374-2tauakcggau7kvk37784k0s2lmveb9c9.apps.googleusercontent.com"
    // --jwt-auth-provider="https://login.microsoftonline.com/612da4de-35c0-42de-ba56-174b69062c96/v2.0,https://login.microsoftonline.com/612da4de-35c0-42de-ba56-174b69062c96/discovery/v2.0/keys"
    // --jwt-auth-provider=https://demo-kms.eu.auth0.com/,https://demo-kms.eu.auth0.com/.well-known/jwks.json"
    IdpAuthConfig {
        jwt_auth_provider: Some(vec![
            format!(
                "{},{},kacls-migration,996739510374-2tauakcggau7kvk37784k0s2lmveb9c9.apps.googleusercontent.com",
                "https://accounts.google.com", "https://www.googleapis.com/oauth2/v3/certs"
            ),
            format!(
                "{},{}",
                "https://login.microsoftonline.com/612da4de-35c0-42de-ba56-174b69062c96/v2.0",
                "https://login.microsoftonline.com/612da4de-35c0-42de-ba56-174b69062c96/discovery/v2.0/keys"
            ),
            format!("{AUTH0_JWT_ISSUER_URI},{AUTH0_JWT_ISSUER_URI}.well-known/jwks.json"),
        ]),
    }
}
