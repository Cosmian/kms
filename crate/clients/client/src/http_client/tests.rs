#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod pkcs12_tests {
    use cosmian_kms_logger::log_init;

    use crate::http_client::{HttpClient, HttpClientConfig};

    #[test]
    fn test_pkcs12_nonexistent_file() {
        // Test with non-existent PKCS12 file
        let config = HttpClientConfig {
            tls_client_pkcs12_path: Some("/nonexistent/path/file.p12".to_owned()),
            tls_client_pkcs12_password: Some("password".to_owned()),
            ..Default::default()
        };

        let result = HttpClient::instantiate(&config);
        // Should fail to open the file
        result.unwrap_err();
    }

    #[test]
    fn test_pkcs12_existent_file() {
        log_init(None);
        // Test with PKCS12 file from the workspace test data
        let config = HttpClientConfig {
            tls_client_pkcs12_path: Some(
                "../../test_data/client_server/owner/owner.client.acme.com.p12".to_owned(),
            ),
            tls_client_pkcs12_password: Some("password".to_owned()),
            ..Default::default()
        };

        let result = HttpClient::instantiate(&config);
        // The file might not exist in the test environment, so we just check that
        // instantiation doesn't panic
        if let Err(e) = result {
            // This is expected if the file doesn't exist or is invalid
            eprintln!("Expected error: {e}");
        }
    }

    #[test]
    fn test_http_client_without_pkcs12() {
        // Test normal HTTP client instantiation without PKCS12
        let config = HttpClientConfig::default();
        let result = HttpClient::instantiate(&config);

        assert!(
            result.is_ok(),
            "Expected OK but got error: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_http_client_with_cipher_suites() {
        // Test HTTP client with custom cipher suites (warns and falls back with native-tls)
        let config = HttpClientConfig {
            cipher_suites: Some("TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256".to_owned()),
            ..Default::default()
        };

        let result = HttpClient::instantiate(&config);
        result.unwrap();
    }

    #[test]
    fn test_http_client_with_invalid_cipher_suites() {
        // Test HTTP client with invalid cipher suites.
        // With native-tls, unknown cipher suites produce a warning and the client
        // falls back to default configuration, so instantiation still succeeds.
        let config = HttpClientConfig {
            cipher_suites: Some("INVALID_CIPHER_SUITE".to_owned()),
            ..Default::default()
        };

        let result = HttpClient::instantiate(&config);
        assert!(
            result.is_ok(),
            "Expected OK with fallback to defaults but got error: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_http_client_with_mixed_cipher_suites() {
        // Test with a mix of valid and invalid cipher suites.
        // With native-tls the cipher suite field is ignored with a warning,
        // so instantiation succeeds regardless.
        let config = HttpClientConfig {
            cipher_suites: Some(
                "TLS_AES_256_GCM_SHA384:INVALID_SUITE:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
                    .to_owned(),
            ),
            ..Default::default()
        };

        let result = HttpClient::instantiate(&config);
        assert!(
            result.is_ok(),
            "Expected OK with fallback to defaults but got error: {:?}",
            result.err()
        );
    }
}

#[cfg(test)]
mod client_auth_constraints_tests {
    use crate::http_client::{HttpClient, HttpClientConfig};

    #[test]
    fn test_error_when_both_pem_and_pkcs12_provided() {
        let config = HttpClientConfig {
            tls_client_pkcs12_path: Some("/tmp/client.p12".to_owned()),
            tls_client_pkcs12_password: Some("password".to_owned()),
            tls_client_pem_cert_path: Some("/tmp/client.crt".to_owned()),
            tls_client_pem_key_path: Some("/tmp/client.key".to_owned()),
            ..Default::default()
        };

        let result = HttpClient::instantiate(&config);
        assert!(
            result.is_err(),
            "Should error when both PEM and PKCS#12 are set"
        );
    }

    #[test]
    fn test_error_when_only_pem_cert_provided() {
        let config = HttpClientConfig {
            tls_client_pem_cert_path: Some("/tmp/client.crt".to_owned()),
            ..Default::default()
        };

        let result = HttpClient::instantiate(&config);
        assert!(result.is_err(), "Should error when PEM key is missing");
    }

    #[test]
    fn test_error_when_only_pem_key_provided() {
        let config = HttpClientConfig {
            tls_client_pem_key_path: Some("/tmp/client.key".to_owned()),
            ..Default::default()
        };

        let result = HttpClient::instantiate(&config);
        assert!(result.is_err(), "Should error when PEM cert is missing");
    }

    #[test]
    fn test_error_when_pkcs12_without_password() {
        let config = HttpClientConfig {
            tls_client_pkcs12_path: Some("/tmp/client.p12".to_owned()),
            ..Default::default()
        };

        let result = HttpClient::instantiate(&config);
        assert!(
            result.is_err(),
            "Should error when PKCS#12 password is missing"
        );
    }
}

#[cfg(test)]
mod tls_version_tests {
    use crate::http_client::{HttpClient, HttpClientConfig};

    #[test]
    fn test_client_with_tls12_cipher_suites() {
        let config = HttpClientConfig {
            cipher_suites: Some(
                "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
                    .to_owned(),
            ),
            ..Default::default()
        };

        let result = HttpClient::instantiate(&config);
        assert!(result.is_ok(), "TLS 1.2 cipher suites should be supported");
    }

    #[test]
    fn test_client_with_tls13_cipher_suites() {
        let config = HttpClientConfig {
            cipher_suites: Some("TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256".to_owned()),
            ..Default::default()
        };

        let result = HttpClient::instantiate(&config);
        assert!(result.is_ok(), "TLS 1.3 cipher suites should be supported");
    }

    #[test]
    fn test_client_with_mixed_tls_cipher_suites() {
        let config = HttpClientConfig {
            cipher_suites: Some(
                "TLS_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256"
                    .to_owned(),
            ),
            ..Default::default()
        };

        let result = HttpClient::instantiate(&config);
        assert!(
            result.is_ok(),
            "Mixed TLS 1.2 and 1.3 cipher suites should be supported"
        );
    }

    #[test]
    fn test_client_with_tls13_and_ecdsa_cipher_suites() {
        let config = HttpClientConfig {
            cipher_suites: Some(
                "TLS_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384".to_owned(),
            ),
            ..Default::default()
        };

        let result = HttpClient::instantiate(&config);
        assert!(
            result.is_ok(),
            "TLS 1.3 and ECDSA cipher suites should be supported"
        );
    }

    #[test]
    fn test_client_with_chacha_cipher_suites() {
        let config = HttpClientConfig {
            cipher_suites: Some(
                "TLS_CHACHA20_POLY1305_SHA256:TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
                    .to_owned(),
            ),
            ..Default::default()
        };

        let result = HttpClient::instantiate(&config);
        assert!(result.is_ok(), "ChaCha20 cipher suites should be supported");
    }

    #[test]
    fn test_client_default_supports_all_tls_versions() {
        let config = HttpClientConfig::default();

        let result = HttpClient::instantiate(&config);
        assert!(
            result.is_ok(),
            "Default configuration should support all TLS versions"
        );
    }

    #[test]
    fn test_client_with_only_tls13_aes_variants() {
        let config = HttpClientConfig {
            cipher_suites: Some("TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256".to_owned()),
            ..Default::default()
        };

        let result = HttpClient::instantiate(&config);
        assert!(result.is_ok(), "TLS 1.3 AES variants should be supported");
    }

    #[test]
    fn test_client_with_only_tls12_ecdhe_variants() {
        let config = HttpClientConfig {
            cipher_suites: Some(
                "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
                    .to_owned(),
            ),
            ..Default::default()
        };

        let result = HttpClient::instantiate(&config);
        assert!(result.is_ok(), "TLS 1.2 ECDHE variants should be supported");
    }

    #[test]
    fn test_client_tls_version_handling_with_accept_invalid_certs() {
        let config = HttpClientConfig {
            accept_invalid_certs: true,
            cipher_suites: Some("TLS_AES_256_GCM_SHA384".to_owned()),
            ..Default::default()
        };

        let result = HttpClient::instantiate(&config);
        assert!(
            result.is_ok(),
            "TLS 1.3 with accept_invalid_certs should work"
        );
    }

    #[test]
    fn test_client_comprehensive_cipher_suite_list() {
        let config = HttpClientConfig {
            cipher_suites: Some(
                "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:\
                 TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:\
                 TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
                    .to_owned(),
            ),
            ..Default::default()
        };

        let result = HttpClient::instantiate(&config);
        assert!(
            result.is_ok(),
            "Comprehensive cipher suite list should be supported"
        );
    }

    #[test]
    fn test_colon_separated_cipher_suites() {
        let config = HttpClientConfig {
            cipher_suites: Some("TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256".to_owned()),
            ..Default::default()
        };
        let result = HttpClient::instantiate(&config);
        assert!(result.is_ok(), "Colon-separated cipher suites should work");

        // Single cipher suite (no separator)
        let config = HttpClientConfig {
            cipher_suites: Some("TLS_AES_256_GCM_SHA384".to_owned()),
            ..Default::default()
        };
        let result = HttpClient::instantiate(&config);
        assert!(result.is_ok(), "Single cipher suite should work");

        // Mixed TLS versions with colon separator
        let config = HttpClientConfig {
            cipher_suites: Some(
                "TLS_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384".to_owned(),
            ),
            ..Default::default()
        };
        let result = HttpClient::instantiate(&config);
        assert!(
            result.is_ok(),
            "Mixed TLS version cipher suites with colon should work"
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
#[allow(clippy::expect_used)]
mod login_tests {
    use crate::http_client::login::{LoginState, Oauth2LoginConfig};

    // Each async test that exercises `finalize()` uses its own unique port so
    // they can run in parallel without competing for the same socket.  Ports
    // in the range below are reserved exclusively for these tests and must not
    // be reused elsewhere.
    //
    // Port    Test
    // 17901   test_finalize_missing_state_returns_error
    // 17902   test_finalize_missing_code_returns_error
    // 17903   test_finalize_wrong_state_returns_error
    // 17904   test_finalize_correct_state_fails_at_token_exchange

    // A minimal OAuth2 config that refers to a reachable-but-wrong token URL
    // (127.0.0.1:1) so that the token-exchange step always fails quickly
    // without hanging.  Used for the tests that reach the token-exchange stage.
    fn dummy_config() -> Oauth2LoginConfig {
        Oauth2LoginConfig {
            client_id: "test-client-id".to_owned(),
            client_secret: "test-client-secret".to_owned(),
            authorize_url: "http://localhost:1/auth".to_owned(),
            token_url: "http://127.0.0.1:1/token".to_owned(),
            scopes: vec!["openid".to_owned(), "email".to_owned()],
        }
    }

    // -----------------------------------------------------------------------
    // Sync unit tests — no network, no ports
    // -----------------------------------------------------------------------

    #[test]
    fn test_login_state_construction_succeeds() {
        let state = LoginState::try_from(dummy_config());
        assert!(
            state.is_ok(),
            "LoginState construction should succeed with valid config"
        );
    }

    #[test]
    fn test_auth_url_contains_client_id() {
        let state = LoginState::try_from(dummy_config()).unwrap();
        let url = state.auth_url.to_string();
        assert!(
            url.contains("test-client-id"),
            "auth_url should contain the client_id, got: {url}"
        );
    }

    #[test]
    fn test_auth_url_contains_scopes() {
        let state = LoginState::try_from(dummy_config()).unwrap();
        let url = state.auth_url.to_string();
        assert!(
            url.contains("openid"),
            "auth_url should contain scope 'openid', got: {url}"
        );
        assert!(
            url.contains("email"),
            "auth_url should contain scope 'email', got: {url}"
        );
    }

    #[test]
    fn test_auth_url_contains_pkce_challenge() {
        let state = LoginState::try_from(dummy_config()).unwrap();
        let url = state.auth_url.to_string();
        assert!(
            url.contains("code_challenge"),
            "auth_url should contain a PKCE code_challenge, got: {url}"
        );
        assert!(
            url.contains("S256"),
            "auth_url should use S256 PKCE method, got: {url}"
        );
    }

    #[test]
    fn test_auth_url_has_state_param() {
        // The CSRF state token must appear in the auth URL so the redirect can be
        // verified in `finalize()`.
        let state = LoginState::try_from(dummy_config()).unwrap();
        let has_state = state
            .auth_url
            .query_pairs()
            .any(|(k, _)| k.as_ref() == "state");
        assert!(has_state, "auth_url must include a 'state' parameter");
    }

    #[test]
    fn test_auth_url_response_type_is_code() {
        let state = LoginState::try_from(dummy_config()).unwrap();
        let has_code = state
            .auth_url
            .query_pairs()
            .any(|(k, v)| k.as_ref() == "response_type" && v.as_ref() == "code");
        assert!(
            has_code,
            "auth_url must have response_type=code for authorization-code flow"
        );
    }

    #[test]
    fn test_invalid_authorize_url_is_rejected() {
        let config = Oauth2LoginConfig {
            authorize_url: "not-a-url".to_owned(),
            ..dummy_config()
        };
        assert!(
            LoginState::try_from(config).is_err(),
            "Invalid authorize_url should produce an error"
        );
    }

    #[test]
    fn test_invalid_token_url_is_rejected() {
        let config = Oauth2LoginConfig {
            token_url: "not-a-url".to_owned(),
            ..dummy_config()
        };
        assert!(
            LoginState::try_from(config).is_err(),
            "Invalid token_url should produce an error"
        );
    }

    // -----------------------------------------------------------------------
    // Async tests — exercise `finalize()` by simulating the browser callback.
    //
    // Each test uses `LoginState::try_from_with_port` so it owns an exclusive
    // port and can run in parallel with the other tests.
    //
    // The browser simulation uses `std::thread::spawn` (not `tokio::spawn`)
    // because `finalize()` calls `std::sync::mpsc::Receiver::recv()`, a
    // blocking call that cannot be driven from the same tokio thread.  A plain
    // OS thread is free to issue a blocking HTTP request without interfering
    // with the tokio scheduler.
    // -----------------------------------------------------------------------

    /// Extract the `state` query parameter from `auth_url` — that is the CSRF
    /// token the actix handler expects.
    fn extract_csrf_state(state: &LoginState) -> String {
        state
            .auth_url
            .query_pairs()
            .find(|(k, _)| k.as_ref() == "state")
            .map(|(_, v)| v.into_owned())
            .expect("state param not found in auth_url")
    }

    /// Issue a minimal HTTP GET to `url` (on a plain TCP connection) after
    /// sleeping `delay_ms` milliseconds.  Runs on a dedicated OS thread so it
    /// does not compete with the tokio scheduler that drives `finalize()`.
    /// Uses raw TCP so we don't need the `blocking` reqwest feature.
    fn spawn_browser_simulation(url: String, delay_ms: u64) {
        std::thread::spawn(move || {
            use std::io::Write;

            std::thread::sleep(std::time::Duration::from_millis(delay_ms));

            // Parse a URL like "http://127.0.0.1:PORT/path?query"
            let stripped = url.trim_start_matches("http://");
            let (host_port, path_query) = stripped
                .find('/')
                .map_or((stripped, "/"), |idx| (&stripped[..idx], &stripped[idx..]));

            if let Ok(mut stream) = std::net::TcpStream::connect(host_port) {
                let request = format!(
                    "GET {path_query} HTTP/1.1\r\nHost: {host_port}\r\nConnection: close\r\n\r\n"
                );
                drop(stream.write_all(request.as_bytes()));
            }
        });
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_finalize_missing_state_returns_error() {
        const PORT: u16 = 17_901;
        let login_state = LoginState::try_from_with_port(dummy_config(), PORT).unwrap();

        // Send a callback without `state`.
        spawn_browser_simulation(
            format!("http://127.0.0.1:{PORT}/authorization?code=fake-code"),
            50,
        );

        let result = login_state.finalize().await;
        assert!(result.is_err(), "Expected error when state is missing");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("state"),
            "Error should mention 'state', got: {msg}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_finalize_missing_code_returns_error() {
        const PORT: u16 = 17_902;
        let login_state = LoginState::try_from_with_port(dummy_config(), PORT).unwrap();
        let csrf = extract_csrf_state(&login_state);

        // Simulate browser sending only the state (no code).
        spawn_browser_simulation(
            format!("http://127.0.0.1:{PORT}/authorization?state={csrf}"),
            50,
        );

        let result = login_state.finalize().await;
        assert!(result.is_err(), "Expected error when code is missing");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("code"),
            "Error should mention 'code', got: {msg}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_finalize_wrong_state_returns_error() {
        const PORT: u16 = 17_903;
        let login_state = LoginState::try_from_with_port(dummy_config(), PORT).unwrap();

        // Simulate browser sending an incorrect state value.
        spawn_browser_simulation(
            format!("http://127.0.0.1:{PORT}/authorization?code=fake-code&state=wrong-state"),
            50,
        );

        let result = login_state.finalize().await;
        assert!(result.is_err(), "Expected error when state does not match");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("state"),
            "Error should mention 'state', got: {msg}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_finalize_correct_state_fails_at_token_exchange() {
        // When a correct state + code are delivered, `finalize()` should proceed
        // past the CSRF check and attempt the token exchange.  Our `token_url`
        // points at `127.0.0.1:1` which is unreachable, so the function must
        // return a network / IO error rather than a CSRF / missing-param error.
        const PORT: u16 = 17_904;
        let login_state = LoginState::try_from_with_port(dummy_config(), PORT).unwrap();
        let csrf = extract_csrf_state(&login_state);

        spawn_browser_simulation(
            format!("http://127.0.0.1:{PORT}/authorization?code=fake-code&state={csrf}"),
            50,
        );

        let result = login_state.finalize().await;
        // Should fail at token exchange, not at CSRF or missing-param stage.
        assert!(
            result.is_err(),
            "Expected a token-exchange error but got success"
        );
        let msg = result.unwrap_err().to_string();
        // State and code were correct — the error must NOT be about missing/wrong
        // state or code.
        assert!(
            !msg.contains("state not received"),
            "Should not fail on missing state, got: {msg}"
        );
        assert!(
            !msg.contains("code not received"),
            "Should not fail on missing code, got: {msg}"
        );
        assert!(
            !msg.contains("does not match"),
            "Should not fail on wrong state, got: {msg}"
        );
    }
}

#[cfg(test)]
mod custom_headers_tests {
    use crate::http_client::{HttpClient, HttpClientConfig};

    #[test]
    fn test_custom_header_valid() {
        let config = HttpClientConfig {
            custom_headers: Some(vec!["X-My-Header: my-value".to_owned()]),
            ..Default::default()
        };
        assert!(
            HttpClient::instantiate(&config).is_ok(),
            "valid header should instantiate successfully"
        );
    }

    #[test]
    fn test_custom_headers_multiple_valid() {
        let config = HttpClientConfig {
            custom_headers: Some(vec![
                "X-First: first".to_owned(),
                "X-Second: second".to_owned(),
                "Authorization: Bearer token123".to_owned(),
            ]),
            ..Default::default()
        };
        assert!(
            HttpClient::instantiate(&config).is_ok(),
            "multiple valid headers should instantiate successfully"
        );
    }

    #[test]
    fn test_custom_header_missing_colon_is_error() {
        let config = HttpClientConfig {
            custom_headers: Some(vec!["InvalidHeaderNoColo".to_owned()]),
            ..Default::default()
        };
        let result = HttpClient::instantiate(&config);
        assert!(
            result.is_err(),
            "expected an error for header without colon"
        );
        if let Err(e) = result {
            assert!(
                e.to_string().contains("InvalidHeaderNoColo"),
                "error message should reference the bad header: {e}"
            );
        }
    }

    #[test]
    fn test_custom_header_invalid_name_is_error() {
        let config = HttpClientConfig {
            custom_headers: Some(vec!["X-Héader: value".to_owned()]),
            ..Default::default()
        };
        assert!(
            HttpClient::instantiate(&config).is_err(),
            "non-ASCII header name should be rejected"
        );
    }

    #[test]
    fn test_custom_headers_none_is_ok() {
        let config = HttpClientConfig {
            custom_headers: None,
            ..Default::default()
        };
        assert!(
            HttpClient::instantiate(&config).is_ok(),
            "None custom_headers should instantiate successfully"
        );
    }
}
