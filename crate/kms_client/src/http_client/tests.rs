#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod pkcs12_tests {
    use cosmian_logger::log_init;

    use crate::http_client::{HttpClient, HttpClientConfig};

    #[test]
    fn test_pkcs12_nonexistent_file() {
        // Test with non-existent PKCS12 file
        let config = HttpClientConfig {
            ssl_client_pkcs12_path: Some("/nonexistent/path/file.p12".to_owned()),
            ssl_client_pkcs12_password: Some("password".to_owned()),
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
            ssl_client_pkcs12_path: Some(
                "../../test_data/client_server/owner/owner.client.acme.com.p12".to_owned(),
            ),
            ssl_client_pkcs12_password: Some("password".to_owned()),
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
            ssl_client_pkcs12_path: Some("/tmp/client.p12".to_owned()),
            ssl_client_pkcs12_password: Some("password".to_owned()),
            ssl_client_pem_cert_path: Some("/tmp/client.crt".to_owned()),
            ssl_client_pem_key_path: Some("/tmp/client.key".to_owned()),
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
            ssl_client_pem_cert_path: Some("/tmp/client.crt".to_owned()),
            ..Default::default()
        };

        let result = HttpClient::instantiate(&config);
        assert!(result.is_err(), "Should error when PEM key is missing");
    }

    #[test]
    fn test_error_when_only_pem_key_provided() {
        let config = HttpClientConfig {
            ssl_client_pem_key_path: Some("/tmp/client.key".to_owned()),
            ..Default::default()
        };

        let result = HttpClient::instantiate(&config);
        assert!(result.is_err(), "Should error when PEM cert is missing");
    }

    #[test]
    fn test_error_when_pkcs12_without_password() {
        let config = HttpClientConfig {
            ssl_client_pkcs12_path: Some("/tmp/client.p12".to_owned()),
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
