# Security Policy

## Reporting a Vulnerability

We take the security of Cosmian KMS seriously. If you discover a security vulnerability, please report it responsibly by following these steps:

### Private Reporting

Please **do not** report security vulnerabilities through public GitHub issues. Instead, please use one of the following methods:

1. **GitHub Security Advisories** (Preferred): Use the [private vulnerability reporting feature](https://github.com/Cosmian/kms/security/advisories/new) on GitHub
2. **Email**: Send details to [tech@cosmian.com](mailto:tech@cosmian.com)

### What to Include

When reporting a vulnerability, please include as much of the following information as possible:

- A clear description of the vulnerability
- Steps to reproduce the issue
- Potential impact of the vulnerability
- Suggested fix (if you have one)
- Your contact information

### Response Timeline

- **Initial Response**: We will acknowledge receipt of your vulnerability report within 48 hours
- **Investigation**: We will investigate and validate the vulnerability within 5 business days
- **Fix Development**: We will work to develop and test a fix as quickly as possible
- **Disclosure**: We will coordinate the disclosure timeline with you

## Known Security Advisories

The following table lists security advisories that are currently being tracked or have been assessed for this project:

| ID                | Description                                              | Status  | Reason                                                   |
| ----------------- | -------------------------------------------------------- | ------- | -------------------------------------------------------- |
| RUSTSEC-2023-0071 | RSA crate vulnerability affecting signature verification | Ignored | Under evaluation - specific use case may not be affected |

### Advisory Details

**RUSTSEC-2023-0071**: This advisory affects the RSA crate used for cryptographic operations. The vulnerability relates to signature verification processes. This advisory is currently ignored as our security team is evaluating whether the specific usage patterns in Cosmian KMS are affected by this vulnerability.

## Security Best Practices

When using Cosmian KMS, we recommend:

1. **Keep Updated**: Always use the latest supported version
2. **Secure Configuration**: Follow the security configuration guidelines in our documentation
3. **Network Security**: Deploy KMS behind appropriate network security controls
4. **Access Control**: Implement proper authentication and authorization mechanisms
5. **Monitoring**: Enable logging and monitoring for security events

## FIPS Compliance

Cosmian KMS supports FIPS 140-3 compliance when built with FIPS features enabled. KMS links against OpenSSL 3.6.0, but the FIPS build still uses the OpenSSL 3.1.2 FIPS provider for cryptographic operations because it is the official FIPS provider version available today (no more recent FIPS provider version).

## Security Audits

This project undergoes regular security assessments. The configuration files `.cargo/audit.toml` and `deny.toml` are maintained to track and manage security advisories affecting our dependencies.

## Contact

For general security questions or concerns, please contact us at [tech@cosmian.com](mailto:tech@cosmian.com).

For immediate security issues, please use the private reporting methods described above.
