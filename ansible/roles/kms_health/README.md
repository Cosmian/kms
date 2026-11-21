# kms_health

Waits until the KMS `/health` endpoint answers `200`. Use it after `kms_server`
to make a play fail early when the server does not start.

## Variables

| Variable                    | Default                        | Description                                 |
|-----------------------------|--------------------------------|---------------------------------------------|
| `kms_health_url`            | `http://localhost:9998/health` | Health endpoint to poll.                    |
| `kms_health_validate_certs` | `true`                         | Validate the TLS certificate of the server. |
| `kms_health_retries`        | `30`                           | Number of attempts.                         |
| `kms_health_delay`          | `2`                            | Seconds between attempts.                   |

## Example

```yaml
- hosts: kms_servers
  roles:
    - role: cosmian.kms.kms_health
      vars:
        kms_health_url: https://localhost:9998/health
```
