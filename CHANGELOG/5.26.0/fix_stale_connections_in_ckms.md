## Bug Fixes

### Client

- Retry HTTP requests once on stale pooled connections (`client error (Connect)`), fixing intermittent failures for long-lived `KmsClient` instances caused by server-side keep-alive timeouts ([#1056](https://github.com/Cosmian/kms/issues/1056))
