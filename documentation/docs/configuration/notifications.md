# Notifications

The Cosmian KMS server ships a built-in notification system that keeps operators and key owners
informed when key auto-rotation events occur (both successes and failures).

Notifications are delivered through two independent channels:

| Channel | Availability | Description |
|---------|-------------|-------------|
| **In-app** | Always enabled | Events are persisted in the KMS database and surfaced in the Web UI |
| **Email** | Optional | Events are emailed via SMTP when an SMTP server is configured |

---

## In-app notifications

Every key auto-rotation event (success or failure) is written to a `notifications` table in
the KMS database. Users can view their own notifications through:

- **Web UI**: a bell icon in the top-right header displays the number of unread events; clicking
  it navigates to the `/notifications` page where events can be read and marked as processed.
- **REST API**: four endpoints allow programmatic access (see below).

The unread count is refreshed automatically every 60 seconds in the UI.

### REST API

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/notifications?page=0&page_size=20` | List notifications for the authenticated user |
| `GET` | `/notifications/count` | Return `{"unread": N}` for the authenticated user |
| `POST` | `/notifications/{id}/read` | Mark a single notification as read |
| `POST` | `/notifications/read-all` | Mark all notifications as read |

The list response includes:

```json
{
  "items": [
    {
      "id": 42,
      "event_type": "key_rotation_success",
      "message": "Key abc rotated successfully (generation 3)",
      "object_id": "abc",
      "created_at": "2025-04-14T10:00:00Z",
      "read_at": null
    }
  ],
  "total_unread": 1,
  "page": 0,
  "page_size": 20
}
```

---

## Email notifications

Email notifications are sent for each rotation event when an SMTP host is configured at runtime.
No special build flag is required — SMTP support is compiled in by default.

### Configuration

SMTP parameters are grouped under a `[notifications.smtp]` section in the TOML configuration
file, or set as environment variables:

| TOML key (under `[notifications.smtp]`) | Environment variable | Default | Description |
|----------------------------------------|---------------------|---------|-------------|
| `host` | `KMS_SMTP_HOST` | *(none — disables email)* | SMTP server hostname |
| `port` | `KMS_SMTP_PORT` | `587` | SMTP server port (STARTTLS) |
| `username` | `KMS_SMTP_USERNAME` | *(none)* | SMTP authentication username |
| `password` | `KMS_SMTP_PASSWORD` | *(none)* | SMTP authentication password |
| `from` | `KMS_SMTP_FROM` | *(none)* | Sender address |
| `to` | `KMS_SMTP_TO` | *(none)* | Comma-separated list of recipient addresses |

If `host` is not set, email notifications are silently disabled — no error is reported and
the server starts normally.

### TOML example

```toml
# Outbound notification channels.
# Additional channels (webhook, Slack, PagerDuty, …) can be added under
# [notifications] in a future release without affecting existing configurations.
[notifications.smtp]
# SMTP server hostname
host = "smtp.example.com"

# SMTP server port (587 for STARTTLS, 465 for implicit TLS, 25 for plaintext)
port = 587

# SMTP credentials — omit if the server does not require authentication
username = "kms-alerts@example.com"
password = "s3cr3t"

# Sender address shown in the From: header
from = "kms-alerts@example.com"

# Comma-separated list of recipient addresses
to = "ops-team@example.com,security@example.com"
```

### Environment variable example

```bash
export KMS_SMTP_HOST=smtp.example.com
export KMS_SMTP_PORT=587
export KMS_SMTP_USERNAME=kms-alerts@example.com
export KMS_SMTP_PASSWORD=s3cr3t
export KMS_SMTP_FROM=kms-alerts@example.com
export KMS_SMTP_TO=ops-team@example.com,security@example.com
cosmian_kms -c /etc/cosmian/kms.toml
```

### Connection security

The email transport uses **STARTTLS** (opportunistic TLS upgrade on the configured port).
Port `587` is the recommended default for submission relays. For implicit TLS (port `465`), set
`smtp_port = 465`.

### Testing with a local mock SMTP server

During development and integration testing, use [MailHog](https://github.com/mailhog/MailHog)
or [Mailpit](https://github.com/axllent/mailpit) as a drop-in local SMTP relay with a
built-in web UI:

```bash
# Option A — MailHog (Docker)
docker run -d -p 1025:1025 -p 8025:8025 mailhog/mailhog

# Option B — Mailpit (Docker)
docker run -d -p 1025:1025 -p 8025:8025 axllent/mailpit
```

Both tools listen on port `1025` (SMTP, no authentication) and expose a web UI on port `8025`
where you can read captured emails.

Configure the KMS server to use the local mock:

```toml
[notifications.smtp]
host = "127.0.0.1"
port = 1025
from = "kms@test.local"
to   = "dev@test.local"
```

Or using environment variables:

```bash
KMS_SMTP_HOST=127.0.0.1 KMS_SMTP_PORT=1025 \
KMS_SMTP_FROM=kms@test.local KMS_SMTP_TO=dev@test.local \
cosmian_kms -c ./test_data/configs/server/smtp_notifications.toml
```

---

## Notification event types

| Event type | Trigger |
|-----------|---------|
| `key_rotation_success` | A key was successfully rotated by the background cron |
| `key_rotation_failure` | The background cron attempted to rotate a key but the operation failed |

---

## Database schema

The `notifications` table is created automatically on server start for SQLite, PostgreSQL, and MySQL backends:

```sql
CREATE TABLE IF NOT EXISTS notifications (
    id         INTEGER PRIMARY KEY,  -- BIGSERIAL in PostgreSQL
    user_id    VARCHAR(255) NOT NULL,
    event_type VARCHAR(64)  NOT NULL,
    message    TEXT         NOT NULL,
    object_id  VARCHAR(128),
    created_at TEXT         NOT NULL, -- ISO-8601 UTC timestamp
    read_at    TEXT                   -- NULL when unread
);
```

> The `notifications` table is not available on the Redis-Findex backend. Notification API calls
> on a Redis-Findex instance silently return empty results.
