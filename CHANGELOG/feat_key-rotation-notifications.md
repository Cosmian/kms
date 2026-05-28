# Features

- Add notifications infrastructure for key auto-rotation events
    - `NotificationsStore` trait and implementations (SQLite, PostgreSQL, MySQL) for persisting in-app notifications
    - SMTP email notifier (`EmailNotifier`) using `lettre` for renewal warnings and rotation success/failure emails
    - `SmtpConfig` and `RenewalNotificationStrategy` configuration structs (`NotificationsConfig`)
    - `dispatch_renewal_warnings()` background function: scans objects approaching rotation and emits threshold-based warnings
    - `rotate_last_warning_days` attribute on `Attributes` to prevent duplicate warnings in the same cycle
    - HTTP API endpoints: `GET /notifications`, `GET /notifications/unread/count`, `POST /notifications/{id}/read`, `POST /notifications/read-all`
    - `NoopNotificationsStore` for Redis-findex backend (notifications not supported)
