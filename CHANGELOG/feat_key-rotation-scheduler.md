## Features

- Add background auto-rotation scheduler (cron thread) that periodically checks for keys due for rotation and rotates them automatically
- Add `--auto-rotation-check-interval-secs` server CLI flag (default: 0 = disabled)
- Add `find_due_for_rotation` database method (SQLite, PostgreSQL, MySQL) to find Active objects past their rotation interval
- Implement `auto_rotate_key` logic supporting SymmetricKey (ReKey), PrivateKey/PublicKey (CreateKeyPair or CoverCrypt ReKeyKeyPair), and Certificate (Certify) rotation
- Transfer rotation policy to new keys and set `ReplacementObjectLink`/`ReplacedObjectLink` cross-links on rotation
