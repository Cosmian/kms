# Log output

The Eviden KMS server outputs logs to the console by default at `INFO` level.

> **For OTLP metrics & traces**: see [Metrics & Traces (OTLP)](./otlp-telemetry.md).
> **For the monitoring stack** (Grafana, VictoriaMetrics, OTel Collector): see [Monitoring stack setup](./monitoring-setup.md).
> **For audit logging** (compliance, SIEM): see [Audit logging](./audit-logs.md).
> **For every log call-site across all components**: see [Log call-site reference](./log-reference.md).

---

## Adjusting the log level

The log level can be adjusted by setting either:

- the `RUST_LOG` environment variable,
- the `rust_log` setting in the TOML configuration file in the `[logging]` section,
- the `--rust-log` command line argument.

Available levels: `trace`, `debug`, `info`, `warn`, `error`. The default is `info`.

Example:

```bash
RUST_LOG=info,cosmian=info,cosmian_kms_server=info,actix_web=info,mysql=info
```

The first `info` sets the default log level for all crates. Individual crates can be overridden:

- To get detailed logs of user requests, set `cosmian_kms_server` to `debug`:

```bash
RUST_LOG=info,cosmian=info,cosmian_kms_server=debug,actix_web=info,mysql=info
```

- To debug HTTP issues, set `actix_web` to `debug`:

```bash
RUST_LOG=info,cosmian=info,cosmian_kms_server=info,actix_web=debug,mysql=info
```

> **⚠️ WARNING:** Setting the log level to `debug` or `trace` may leak sensitive information
> in the logs.

---

## Console and syslog logging

Logging to the console is enabled by default. It can be disabled via:

- the `quiet` parameter in the TOML configuration file in the `[logging]` section,
- the `--quiet` command line argument,
- the `KMS_LOG_QUIET` environment variable set to `true`.

On Linux, logs can be redirected to syslog instead of stdout by setting:

- the `log_to_syslog` parameter in the TOML configuration file in the `[logging]` section,
- the `--log-to-syslog` command line argument,
- the `KMS_LOG_TO_SYSLOG` environment variable set to `true`.

---

## Rolling log files

The server can write daily rolling log files. File logging is **disabled** unless
`rolling_log_dir` is explicitly configured (via `--rolling-log-dir`, the
`KMS_ROLLING_LOG_DIR` environment variable, or the TOML configuration).

Log files are named `<name>.YYYY-MM-DD`, where `<name>` defaults to `kms`.

When `rolling_log_dir` is set without specifying a path (e.g. via the
configuration wizard), the recommended platform-specific defaults are:

| Platform | Default directory                                        |
| -------- | ------------------------------------------------------- |
| Linux    | `/var/log/`                                             |
| Windows  | `C:\\Users\\<username>\\AppData\\Local\\Eviden KMS Server` |
| macOS    | `~/Library/Logs/`                                       |

> **Warning (Windows):** The server does **not** expand Windows environment variables
> such as `%LOCALAPPDATA%` in configuration files. If you override `rolling_log_dir`
> in `kms.toml`, you must use the fully-expanded path, for example:
>
> ```toml
> rolling_log_dir = "C:\\\\Users\\\\<username>\\\\AppData\\\\Local\\\\Eviden KMS Server"
> ```
>
> When `rolling_log_dir` is not set, the server resolves the `LOCALAPPDATA`
> environment variable at runtime and defaults to
> `C:\\Users\\<username>\\AppData\\Local\\Eviden KMS Server`.
> When running as a Windows service under LocalSystem, the variable may not be set;
> the server then falls back to `C:\\ProgramData\\Eviden KMS Server`.
>
> **Note (macOS):** The server defaults to `~/Library/Logs/` which is the standard
> per-user log directory on macOS and is writable without root. If you run the server
> as a LaunchDaemon (root), you may override this with
> `--rolling-log-dir /Library/Logs/`.
>
> **Graceful fallback:** If the configured rolling log directory does not exist and cannot
> be created, or is not writable by the current process, the server disables file logging
> with a warning message on stderr and continues operating normally. This prevents the
> server from panicking due to inaccessible log paths.

The directory and file name can be overridden via:

- the `rolling_log_dir` / `rolling_log_name` entries in the TOML configuration
  file (`[logging]` section),
- the `--rolling-log-dir` / `--rolling-log-name` command line arguments,
- the `KMS_ROLLING_LOG_DIR` / `KMS_ROLLING_LOG_NAME` environment variables.
