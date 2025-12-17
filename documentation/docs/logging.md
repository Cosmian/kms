# Logging

By default, the Cosmian KMS server outputs logs to the console with a log level of INFO. You can
change the log level and send traces to an [OpenTelemetry](https://opentelemetry.io/) collector.

## Adjusting the log level

The log level can be adjusted by setting either:

- the `RUST_LOG` environment variable. The following log
- the `rust_log` setting in the TOML configuration file in the `[logging]` section.
- the `--rust-log` command line argument.

The available levels are: `trace`, `debug`, `info`, `warn`, `error`.

The default value is set to `info`.

Example of setting the log level using the `RUST_LOG` environment variable:

```bash
RUST_LOG=info,cosmian=info,cosmian_kms_server=info,actix_web=info,mysql=info"
```

The first `info` specifies the default log level for the crates (packages) that compose
the server. Other log levels can be set for specific crates by adding the crate name followed by
the log level.

To get detailed logs of user requests, set the log level of `cosmian_kms_server` to
`debug`:

```bash
RUST_LOG=info,cosmian=info,cosmian_kms_server=debug,actix_web=info,mysql=info"
```

To debug HTTP issues, set the log level of `actix_web` to `debug`:

```bash
RUST_LOG=info,cosmian=info,cosmian_kms_server=info,actix_web=debug,mysql=info"
```

**WARNING**: Setting the log level to `debug` or `trace` may leak sensitive information in the
logs

## Console and syslog logging

Logging to the console is enabled by default, but can be disabled by setting either:

- the `quiet` parameter in the TOML configuration file in the `[logging]` section,
- the `--quiet` command line argument
- the `KMS_LOG_QUIET` environment variable to `true`.

Instead of being sent to stdout on Linux, the logs can be sent to syslog by setting either:

- the `log_to_syslog` parameter in the TOML configuration file in the `[logging]` section,
- the `--log-to-syslog` command line argument
- the `KMS_LOG_TO_SYSLOG` environment variable to `true`.

## Rolling log files

It is also possible to enable logging to a daily rolling file by setting the directory hosting
the log files using either the `rolling_log_dir` entry of the TOML configuration file, or the
`--rolling-log-dir` command line argument.

Files will be named `<name>.YYYY-MM-DD` where `<name>` defaults to `kms`. The name can be changed
using the `rolling_log_name` entry of the TOML configuration file, or the `--rolling-log-name`
command line argument.

## Using the OTLP telemetry

The server can send traces to an [OpenTelemetry](https://opentelemetry.io/) collector that supports the OTLP protocol.
To enable this feature, set either:

- the `oltp` parameter in the TOML configuration file in the `[logging]` section,
- the `--otlp` command line argument
- the `KMS_OTLP_URL` environment variable
  to the URL of the collector. For example:

```bash
KMS_OTLP_URL="http://localhost:4317"
```

The traces will contain the following information:

- The start configuration of the KMS server
- The KMIP requests
- The requests that are linked to access rights management

The content of the traces is adjusted by the log level set above.

The traces will also contain metering events if the `enable_metering` feature is enabled.

### Testing the telemetry

To test the OpenTelemetry collector, start a Jaeger server with the following command:

=== "Docker"

  ```bash
  docker run  -p16686:16686 -p4317:4317 -e COLLECTOR_OTLP_ENABLED=true jaegertracing/all-in-one:latest
  ```

=== "kms.toml"

  ```toml
  [logging]
  otlp = "http://localhost:4317"
  quiet = true
  ```

Then start the KMS locally with the following command:

```bash
./cosmian_kms_server --otlp http://localhost:4317 --quiet
```
