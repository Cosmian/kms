# Logging

By default, the Cosmian KMS server outputs logs to the console with a log level of INFO. You can
change the log level and send traces to an [OpenTelemetry](https://opentelemetry.io/) collector.

## Adjusting the log level

The log level can be adjusted by setting the `RUST_LOG` environment variable. The following log
levels are available: `trace`, `debug`, `info`, `warn`, `error`.

The default value is set to

```bash
RUST_LOG=info,cosmian=info,cosmian_kms_server=info,actix_web=info,sqlx::query=error,mysql=info"
```

The first `info` specifies the default log level for the crates (packages) that compose
the server. Other log levels can be set for specific crates by adding the crate name followed by
the log level.

To get detailed logs of user requests, set the log level of `cosmian_kms_server` to
`debug`:

```bash
RUST_LOG=info,cosmian=info,cosmian_kms_server=debug,actix_web=info,sqlx::query=error,mysql=info"
```

To debug HTTP issues, set the log level of `actix_web` to `debug`:

```bash
RUST_LOG=info,cosmian=info,cosmian_kms_server=info,actix_web=debug,sqlx::query=error,mysql=info"
```

**WARNING**: Setting the log level to `debug` or `trace` may leak sensitive information in the
logs

## Using the OTLP telemetry

The server can send traces to an [OpenTelemetry](https://opentelemetry.io/) collector that
supports the OTLP protocol.
To enable this feature, set the `--otlp` command line argument or `KMS_OTLP_URL` environment
variable to the URL of the collector. For example:

```bash
KMS_OTLP_URL="http://localhost:4317"
```

The traces will contain the following information:

- the start configuration of the KMS server
- the KMIP requests
- the requests that are linked to access-rights management

The content of the traces is adjusted by the log level set above.

In addition, logs to the console can be disabled by setting the `--quiet` command line argument or
`KMS_LOG_QUIET` environment variable to `true`.

To test the OpenTelemetry collector, start a Jaeger server with the following command:

```bash
docker run  -p16686:16686 -p4317:4317 -e COLLECTOR_OTLP_ENABLED=true jaegertracing/all-in-one:latest
```

Then start the KMS locally with the following command:

```bash
./cosmian_kms_server --otlp http://localhost:4317 --quiet
```
