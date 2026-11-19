## Features

### `/health` for load balancers: strict mode and KMIP socket check ([#1366](https://github.com/Cosmian/kms/issues/1366))

- `GET /health?strict=true` answers HTTP 503 for a `DEGRADED` node as well as for a `DOWN` one, so that a load balancer
  or Keepalived takes out a node whose HSM does not answer. Without `strict=true`, `DEGRADED` still answers 200. The body
  is the same in both cases.
- When the KMIP socket server is enabled, `/health` reports it as a `kmip` dependency, and a node whose socket server
  has stopped is `DEGRADED`. The check looks at the socket server task: it does not open a connection to the KMIP port.

## Security

- The `message` of a `DOWN` dependency in the public `GET /health` is now a fixed text. The detail of the error (database
  driver text with host, user or file paths, PKCS#11 return code) is written to the server log as `health check: ...`
  instead of being returned to any caller.

## Documentation

- The [Cluster coordination](documentation/docs/installation/cluster_coordination.md),
  [High availability and deployment profiles](documentation/docs/installation/high_availability_mode.md) and OpenAPI
  pages describe `strict` and the `kmip` dependency. The Keepalived-only configuration uses `?strict=true`.
