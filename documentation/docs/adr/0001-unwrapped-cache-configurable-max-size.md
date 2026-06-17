# Configurable UnwrappedCache max size

The `UnwrappedCache` LRU size was hardcoded to 100 entries. For XKS deployments with
~100 active keys, any access to a cold key evicts a warm one, causing continuous LRU
thrashing and forcing a full KEK unwrap on every evicted key's next request. We make the
limit configurable via a new `--unwrapped-cache-max-size` CLI flag (default: 1000) so
operators can size the cache above their active key cardinality and achieve a stable warm
state.

## Considered Options

- **Keep hardcoded 100** — simple, but silently degrades performance for any deployment
  with ≥100 keys and non-uniform access patterns.
- **Remove the LRU bound entirely** — eliminates thrashing but risks unbounded memory
  growth if key cardinality is large or keys are rotated frequently.
- **Configurable with a higher default (chosen)** — operators get explicit control;
  the default 1000 is safe for typical deployments while leaving room for growth.
