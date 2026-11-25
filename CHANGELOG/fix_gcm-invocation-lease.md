## Bug Fixes

### Server

- Fix the AES-GCM encrypt throughput regression introduced with the invocation counter (up to −65 % under concurrency on the nightly benchmark): invocations are now leased from the store in blocks of 4096 per key and node, so the store is written once per block instead of once per encryption. The SP 800-38D §8.3 limit is still enforced before use; the unused rest of a block is lost when the node stops, so the recorded count can exceed the real one by at most 4095 per key and node run.
