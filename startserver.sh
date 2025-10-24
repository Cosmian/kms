RUST_LOG="info,cosmian_kms_server=debug" \
cargo run --bin cosmian_kms --features non-fips -- \
--database-type redis-findex --database-url redis://localhost:6379 \
--redis-master-password secret --redis-findex-label label