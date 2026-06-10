## Features

- Add EDB PostgreSQL TDE KMIP compliance tests: proves Cosmian KMS works with
  `edb_tde_kmip_client.py` for Transparent Data Encryption key wrapping
    - Both `--variant=pykmip` and `--variant=thales` variants covered end-to-end
    using the **real** `edb_tde_kmip_client.py` inside the running EDB container
    - Test scenarios: container login/start, master key creation, DEK wrap/unwrap,
    key rotation, multiple DEK sizes, TDE encryption verification (7 tests)
    - Real integration: `docker exec kms-edb-tde-1 python3 /usr/edb/kmip/client/edb_tde_kmip_client.py`
    used for all wrap/unwrap when `EDB_SUBSCRIPTION_TOKEN` is set
- Add `create_master_key.py`: minimal 40-line Python helper that issues KMIP
  Create + Activate for an AES-256 key; replaces the 300-line simulation client
  (`edb_tde_kmip_client_sim.py` deleted).  The official `edb_tde_kmip_client.py`
  only implements `encrypt` / `decrypt` — it has no key-creation command.
- Add `edb_startup.sh`: startup script for EDB container — runs `initdb -y
  --key-wrap-command --key-unwrap-command` then starts postgres in foreground
- Add `sitecustomize.py` shim: restores `ssl.wrap_socket` removed in Python 3.12
  so pre-installed PyKMIP 0.10.0 works in the EDB image
- Dockerfile.edb: COPY shim + pip-install PyKMIP for Python 3.12
- docker-compose.yml `edb-tde` service: use `edb_startup.sh` as command,
  resolve real container name (`kms-edb-tde-1`) via `docker compose ps --format`
- Add documentation page `documentation/docs/integrations/databases/edb_postgres_tde.md`
  with architecture diagram, wire format explanation, PGDATA{KEY}WRAPCMD examples, key rotation, and test instructions
- Update `documentation/mkdocs.yml` and `README.md` with EDB Postgres Advanced Server TDE entry

## Bug Fixes

- `docker-compose.yml`: add `:-` default for `EDB_MASTER_KEY_UID` in `PGDATAKEYWRAPCMD`
  and `PGDATAKEYUNWRAPCMD` to suppress spurious Docker Compose warnings when the variable
  is not set (e.g. when running `docker compose up -d otel-collector jaeger`)
- `decrypt.rs`: treat missing `IVCounterNonce` as zero-IV (fixes thales KMIP
  variant where `iv+ciphertext` is sent as one blob with no separate IV field)
- `test_edb_tde.sh`: separate `COMPOSE_SERVICE` (for compose commands) from
  `CONTAINER_NAME` (for bare `docker exec`) — compose prefixes the project name
- `test_postgres_tde_verify`: add `-d postgres` to psql — `enterprisedb` DB does
  not exist in a plain initdb; use output-based error detection instead of `|| echo "0"`

## Testing

- Add 3 non-regression test vectors under `test_data/vectors/non-fips/integrations/`:
    - `edb_tde_pykmip_variant/` — Create → Activate → Encrypt → Decrypt roundtrip
    - `edb_tde_thales_variant/` — thales zero-IV CBC decrypt path
    - `edb_tde_key_rotation/` — Dual-key rotation with re-wrap verification
- Add `edb_tde` test type to `nix.sh` and CI workflow (non-FIPS only)

- Fix `edb_tde_kmip_client_sim.py`: truncate old version content appended after `if __name__ == '__main__'`
  that caused `SyntaxError: unterminated triple-quoted string literal`; all 6 EDB TDE tests now pass
- `test_edb_tde.sh`: simplify — remove simulation fallback; fail immediately when `EDB_SUBSCRIPTION_TOKEN` is absent; always use real `edb_tde_kmip_client.py` via `docker exec`
- Verify wire format from real `edb_tde_kmip_client.py` source: encrypt writes `[16-byte IV][ciphertext]`; thales decrypt passes `iv+ciphertext` as one blob, strips first 16 bytes — confirms `decrypt.rs` zero-IV fix is correct

## Infrastructure

- Merge `docker-compose.edb.yml` into `docker-compose.yml` (`edb-tde` service); delete standalone file
- Adapt `nix.sh` `edb_tde` test case: `PURE_FLAG=""` (system docker accessible), added `EDB_SUBSCRIPTION_TOKEN`
  / `EDB_PGPASSWORD` / `EDB_MASTER_KEY_UID` to `KEEP_VARS`
- `test_edb_tde.sh` inner runner: use `docker compose --project-directory "$REPO_ROOT"` instead of `-f`
