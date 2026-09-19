#!/usr/bin/env bash
# .mise/lib/multi_region_guards.sh — guards validating the multi-region active-active
# PostgreSQL deployment model (issue #1187).
#
# The guard layers are:
#   * static source guards  — the leader-gating wiring and the PostgreSQL trigger/schema DDL
#   * static config guards  — operator TOML topology/backend/ceremony checks, including
#                             detectors for features incompatible with multi-region mode
#   * live DB guards        — PRIMARY KEY/REPLICA IDENTITY, ENABLE ALWAYS trigger, Spock wiring
#   * behavioral guards     — the existing live 2-node pgEdge proofs (state conflict merge,
#                             grants LWW, CRL gating, CO ceremony gating)
#
# Provides:
#   mr_toml_get                            — extract a top-level scalar from a KMS server TOML
#   mr_config_set_is_multi_region          — true when a config set declares multi-region
#   mr_run_guard                           — run one guard, recording (not aborting on) failure
#   mr_guard_source_model                  — static source-level guards
#   mr_guard_config_topology               — exactly one leader region across the config set
#   mr_guard_config_backend                — postgresql backend only for multi-region nodes
#   mr_guard_config_clear_database         — clear_database must be off for multi-region nodes
#   mr_guard_config_ceremony_keys          — identical ceremony key material across regions
#   mr_guard_config_incompatible_features  — detect settings incompatible with multi-region
#   mr_self_test_config_guards             — prove the config-guard detectors fire correctly
#   mr_guard_pg_container_ready            — wait until a pgEdge container accepts connections
#   mr_guard_primary_keys                  — real PRIMARY KEYs / REPLICA IDENTITY on replicated tables
#   mr_guard_state_monotonic_trigger       — objects.state monotonic trigger installed ENABLE ALWAYS
#   mr_guard_spock_wiring                  — Spock extension, node, and subscription present
#   mr_guard_db_state_and_grants           — behavioral proof: state conflict merge + grants LWW
#   mr_guard_crl_gating                    — behavioral proof: CRL issuance gating
#   mr_guard_ceremony_gating               — behavioral proof: CO ceremony activation gating
#   mr_prebuild_behavioral_tests           — build the behavioral test binaries without running them

[ -n "${_MISE_MULTI_REGION_GUARDS_SH_LOADED:-}" ] && return 0
_MISE_MULTI_REGION_GUARDS_SH_LOADED=1

_MR_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -z "${_MISE_COMMON_SH_LOADED:-}" ]; then
  # shellcheck source=.mise/lib/common.sh
  source "${_MR_LIB_DIR}/common.sh"
fi

# Guard-failure accumulator. The calling task reads this after running its guards.
MR_GUARD_FAILURES=()

# Run one guard function, recording (not aborting on) failure.
# Usage: mr_run_guard <name> [args...]
mr_run_guard() {
  local name="$1"
  shift
  print_status "Guard: $name"
  if "$@"; then
    print_success "Guard passed: $name"
    return 0
  fi
  print_warning "Guard FAILED: $name"
  MR_GUARD_FAILURES+=("$name")
  return 1
}

# Extract the first top-level `key = value` scalar from a KMS server TOML file.
# Supports `key = "value"`, `key = 'value'`, and bare `key = value`.
# Prints nothing when the key is absent (or the file is unreadable).
# Usage: mr_toml_get <file> <key>
mr_toml_get() {
  local file="$1" key="$2"
  awk -F'=' -v k="$key" '
    /^[[:space:]]*#/ { next }
    {
      lhs = $1
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", lhs)
      if (lhs != k) next
      rhs = substr($0, index($0, "=") + 1)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", rhs)

      # Strip inline comment, respecting quoted # characters.
      # Match anything after an unquoted # (not preceded/followed by a quote in the active context).
      # Simpler heuristic: find the first # not inside quotes.
      in_double = 0
      in_single = 0
      for (i = 1; i <= length(rhs); i++) {
        c = substr(rhs, i, 1)
        if (c == "\"" && (i == 1 || substr(rhs, i-1, 1) != "\\")) in_double = !in_double
        else if (c == "'"'"'" && (i == 1 || substr(rhs, i-1, 1) != "\\")) in_single = !in_single
        else if (c == "#" && !in_double && !in_single) {
          rhs = substr(rhs, 1, i - 1)
          break
        }
      }

      # Trim trailing whitespace after inline comment removal.
      gsub(/[[:space:]]+$/, "", rhs)

      # Strip leading/trailing quotes.
      gsub(/^"|"$|^'"'"'|'"'"'$/, "", rhs)
      print rhs
      exit
    }' "$file" 2>/dev/null
}

# True when a set of node configs actually declares a multi-region topology:
# more than one node config, or at least one explicit `region_role = "follower"`.
# Usage: mr_config_set_is_multi_region <config>...
mr_config_set_is_multi_region() {
  local f count=0
  for f in "$@"; do count=$((count + 1)); done
  [ "$count" -gt 1 ] && return 0
  for f in "$@"; do
    [ "$(mr_toml_get "$f" region_role)" = "follower" ] && return 0
  done
  return 1
}

# ── Static source guards ──────────────────────────────────────────────────────

# Verify the source-level wiring of the multi-region model. Every check below
# protects a behavior from the issue #1187 acceptance criteria; a regression
# removing any of them fails the guard.
# Usage: mr_guard_source_model <repo_root>
mr_guard_source_model() {
  local repo_root="$1" ok=0
  local core="${repo_root}/crate/server/src/core/mod.rs"
  local crl="${repo_root}/crate/server/src/core/operations/generate_crl.rs"
  local ceremony="${repo_root}/crate/server/src/core/operations/join_split_key.rs"
  local permissions="${repo_root}/crate/server/src/core/kms/permissions.rs"
  local cron="${repo_root}/crate/server/src/cron.rs"
  local pgsql="${repo_root}/crate/server_database/src/stores/sql/pgsql.rs"
  local interfaces="${repo_root}/crate/interfaces/src/stores/objects_store.rs"
  local f

  for f in "$core" "$crl" "$ceremony" "$permissions" "$cron" "$pgsql" "$interfaces"; do
    if [ ! -f "$f" ]; then
      print_warning "source guard: missing expected file $f"
      ok=1
    fi
  done
  [ "$ok" -eq 0 ] || return 1

  grep -q "fn require_leader_region" "$core" || {
    print_warning "source guard: require_leader_region helper missing from core/mod.rs"
    ok=1
  }
  grep -q 'require_leader_region(kms, "CRL generation")' "$crl" || {
    print_warning "source guard: CRL generation is no longer leader-gated in generate_crl.rs"
    ok=1
  }
  grep -q 'require_leader_region(kms, "Crypto Officer ceremony activation")' "$ceremony" || {
    print_warning "source guard: CO ceremony activation is no longer leader-gated in join_split_key.rs"
    ok=1
  }
  grep -q 'require_leader_region(self, "Crypto Officer ceremony revocation")' "$permissions" || {
    print_warning "source guard: CO ceremony revocation is no longer leader-gated in kms/permissions.rs"
    ok=1
  }
  grep -q "Skipping background CRL refresh on follower" "$cron" || {
    print_warning "source guard: follower CRL-refresh cron skip missing from cron.rs"
    ok=1
  }
  grep -q "objects_state_monotonic_guard()" "$pgsql" || {
    print_warning "source guard: objects state monotonic guard function missing from pgsql.rs"
    ok=1
  }
  grep -q "ENABLE ALWAYS TRIGGER trg_objects_state_monotonic" "$pgsql" || {
    print_warning "source guard: state trigger is no longer ENABLE ALWAYS in pgsql.rs"
    ok=1
  }
  for pk in tags_pkey read_access_pkey crypto_officer_activations_pkey; do
    grep -q "$pk" "$pgsql" || {
      print_warning "source guard: PRIMARY KEY migration for '$pk' missing from pgsql.rs"
      ok=1
    }
  done
  grep -q "update_state_allow_downgrade" "$interfaces" || {
    print_warning "source guard: batch-UNDO downgrade bypass missing from ObjectsStore trait"
    ok=1
  }

  # Documented multi-region hazard (warning, not a failure): the batch-UNDO
  # bypass is transaction-local on one node; a peer that still holds the higher
  # state coerces the replicated row back up, so the revert may not hold.
  if grep -q "kms.allow_backward_state_transition" "$pgsql"; then
    print_warning "hazard: kms.allow_backward_state_transition bypass exists — KMIP batch UNDO \
may be overridden by a peer's higher state under multi-region replication"
  fi

  [ "$ok" -eq 0 ] || return 1
  return 0
}

# ── Static config guards ──────────────────────────────────────────────────────

# Exactly one region across the deployment must be `leader`; every other region
# must be `follower`. Usage: mr_guard_config_topology <config>...
mr_guard_config_topology() {
  local f role leaders=0 followers=0 ok=0
  for f in "$@"; do
    [ -f "$f" ] || {
      print_warning "config topology: file not found: $f"
      ok=1
      continue
    }
    role="$(mr_toml_get "$f" region_role)"
    role="${role:-leader}"
    case "$role" in
      leader) leaders=$((leaders + 1)) ;;
      follower) followers=$((followers + 1)) ;;
      *)
        print_warning "config topology: $f has invalid region_role '$role' (expected leader|follower)"
        ok=1
        ;;
    esac
  done

  if [ "$leaders" -eq 0 ]; then
    print_warning "config topology: no leader region declared (all nodes are followers)"
    ok=1
  fi
  if [ "$leaders" -gt 1 ]; then
    print_warning "config topology: $leaders leader regions declared — split-brain CRL/ceremony issuance"
    ok=1
  fi
  if [ "$#" -gt 1 ] && [ "$followers" -eq 0 ]; then
    print_warning "config topology: $# node configs but no follower — all regions are leaders"
    ok=1
  fi

  [ "$ok" -eq 0 ] || return 1
  return 0
}

# Multi-region nodes must use the PostgreSQL backend (the only backend with the
# logical-replication schema hardening and the monotonic state trigger).
# Usage: mr_guard_config_backend <config>...
mr_guard_config_backend() {
  local f backend ok=0
  mr_config_set_is_multi_region "$@" || return 0
  for f in "$@"; do
    backend="$(mr_toml_get "$f" database_type)"
    if [ "$backend" != "postgresql" ]; then
      print_warning "config backend: $f declares database_type=${backend:-<unset>} — multi-region \
active-active requires PostgreSQL (logical replication); sqlite/mysql/redis-findex cannot replicate"
      ok=1
    fi
  done
  [ "$ok" -eq 0 ] || return 1
  return 0
}

# `clear_database = true` on any multi-region node would wipe its local copy and
# replicate the deletes to every peer. Usage: mr_guard_config_clear_database <config>...
mr_guard_config_clear_database() {
  local f clear ok=0
  mr_config_set_is_multi_region "$@" || return 0
  for f in "$@"; do
    clear="$(mr_toml_get "$f" clear_database)"
    if [ "$clear" = "true" ]; then
      print_warning "config clear_database: $f has clear_database = true — destructive on every \
start and the deletes replicate to all regions"
      ok=1
    fi
  done
  [ "$ok" -eq 0 ] || return 1
  return 0
}

# When the CO ceremony is enabled, every region must share identical ceremony key
# material (ceremony_secret or ceremony_key_id) — replicated records are
# AES-256-GCM sealed and verified with the local node's derived keys.
# Usage: mr_guard_config_ceremony_keys <config>...
mr_guard_config_ceremony_keys() {
  local f require secret key_id ok=0 ceremony_enabled=0
  local first_secret="" first_key_id=""
  mr_config_set_is_multi_region "$@" || return 0

  for f in "$@"; do
    require="$(mr_toml_get "$f" crypto_officer_require_ceremony)"
    [ "$require" = "true" ] && ceremony_enabled=1
  done
  [ "$ceremony_enabled" -eq 1 ] || return 0

  for f in "$@"; do
    secret="$(mr_toml_get "$f" ceremony_secret)"
    key_id="$(mr_toml_get "$f" ceremony_key_id)"

    if [ -z "$secret" ] && [ -z "$key_id" ]; then
      print_warning "config ceremony: $f enables CO ceremony but sets neither ceremony_secret \
nor ceremony_key_id"
      ok=1
      continue
    fi

    if [ -n "$secret" ]; then
      if [ -z "$first_secret" ]; then
        first_secret="$secret"
      elif [ "$secret" != "$first_secret" ]; then
        print_warning "config ceremony: $f ceremony_secret differs from the first region's — \
replicated records will fail GCM verification on this node"
        ok=1
      fi
    fi
    if [ -n "$key_id" ]; then
      if [ -z "$first_key_id" ]; then
        first_key_id="$key_id"
      elif [ "$key_id" != "$first_key_id" ]; then
        print_warning "config ceremony: $f ceremony_key_id differs from the first region's"
        ok=1
      fi
    fi
  done

  [ "$ok" -eq 0 ] || return 1
  return 0
}

# Detect features known to be incompatible with (or unsafe under) the
# multi-region active-active model. Emits warnings for advisory hazards and
# fails only for hard incompatibilities.
# Usage: mr_guard_config_incompatible_features <config>...
mr_guard_config_incompatible_features() {
  local f ok=0 rotation_nodes=0 value
  mr_config_set_is_multi_region "$@" || return 0

  for f in "$@"; do
    # HSM-backed objects live in the local PKCS#11 token and do not replicate.
    # Every region must therefore have access to the same HSM partition.
    value="$(mr_toml_get "$f" hsm_slot)"
    if [ -n "$value" ] && [ "$value" != "[]" ]; then
      print_warning "config incompatible: $f configures hsm_slot ${value} — HSM-stored objects \
do not replicate; every region must share the same HSM partition/token"
    fi

    # Auto-rotation is not leader-gated: if several regions run the cron, the
    # same key can be rotated concurrently on both sides.
    value="$(mr_toml_get "$f" auto_rotation_check_interval_secs)"
    value="${value:-0}"
    if [ "$value" -gt 0 ] 2>/dev/null; then
      rotation_nodes=$((rotation_nodes + 1))
    fi
  done

  if [ "$rotation_nodes" -gt 1 ]; then
    print_warning "config incompatible: auto-rotation cron enabled on $rotation_nodes regions — \
rotation is not leader-gated and can double-rotate the same key concurrently"
  elif [ "$rotation_nodes" -eq 1 ]; then
    print_info "auto-rotation cron is enabled on exactly one region — acceptable, but keep it on the leader"
  fi

  [ "$ok" -eq 0 ] || return 1
  return 0
}

# Prove the config-guard detectors actually fire, using synthetic config files.
# Positive cases must pass; negative cases must fail. Usage: mr_self_test_config_guards
mr_self_test_config_guards() {
  local tmpdir ok=0
  tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/kms-mr-guards.XXXXXX")" || return 1

  cat >"${tmpdir}/leader.toml" <<'EOF'
region_role = "leader"
database_type = "postgresql"
database_url = "postgresql://kms:kms@127.0.0.1:6432/kms"
clear_database = false
crypto_officer_require_ceremony = true
ceremony_secret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
auto_rotation_check_interval_secs = 0
EOF
  cat >"${tmpdir}/follower.toml" <<'EOF'
region_role = "follower"
database_type = "postgresql"
database_url = "postgresql://kms:kms@127.0.0.1:6433/kms"
clear_database = false
crypto_officer_require_ceremony = true
ceremony_secret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
auto_rotation_check_interval_secs = 0
EOF

  print_status "config guard self-test: positive case (leader + follower, matching ceremony key)"
  if mr_guard_config_topology "${tmpdir}/leader.toml" "${tmpdir}/follower.toml" &&
    mr_guard_config_backend "${tmpdir}/leader.toml" "${tmpdir}/follower.toml" &&
    mr_guard_config_clear_database "${tmpdir}/leader.toml" "${tmpdir}/follower.toml" &&
    mr_guard_config_ceremony_keys "${tmpdir}/leader.toml" "${tmpdir}/follower.toml"; then
    print_success "config guard self-test: positive case passed"
  else
    print_warning "config guard self-test: positive case FAILED"
    ok=1
  fi

  cat >"${tmpdir}/sqlite_follower.toml" <<'EOF'
region_role = "follower"
database_type = "sqlite"
sqlite_path = "/tmp/kms-mr-sqlite"
EOF
  if mr_guard_config_backend "${tmpdir}/sqlite_follower.toml"; then
    print_warning "config guard self-test: sqlite follower was NOT rejected by the backend guard"
    ok=1
  else
    print_success "config guard self-test: sqlite follower correctly rejected"
  fi

  cat >"${tmpdir}/leader2.toml" <<'EOF'
region_role = "leader"
database_type = "postgresql"
database_url = "postgresql://kms:kms@127.0.0.1:6433/kms"
EOF
  if mr_guard_config_topology "${tmpdir}/leader.toml" "${tmpdir}/leader2.toml"; then
    print_warning "config guard self-test: two-leader topology was NOT rejected"
    ok=1
  else
    print_success "config guard self-test: two-leader topology correctly rejected"
  fi

  cat >"${tmpdir}/clearing_follower.toml" <<'EOF'
region_role = "follower"
database_type = "postgresql"
database_url = "postgresql://kms:kms@127.0.0.1:6433/kms"
clear_database = true
EOF
  if mr_guard_config_clear_database "${tmpdir}/clearing_follower.toml"; then
    print_warning "config guard self-test: clear_database follower was NOT rejected"
    ok=1
  else
    print_success "config guard self-test: clear_database follower correctly rejected"
  fi

  cat >"${tmpdir}/mismatch_follower.toml" <<'EOF'
region_role = "follower"
database_type = "postgresql"
database_url = "postgresql://kms:kms@127.0.0.1:6433/kms"
crypto_officer_require_ceremony = true
ceremony_secret = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
EOF
  if mr_guard_config_ceremony_keys "${tmpdir}/leader.toml" "${tmpdir}/mismatch_follower.toml"; then
    print_warning "config guard self-test: mismatched ceremony_secret was NOT rejected"
    ok=1
  else
    print_success "config guard self-test: mismatched ceremony_secret correctly rejected"
  fi

  # Test inline comments on boolean values (catching the original bug).
  cat >"${tmpdir}/commented_clear.toml" <<'EOF'
region_role = "leader"
database_type = "postgresql"
database_url = "postgresql://kms:kms@127.0.0.1:6432/kms"
clear_database = true # destructive but intentional in test
crypto_officer_require_ceremony = true
ceremony_secret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
EOF
  # Create a follower to make this a multi-region deployment
  cat >"${tmpdir}/commented_follower_for_clear.toml" <<'EOF'
region_role = "follower"
database_type = "postgresql"
database_url = "postgresql://kms:kms@127.0.0.1:6433/kms"
EOF
  if mr_guard_config_clear_database "${tmpdir}/commented_clear.toml" "${tmpdir}/commented_follower_for_clear.toml"; then
    print_warning "config guard self-test: clear_database with inline comment was NOT rejected"
    ok=1
  else
    print_success "config guard self-test: clear_database with inline comment correctly rejected"
  fi

  # Test inline comments on region_role (catching false failures).
  cat >"${tmpdir}/commented_follower.toml" <<'EOF'
region_role = "follower" # secondary region
database_type = "postgresql"
database_url = "postgresql://kms:kms@127.0.0.1:6433/kms"
EOF
  if mr_guard_config_topology "${tmpdir}/leader.toml" "${tmpdir}/commented_follower.toml"; then
    print_success "config guard self-test: region_role with inline comment correctly parsed"
  else
    print_warning "config guard self-test: region_role with inline comment was incorrectly rejected"
    ok=1
  fi

  # Incompatible-feature detectors: run them against a synthetic misconfigured
  # follower to prove they emit their warnings (advisory by design, so exit code
  # is not asserted here).
  cat >"${tmpdir}/rotating_hsm_follower.toml" <<'EOF'
region_role = "follower"
database_type = "postgresql"
database_url = "postgresql://kms:kms@127.0.0.1:6433/kms"
auto_rotation_check_interval_secs = 3600
hsm_slot = [0]
EOF
  print_status "config guard self-test: incompatible-feature detectors (warnings expected)"
  mr_guard_config_incompatible_features "${tmpdir}/leader.toml" "${tmpdir}/rotating_hsm_follower.toml"

  rm -rf "${tmpdir}"
  [ "$ok" -eq 0 ] || return 1
  return 0
}

# ── Live DB guards (pgEdge containers) ────────────────────────────────────────

# Run psql inside a pgEdge container and print the query result.
# Usage: _mr_psql <container> <sql>
_mr_psql() {
  local container="$1" sql="$2"
  docker exec -e PGPASSWORD=kms "${container}" \
    psql -h 127.0.0.1 -U kms -d kms -tAc "${sql}" 2>/dev/null
}

# Wait until a pgEdge container accepts connections. Usage: mr_guard_pg_container_ready <container> [timeout]
mr_guard_pg_container_ready() {
  local container="$1" timeout="${2:-30}" _i
  for _i in $(seq 1 "$timeout"); do
    if docker exec "${container}" pg_isready -h 127.0.0.1 -U kms -d kms -q 2>/dev/null; then
      return 0
    fi
    sleep 1
  done
  print_warning "pg container ${container} not ready after ${timeout}s"
  return 1
}

# The replicated tables must carry a real PRIMARY KEY (REPLICA IDENTITY DEFAULT),
# otherwise logical replication cannot replicate UPDATE/DELETE on them.
# Usage: mr_guard_primary_keys <container>
mr_guard_primary_keys() {
  local container="$1" pks ident
  pks="$(_mr_psql "${container}" "SELECT count(*) FROM pg_constraint WHERE contype='p' AND conname IN ('tags_pkey','read_access_pkey','crypto_officer_activations_pkey');")"
  if [ "${pks//[^0-9]/}" != "3" ]; then
    print_warning "primary keys: ${container} has ${pks:-0}/3 expected PRIMARY KEYs (tags_pkey, read_access_pkey, crypto_officer_activations_pkey)"
    return 1
  fi

  ident="$(_mr_psql "${container}" "SELECT string_agg(relname || '=' || relreplident::text, ',' ORDER BY relname) FROM pg_class WHERE relname IN ('tags','read_access','crypto_officer_activations');")"
  if [ "$ident" != "crypto_officer_activations=d,read_access=d,tags=d" ]; then
    print_warning "primary keys: ${container} REPLICA IDENTITY not default for all replicated tables: ${ident:-<none>}"
    return 1
  fi
  print_success "primary keys: ${container} has valid PRIMARY KEYs with REPLICA IDENTITY DEFAULT"
  return 0
}

# The monotonic state trigger must exist, fire BEFORE UPDATE FOR EACH ROW, and be
# ENABLE ALWAYS so it coerces both local and replicated downgrades to GREATEST(state).
# Usage: mr_guard_state_monotonic_trigger <container>
mr_guard_state_monotonic_trigger() {
  local container="$1" def enabled fn
  enabled="$(_mr_psql "${container}" "SELECT tgenabled FROM pg_trigger WHERE tgname='trg_objects_state_monotonic' AND NOT tgisinternal;")"
  if [ "$enabled" != "A" ]; then
    print_warning "state trigger: ${container} trigger missing or not ENABLE ALWAYS (tgenabled=${enabled:-<none>}, expected A)"
    return 1
  fi
  fn="$(_mr_psql "${container}" "SELECT count(*) FROM pg_proc WHERE proname='objects_state_monotonic_guard';")"
  if [ "${fn//[^0-9]/}" != "1" ]; then
    print_warning "state trigger: ${container} guard function objects_state_monotonic_guard() missing"
    return 1
  fi
  def="$(_mr_psql "${container}" "SELECT pg_get_triggerdef(oid) FROM pg_trigger WHERE tgname='trg_objects_state_monotonic';")"
  if ! grep -q "BEFORE UPDATE" <<<"$def" || ! grep -q "FOR EACH ROW" <<<"$def"; then
    print_warning "state trigger: ${container} trigger definition is not BEFORE UPDATE FOR EACH ROW: ${def:-<none>}"
    return 1
  fi
  print_success "state trigger: ${container} monotonic guard is ENABLE ALWAYS (BEFORE UPDATE FOR EACH ROW)"
  return 0
}

# Spock must be installed with a node and at least one subscription (full-mesh
# bidirectional replication). Usage: mr_guard_spock_wiring <container>
mr_guard_spock_wiring() {
  local container="$1" ext nodes subs
  ext="$(_mr_psql "${container}" "SELECT EXISTS (SELECT 1 FROM pg_extension WHERE extname='spock');")"
  if [ "$ext" != "t" ]; then
    print_warning "spock wiring: ${container} does not have the spock extension installed"
    return 1
  fi
  nodes="$(_mr_psql "${container}" "SELECT count(*) FROM spock.node;")"
  subs="$(_mr_psql "${container}" "SELECT count(*) FROM spock.subscription;")"
  if [ "${nodes//[^0-9]/}" = "0" ] || [ "${subs//[^0-9]/}" = "0" ]; then
    print_warning "spock wiring: ${container} has ${nodes:-0} node(s) and ${subs:-0} subscription(s) — expected >=1 of each"
    return 1
  fi
  print_success "spock wiring: ${container} has spock with ${nodes//[^0-9]/} node(s) and ${subs//[^0-9]/} subscription(s)"
  return 0
}

# ── Behavioral guards (live 2-node pgEdge proofs) ─────────────────────────────

# Pre-build the pgEdge behavioral test binaries without running them, so the
# pgEdge containers are only started for the short test-execution window — a
# long first build (e.g. a cold nix-shell bootstrap) must not outlive the
# containers. Usage: mr_prebuild_behavioral_tests <repo_root>
mr_prebuild_behavioral_tests() {
  local repo_root="$1"
  (
    cd "${repo_root}" || return 1
    cargo test -p cosmian_kms_server_database --lib \
      "${FEATURES_FLAG[@]+"${FEATURES_FLAG[@]}"}" --no-run
    cargo test -p cosmian_kms_server --lib \
      "${FEATURES_FLAG[@]+"${FEATURES_FLAG[@]}"}" --no-run
  )
}

# Run one of the `#[ignore]`d pgEdge cargo proofs. Usage: _mr_cargo_pgedge <repo_root> <package> <test_name>
_mr_cargo_pgedge() {
  local repo_root="$1" package="$2" test_name="$3"
  (
    cd "${repo_root}" || return 1
    cargo test -p "${package}" --lib \
      "${FEATURES_FLAG[@]+"${FEATURES_FLAG[@]}"}" \
      -- --ignored --nocapture "${test_name}"
  )
}

# Object-state conflict merge (both commit orderings) + grants/permissions LWW
# convergence. Usage: mr_guard_db_state_and_grants <repo_root> <pg1_url> <pg2_url>
mr_guard_db_state_and_grants() {
  local repo_root="$1" pg1_url="$2" pg2_url="$3"
  KMS_PGEDGE_1_URL="${pg1_url}" KMS_PGEDGE_2_URL="${pg2_url}" \
    _mr_cargo_pgedge "${repo_root}" cosmian_kms_server_database test_db_pgedge_active_active
}

# CRL issuance gating: follower rejection, leader issuance, CDP replication,
# follower revoke does not regenerate. Usage: mr_guard_crl_gating <repo_root> <pg1_url> <pg2_url>
mr_guard_crl_gating() {
  local repo_root="$1" pg1_url="$2" pg2_url="$3"
  KMS_PGEDGE_1_URL="${pg1_url}" KMS_PGEDGE_2_URL="${pg2_url}" \
    _mr_cargo_pgedge "${repo_root}" cosmian_kms_server test_pgedge_crl_leader_only_generation_and_follower_cdp_replication
}

# CO ceremony gating: leader activation replicates, follower activation/revocation
# rejected, mismatched ceremony_secret fails secure. Usage: mr_guard_ceremony_gating <repo_root> <pg1_url> <pg2_url>
mr_guard_ceremony_gating() {
  local repo_root="$1" pg1_url="$2" pg2_url="$3"
  KMS_PGEDGE_1_URL="${pg1_url}" KMS_PGEDGE_2_URL="${pg2_url}" \
    _mr_cargo_pgedge "${repo_root}" cosmian_kms_server test_pgedge_crypto_officer_multi_region_activation_replication_and_fail_secure
}
