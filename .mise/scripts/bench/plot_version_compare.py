#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Generate gnuplot comparison charts and a combined report from multi-version bench results.

Output layout under <results_dir>:
  <version>/      per-version raw data (load_*.json, criterion.json)
  load/           load-test SVGs (one per operation, curves per protocol×version)
  criterion/      criterion bar-chart SVGs (4 category charts)
  report.md       combined human-readable report

Usage:
    python3 plot_version_compare.py <results_dir> <version1> [version2] ...
"""
from __future__ import annotations

import json
import math
import re
import subprocess
import sys
from collections import defaultdict
from datetime import date
from pathlib import Path

# ── Algorithm category helpers ────────────────────────────────────────────────

# Five criterion chart categories: (chart_id, title, op_type)
CHART_DEFS = [
    ('symmetric_encrypt', 'Symmetric Encryption', 'encrypt'),
    ('asymmetric_encrypt', 'Asymmetric Encryption', 'encrypt'),
    ('kem', 'Key Encapsulation (KEM)', 'kem'),
    ('key_creation', 'Key Creation', 'key-creation'),
    ('signature', 'Sign / Verify', 'sign-verify'),
]

_SYMMETRIC_PREFIXES = ('aes', 'chacha', 'salsa', 'camellia', 'sm4')
# JWA symmetric algorithm pattern: Axxxgcm / Axxxcbc (A128GCM, A256GCM, etc.)
_JWA_SYMMETRIC_RE = re.compile(r'^a\d+(gcm|cbc)', re.IGNORECASE)


def _is_symmetric(algorithm: str) -> bool:
    """Return True if the algorithm name suggests a symmetric cipher.

    Strips an optional 'hsm-' prefix first: HSM-delegated benchmarks (see
    `bench/load-hsm --delegated`) label their algorithm 'hsm-aes-gcm', 'hsm-rsa-oaep',
    etc. so the criterion group's op_type still parses correctly (a bare 'hsm/'
    path segment would shift `bench_id_to_parts`'s op_type/algorithm split).
    """
    alg = algorithm.lower().removeprefix('hsm-')
    return any(alg.startswith(p) for p in _SYMMETRIC_PREFIXES) or bool(
        _JWA_SYMMETRIC_RE.match(alg)
    )


# ── Bench-function name normalisation ────────────────────────────────────────

# ttlv-bytes uses string literals like "encrypt/128" or "encrypt/P-256" whose
# embedded slashes are sanitized to underscores by Criterion ("encrypt_128",
# "encrypt_P-256"), while ttlv-json uses BenchmarkId::new("encrypt", 128) /
# BenchmarkId::new("encrypt", "P-256") which Criterion renders as "encrypt/128"
# / "encrypt/P-256".  Normalise the underscore form to the slash form so rows
# merge across protocols.
_TRAILING_LABEL_RE = re.compile(r'_([^/]+)$')


def _normalize_bench_fn(bench_fn: str) -> str:
    """Normalise 'op_LABEL' → 'op/LABEL' so ttlv-bytes and ttlv-json rows merge.

    Handles both numeric suffixes (encrypt_128 → encrypt/128) and
    alphanumeric ones (decrypt_P-256 → decrypt/P-256).
    """
    return _TRAILING_LABEL_RE.sub(r'/\1', bench_fn)


# JWA algorithm names used by jose (e.g. A256GCM, A128CBC-HS256).
_JWA_AES_RE = re.compile(r'^A(\d+)(GCM|CBC)', re.IGNORECASE)


def _normalize_jwa_algo(jwa: str) -> tuple[str, str]:
    """Map a JWA algorithm identifier to (canonical_slug, key_bits_str).

    Examples::
        'A256GCM'       -> ('aes-gcm', '256')
        'A128GCM'       -> ('aes-gcm', '128')
        'A128CBC-HS256' -> ('aes-cbc', '128')
    """
    m = _JWA_AES_RE.match(jwa)
    if m:
        return f"aes-{m.group(2).lower()}", m.group(1)
    return jwa.lower(), ''


# ── Shared criterion-classification helpers ───────────────────────────────────

# Display order of protocols in table columns and chart bars.
_PROTOCOL_ORDER: dict[str, int] = {
    'ttlv-json': 0,
    'ttlv-bytes': 1,
    'jose': 2,
    'pkcs11': 3,
}

_PKCS11_OVERHEAD_TIERS: list[tuple[str, str, str | None]] = [
    ('request-build', 'Request construction', None),
    ('ttlv-json-serialize', 'TTLV + JSON serialization', None),
    (
        'published-full-message-raw-http',
        'Published-equivalent full-message raw HTTP',
        None,
    ),
    (
        'bare-sign-raw-http',
        'Bare Sign raw HTTP',
        'published-full-message-raw-http',
    ),
    ('response-parse', 'Response JSON + TTLV parsing', None),
    ('typed-kms-client-sign', 'Typed KMS client Sign', 'bare-sign-raw-http'),
    (
        'published-full-message-binary-http',
        'Full-message binary TTLV HTTP + KMIP validation',
        None,
    ),
    ('binary-response-parse', 'Binary TTLV response parsing', None),
    (
        'typed-binary-message-sign-bracketed',
        'Typed binary-TTLV message Sign (bracketed mean)',
        'published-full-message-binary-http',
    ),
    ('runtime-block-on-ready', 'Tokio block_on control', None),
    (
        'pkcs11-one-call-bracketed',
        'PKCS#11 v3 C_SignMessage (bracketed mean)',
        'typed-binary-message-sign-bracketed',
    ),
    (
        'pkcs11-two-call-fixed-query',
        'Legacy C_Sign API (fixed length query)',
        None,
    ),
]
_PKCS11_TIER_LABELS = {
    name: (label, baseline) for name, label, baseline in _PKCS11_OVERHEAD_TIERS
}

_PKCS11_PHASE_ORDER = [
    'c-sign-body',
    'session-map-lookup',
    'session-lock-wait',
    'session-callback',
    'private-key-sign',
    'backend-lookup',
    'backend-remote-sign',
    'request-build',
    'runtime-block-on',
    'kms-client-sign',
    'signature-copy',
]
_PKCS11_PHASE_LABELS = {
    'c-sign-body': 'C_SignMessage body',
    'session-map-lookup': 'Session map lookup',
    'session-lock-wait': 'Per-session lock wait',
    'session-callback': 'Session callback',
    'private-key-sign': 'Private-key Sign',
    'backend-lookup': 'Backend lookup',
    'backend-remote-sign': 'Backend remote Sign',
    'request-build': 'Request construction',
    'runtime-block-on': 'Tokio block_on',
    'kms-client-sign': 'Typed KMS client Sign',
    'signature-copy': 'Signature copy',
}
_PKCS11_INCLUSIVE_PHASES = {
    'c-sign-body',
    'session-callback',
    'private-key-sign',
    'backend-remote-sign',
    'runtime-block-on',
    'kms-client-sign',
}
_PKCS11_LEAF_PHASES = {
    'session-map-lookup',
    'session-lock-wait',
    'backend-lookup',
    'request-build',
    'signature-copy',
}


def _criterion_algo_key(algorithm: str, bench_fn: str) -> str:
    """Return a normalised row-label for the criterion table.

    When algorithm is empty (jose-style: group 'jose_encrypt' without an algo
    in the group name), the bench function carries the JWA identifier, e.g.
    'decrypt/A256GCM'.  Normalise it to 'aes-gcm/decrypt/256' so the row
    merges with the corresponding ttlv-json / ttlv-bytes row.
    """
    fn = _normalize_bench_fn(bench_fn)
    if algorithm:
        return f"{algorithm}/{fn}" if fn else algorithm
    # jose-style: bench_fn is 'decrypt/A256GCM' or 'encrypt/A128GCM'
    parts = fn.rsplit('/', 1)
    if len(parts) == 2:
        op_path, jwa = parts
        canon_algo, key_bits = _normalize_jwa_algo(jwa)
        if key_bits:
            return f"{canon_algo}/{op_path}/{key_bits}"
    return fn or 'unknown'


def _criterion_category(op_type: str, algorithm: str, bench_fn: str) -> str | None:
    """Return the CHART_DEF category id for a benchmark, or None to skip."""
    if op_type == 'encrypt':
        if algorithm:
            check = algorithm
        else:
            # jose-style: extract JWA name from bench_fn and canonicalise.
            jwa = bench_fn.rsplit('/', 1)[-1] if bench_fn else ''
            check, _ = _normalize_jwa_algo(jwa)  # e.g. 'A256GCM' -> 'aes-gcm'
        return 'symmetric_encrypt' if _is_symmetric(check) else 'asymmetric_encrypt'
    if op_type == 'kem':
        return 'kem'
    if op_type == 'key-creation':
        return 'key_creation'
    if op_type in ('sign-verify', 'sign_verify'):
        return 'signature'
    return None


# ── Operation-name normalization ──────────────────────────────────────────────

# Maps (protocol, jose_op_name) → canonical operation name used by ttlv protocols.
# JOSE uses JWA algorithm identifiers (A128GCM, A256GCM…) while ttlv uses
# descriptive slugs (aes-gcm).  Merge them so all three protocols appear on
# the same load chart.
_JOSE_OP_ALIASES: dict[str, str] = {
    'encrypt/a128gcm': 'encrypt/aes-gcm',
    'encrypt/a192gcm': 'encrypt/aes-gcm',
    'encrypt/a256gcm': 'encrypt/aes-gcm',
    'encrypt/a128cbc-hs256': 'encrypt/aes-cbc',
    'encrypt/a192cbc-hs384': 'encrypt/aes-cbc',
    'encrypt/a256cbc-hs512': 'encrypt/aes-cbc',
}


def _normalize_load_records(records: list[dict]) -> None:
    """Normalise protocol-specific operation names to their canonical form in-place."""
    for r in records:
        if r.get('protocol') == 'jose':
            r['operation'] = _JOSE_OP_ALIASES.get(
                r.get('operation', ''), r.get('operation', '')
            )


# Known protocol prefixes that may appear at the start of a criterion group name.
_KNOWN_PROTOCOLS = ('ttlv-bytes', 'ttlv-json', 'jose', 'pkcs11')


def bench_id_to_parts(bid: str) -> tuple[str, str, str]:
    """Decompose an actual criterion bench ID into (protocol, op_type, algorithm).

    Criterion sanitizes group names by replacing '/' with '_', so:
      Rust group "encrypt/aes-gcm"        -> criterion ID prefix "encrypt_aes-gcm"
      Rust group "ttlv-bytes/encrypt/..." -> criterion ID prefix "ttlv-bytes_encrypt_..."
      Rust group "key-creation/rsa"       -> criterion ID prefix "key-creation_rsa"

    Examples:
      "encrypt_aes-gcm/encrypt/128"           -> ("ttlv-json", "encrypt", "aes-gcm")
      "ttlv-bytes_encrypt_aes-gcm/encrypt/128"-> ("ttlv-bytes", "encrypt", "aes-gcm")
      "key-creation_rsa/rsa/2048"             -> ("ttlv-json", "key-creation", "rsa")
      "sign-verify_rsa-pss/sign/2048"         -> ("ttlv-json", "sign-verify", "rsa-pss")
      "kem_pqc/encapsulate/ML-KEM-512"        -> ("ttlv-json", "kem", "pqc")
    """
    # The first "/" separates the sanitized group name from the bench function path.
    slash = bid.find('/')
    group = bid[:slash] if slash >= 0 else bid

    # Strip known protocol prefix (e.g. "ttlv-bytes_").
    protocol = 'ttlv-json'
    for p in _KNOWN_PROTOCOLS:
        if group.startswith(p + '_'):
            protocol = p
            group = group[len(p) + 1 :]
            break

    # Split on the FIRST underscore to separate op_type from algorithm.
    # op_type may contain hyphens (e.g. "key-creation", "sign-verify").
    underscore = group.find('_')
    if underscore >= 0:
        op_type = group[:underscore]  # e.g. "encrypt", "kem", "key-creation"
        algorithm = group[underscore + 1 :]  # e.g. "aes-gcm", "pqc", "rsa"
    else:
        op_type = group
        algorithm = ''

    return protocol, op_type, algorithm


# ── Data parsing ──────────────────────────────────────────────────────────────


def parse_load_json(path: Path) -> list[dict]:
    """Parse a load_XXX.json file (one JSON object per line).

    Returns list of dicts with keys: protocol, operation, concurrency,
    throughput_rps, p50_ms, p95_ms, p99_ms
    """
    if not path.exists():
        return []
    records: list[dict] = []
    for raw in path.read_text(encoding='utf-8').splitlines():
        raw = raw.strip()
        if not raw:
            continue
        try:
            records.append(json.loads(raw))
        except json.JSONDecodeError:
            pass
    return records


def parse_criterion_json(path: Path, version: str) -> dict[str, float]:
    """Parse criterion JSON output (one object per line).

    Strips the version label so IDs match across versions.
    Returns: {normalized_bench_id: mean_time_ns}
    """
    if not path.exists():
        return {}
    results: dict[str, float] = {}
    for raw in path.read_text(encoding='utf-8').splitlines():
        raw = raw.strip()
        if not raw:
            continue
        try:
            obj = json.loads(raw)
            if obj.get('reason') != 'benchmark-complete':
                continue
            bid = obj.get('id', '')
            bid = bid.replace(f"/{version}/", '/').replace(f"/{version}", '')
            ns = obj.get('mean', {}).get('estimate', 0.0)
            if bid and ns > 0:
                results[bid] = ns
        except (json.JSONDecodeError, KeyError, TypeError):
            continue
    return results


def _finite_number(value: object, *, positive: bool = False) -> float | None:
    """Return a finite non-negative JSON number, or None when invalid."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        number = float(value)
    except (OverflowError, ValueError):
        return None
    if not math.isfinite(number) or number < 0 or (positive and number == 0):
        return None
    return number


def _optional_measurements(
    record: dict[str, object], names: tuple[str, ...]
) -> dict[str, float]:
    """Extract valid optional timing measurements from a schema record."""
    measurements: dict[str, float] = {}
    for name in names:
        value = _finite_number(record.get(name))
        if value is not None:
            measurements[name] = value
    return measurements


def parse_pkcs11_overhead_json(path: Path) -> dict[str, object]:
    """Parse the versioned PKCS#11 Ed25519 overhead schema.

    Invalid top-level documents are ignored. Within a valid schema, malformed
    tier or phase records are skipped independently so a partial benchmark run
    can still produce the useful portions of the report.
    """
    if not path.exists():
        return {}
    try:
        raw = json.loads(path.read_text(encoding='utf-8'))
    except (json.JSONDecodeError, OSError, ValueError):
        return {}
    if (
        not isinstance(raw, dict)
        or type(raw.get('schema_version')) is not int
        or raw.get('schema_version') != 1
        or raw.get('algorithm') != 'eddsa-ed25519'
    ):
        return {}

    tiers: list[dict[str, object]] = []
    raw_tiers = raw.get('tiers', [])
    if isinstance(raw_tiers, list):
        for record in raw_tiers:
            if not isinstance(record, dict):
                continue
            name = record.get('name')
            mean_ns = _finite_number(record.get('mean_ns'), positive=True)
            if not isinstance(name, str) or not name or mean_ns is None:
                continue
            tier: dict[str, object] = {'name': name, 'mean_ns': mean_ns}
            tier.update(
                _optional_measurements(record, ('median_ns', 'lower_ns', 'upper_ns'))
            )
            tiers.append(tier)

    phases: list[dict[str, object]] = []
    raw_phases = raw.get('phases', [])
    if isinstance(raw_phases, list):
        for record in raw_phases:
            if not isinstance(record, dict):
                continue
            name = record.get('name')
            count = record.get('count')
            mean_ns = _finite_number(record.get('mean_ns'), positive=True)
            if (
                not isinstance(name, str)
                or not name
                or isinstance(count, bool)
                or not isinstance(count, int)
                or count < 0
                or mean_ns is None
            ):
                continue
            phase: dict[str, object] = {
                'name': name,
                'count': count,
                'mean_ns': mean_ns,
            }
            phase.update(
                _optional_measurements(record, ('p50_ns', 'p95_ns', 'p99_ns', 'max_ns'))
            )
            phases.append(phase)

    parsed: dict[str, object] = {
        'schema_version': 1,
        'algorithm': 'eddsa-ed25519',
        'tiers': tiers,
        'phases': phases,
    }
    for name in (
        'payload_bytes',
        'request_bytes',
        'response_bytes',
        'binary_request_bytes',
        'binary_response_bytes',
    ):
        value = raw.get(name)
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
            parsed[name] = value
    if isinstance(raw.get('varying_payload'), bool):
        parsed['varying_payload'] = raw['varying_payload']
    return parsed


# ── Helpers ───────────────────────────────────────────────────────────────────


def _fmt_time(ns: float) -> str:
    """Format nanoseconds as a human-readable string."""
    if ns < 1_000:
        return f"{ns:.0f} ns"
    if ns < 1_000_000:
        return f"{ns / 1_000:.1f} µs"
    if ns < 1_000_000_000:
        return f"{ns / 1_000_000:.2f} ms"
    return f"{ns / 1_000_000_000:.2f} s"


# ── gnuplot ───────────────────────────────────────────────────────────────────


def gnuplot_available() -> bool:
    """Return True if gnuplot is installed."""
    try:
        subprocess.run(['gnuplot', '--version'], capture_output=True, check=True)
        return True
    except (FileNotFoundError, subprocess.CalledProcessError):
        return False


def run_gnuplot(script: str, out_dir: Path, svg_name: str) -> bool:
    """Save a gnuplot script alongside its SVG and execute it. Returns True on success."""
    script_path = out_dir / svg_name.replace('.svg', '.gnuplot')
    script_path.write_text(script)
    r = subprocess.run(['gnuplot', script_path.name], cwd=out_dir, capture_output=True)
    if r.returncode != 0:
        print(f"  gnuplot error ({svg_name}): {r.stderr.decode().strip()}")
    return r.returncode == 0


def svg_preamble(svg_name: str, title: str, *, w: int = 1000, h: int = 500) -> str:
    """Return the gnuplot lines for terminal, output, title, and grid."""
    return (
        f"set terminal svg size {w},{h} enhanced font 'Helvetica,12'\n"
        f"set output '{svg_name}'\n"
        f"set title '{title}'\n"
        f"set grid\n"
    )


# ── Load test charts ──────────────────────────────────────────────────────────


def generate_load_charts(
    load_dir: Path,
    versions: list[str],
    load_data: dict[str, list[dict]],
) -> list[str]:
    """Generate one throughput SVG per operation in load_dir.

    Each chart has one curve per (protocol, version) combination.
    Returns relative paths from the parent directory (e.g. 'load/encrypt_aes-gcm.svg').
    """
    if not gnuplot_available():
        print('WARNING: gnuplot not found — install with: apt install gnuplot')
        return []

    load_dir.mkdir(parents=True, exist_ok=True)
    generated: list[str] = []

    # Collect all unique operations preserving first-seen order.
    ops: list[str] = []
    for v in versions:
        for rec in load_data.get(v, []):
            op = rec.get('operation', '')
            if op and op not in ops:
                ops.append(op)

    multi_version = len(versions) > 1

    for op in ops:
        safe = op.replace('/', '_')
        curves: list[tuple[str, str]] = []  # (label, dat_filename)

        for v in versions:
            # Group records for this operation by protocol.
            by_proto: dict[str, list[dict]] = defaultdict(list)
            for rec in load_data.get(v, []):
                if rec.get('operation') == op:
                    by_proto[rec.get('protocol', 'unknown')].append(rec)

            for proto, recs in sorted(by_proto.items()):
                recs_sorted = sorted(recs, key=lambda r: r.get('concurrency', 0))
                dat_name = f"{safe}-{v}-{proto}.dat"
                dat_content = '# concurrency  rps  p50  p95  p99\n' + ''.join(
                    f"{r['concurrency']}  {r['throughput_rps']:.2f}"
                    f"  {r['p50_ms']:.3f}  {r['p95_ms']:.3f}  {r['p99_ms']:.3f}\n"
                    for r in recs_sorted
                )
                (load_dir / dat_name).write_text(dat_content)
                ver_tag = f"v{v}" if v[:1].isdigit() else v
                label = f"{proto}/{ver_tag}" if multi_version else proto
                curves.append((label, dat_name))

        if not curves:
            continue

        svg = f"{safe}.svg"
        plot_lines = ', \\\n     '.join(
            f"'{dat}' using 1:2 with linespoints lw 2 pt 7 title '{label}'"
            for label, dat in curves
        )
        script = (
            svg_preamble(svg, f"Throughput — {op}", w=1000, h=500)
            + "set xlabel 'Concurrency'\n"
            + "set ylabel 'Requests/s'\n"
            + 'set key top left\n'
            + f"plot {plot_lines}\n"
        )
        if run_gnuplot(script, load_dir, svg):
            generated.append(f"load/{svg}")

    return generated


# ── Criterion charts ──────────────────────────────────────────────────────────


def generate_criterion_charts(
    crit_dir: Path,
    versions: list[str],
    all_criterion: dict[str, dict[str, float]],
) -> list[str]:
    """Generate grouped bar charts per category (symmetric, asymmetric, kem, signature, key_creation).

    X-axis: benchmark variant (algorithm + bench function); bars: (protocol, version) combinations.
    Returns relative paths (e.g. 'criterion/symmetric_encrypt.svg').
    """
    if not gnuplot_available():
        return []

    crit_dir.mkdir(parents=True, exist_ok=True)
    generated: list[str] = []

    # Classify all bench IDs into categories.
    # cat_data: {cat_id: {bench_label: {(protocol,version): ns}}}
    cat_data: dict[str, dict[str, dict[tuple, float]]] = defaultdict(
        lambda: defaultdict(dict)
    )
    for v in versions:
        for bid, ns in all_criterion.get(v, {}).items():
            protocol, op_type, algorithm = bench_id_to_parts(bid)
            slash = bid.find('/')
            bench_fn = bid[slash + 1 :] if slash >= 0 else ''
            cat = _criterion_category(op_type, algorithm, bench_fn)
            if cat is None:
                continue
            algo_key = _criterion_algo_key(algorithm, bench_fn)
            # Keep only the minimum (fastest) time if the same label appears multiple times.
            prev = cat_data[cat][algo_key].get((protocol, v), float('inf'))
            cat_data[cat][algo_key][(protocol, v)] = min(ns, prev)

    multi_version = len(versions) > 1

    for chart_id, chart_title, _ in CHART_DEFS:
        algo_data = cat_data.get(chart_id, {})
        if not algo_data:
            continue

        algos = sorted(algo_data.keys())

        # Collect all (protocol, version) combos present in this chart.
        combos: list[tuple[str, str]] = []
        for pv_dict in algo_data.values():
            for pv in pv_dict:
                if pv not in combos:
                    combos.append(pv)
        combos.sort(key=lambda pv: (_PROTOCOL_ORDER.get(pv[0], 99), pv[1]))

        n = len(combos)
        bar_w = 0.8 / n if n > 0 else 0.8

        dat = f"{chart_id}.dat"
        header = '# idx  ' + '  '.join(f"{p}/{v}" for p, v in combos) + '  label'
        rows = [header]
        for i, algo in enumerate(algos):
            vals = '  '.join(
                f"{algo_data[algo].get(pv, 0.0) / 1_000:.2f}" for pv in combos
            )
            rows.append(f'{i}  {vals}  "{algo}"')
        (crit_dir / dat).write_text('\n'.join(rows) + '\n')

        svg = f"{chart_id}.svg"
        plot_parts = []
        for ci, (proto, v) in enumerate(combos):
            offset = (ci - n / 2 + 0.5) * bar_w
            ver_tag = f"v{v}" if v[:1].isdigit() else v
            label = f"{proto}/{ver_tag}" if multi_version else proto
            plot_parts.append(
                f"'{dat}' using ($1+{offset:.3f}):{ci + 2}"
                f" with boxes lw 1 title '{label}'"
            )
        plot = ', \\\n     '.join(plot_parts)
        xtics = ', '.join(f'"{a}" {i}' for i, a in enumerate(algos))
        w = min(max(1200, 200 + 120 * len(algos) * n), 2000)
        script = (
            svg_preamble(svg, chart_title, w=w, h=600)
            + "set ylabel 'Time (µs)'\n"
            + 'set style data boxes\n'
            + 'set style fill solid 0.7 border -1\n'
            + f"set boxwidth {bar_w:.3f}\n"
            + 'set grid ytics\nset key top right\nset xtics rotate by -30\n'
            + f"set xtics ({xtics})\n"
            + f"plot {plot}\n"
        )
        if run_gnuplot(script, crit_dir, svg):
            generated.append(f"criterion/{svg}")

    return generated


# ── Criterion markdown tables ───────────────────────────────────────────────────


def _build_criterion_tables(
    versions: list[str],
    criterion_data: dict[str, dict[str, float]],
) -> list[tuple[str, list[str]]]:
    """Return [(chart_title, table_lines)] for each CHART_DEF category that has data."""
    cat_data: dict[str, dict[str, dict[tuple, float]]] = defaultdict(
        lambda: defaultdict(dict)
    )
    for v in versions:
        for bid, ns in criterion_data.get(v, {}).items():
            protocol, op_type, algorithm = bench_id_to_parts(bid)
            slash = bid.find('/')
            bench_fn = bid[slash + 1 :] if slash >= 0 else ''
            cat = _criterion_category(op_type, algorithm, bench_fn)
            if cat is None:
                continue
            algo_key = _criterion_algo_key(algorithm, bench_fn)
            prev = cat_data[cat][algo_key].get((protocol, v), float('inf'))
            cat_data[cat][algo_key][(protocol, v)] = min(ns, prev)

    multi_version = len(versions) > 1
    results: list[tuple[str, list[str]]] = []

    for chart_id, chart_title, _ in CHART_DEFS:
        algo_data = cat_data.get(chart_id, {})
        if not algo_data:
            continue

        algos = sorted(algo_data.keys())

        combos: list[tuple[str, str]] = []
        for pv_dict in algo_data.values():
            for pv in pv_dict:
                if pv not in combos:
                    combos.append(pv)
        combos.sort(key=lambda pv: (_PROTOCOL_ORDER.get(pv[0], 99), pv[1]))

        # Key creation is a server management operation; wire-format and JOSE
        # columns add noise without insight — restrict to ttlv-json only.
        if chart_id == 'key_creation':
            combos = [(p, v) for p, v in combos if p == 'ttlv-json']
        if not combos:
            continue

        def _col(proto: str, v: str) -> str:
            ver_tag = f"v{v}" if v[:1].isdigit() else v
            return f"{proto}/{ver_tag}" if multi_version else proto

        col_headers = [_col(p, v) for p, v in combos]
        header = '| Benchmark | ' + ' | '.join(col_headers) + ' |'
        divider = '|---|' + '---|' * len(combos)

        rows: list[str] = [header, divider]
        for algo in algos:
            cells = [algo]
            for pv in combos:
                ns = algo_data[algo].get(pv)
                cells.append(_fmt_time(ns) if ns is not None else '—')
            rows.append('| ' + ' | '.join(cells) + ' |')

        results.append((chart_title, rows))

    return results


# ── Environment / protocol / methodology sections ─────────────────────────────


def parse_env_json(version_dir: Path) -> dict:
    """Load env.json produced by bench_collect_env, or return {}."""
    p = version_dir / 'env.json'
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding='utf-8'))
    except (json.JSONDecodeError, OSError):
        return {}


def _render_env_section(env_data: dict[str, dict], versions: list[str]) -> list[str]:
    """Render the ## Benchmark Environment section from per-version env.json data."""
    if not env_data:
        return []

    lines: list[str] = ['## Benchmark Environment', '']
    multi = len(versions) > 1

    for v in versions:
        env = env_data.get(v)
        if not env:
            continue

        if multi:
            ver_tag = f"v{v}" if v[:1].isdigit() else v
            lines += [f"### Version {ver_tag}", '']

        # ── System / server info ──────────────────────────────────────────────
        rows: list[tuple[str, str]] = []
        rows.append(('Date', env.get('date', '—')))

        build = env.get('build_mode', 'release')
        variant = env.get('variant', 'non-fips')
        rows.append(('Build', f"{build} / {variant}"))

        workers = env.get('http_workers')
        if workers:
            rows.append(('HTTP workers (Actix-web)', str(workers)))

        rows.append(('Database', 'SQLite (temporary, single benchmark run)'))

        cpu = env.get('cpu_model', '—')
        mhz = env.get('cpu_mhz')
        rows.append(('CPU', f"{cpu} @ {mhz:,} MHz" if mhz else cpu))

        phys = env.get('cpu_physical_cores')
        logical = env.get('cpu_logical_cores')
        if phys and logical:
            rows.append(('CPU cores', f"{phys} physical / {logical} logical (HT)"))
        elif logical:
            rows.append(('CPU cores', str(logical)))

        mem = env.get('mem_gb')
        if mem:
            rows.append(('RAM', f"{mem} GB"))

        rows.append(('OS', env.get('os', '—')))
        kernel = env.get('kernel', '')
        if kernel:
            rows.append(('Kernel', kernel))

        lines += ['| Field | Value |', '|---|---|']
        for field, val in rows:
            lines.append(f"| {field} | {val} |")
        lines.append('')

        # ── Benchmark parameters ──────────────────────────────────────────────
        lines += ['### Load test parameters', '', '| Parameter | Value |', '|---|---|']
        lines.append(f"| Mode | {env.get('bench_mode', 'all')} |")
        lines.append(f"| Protocols | {env.get('bench_protocol', 'all')} |")
        lines.append(
            f"| Measurement window | {env.get('bench_time_s', 20)} s per concurrency level |"
        )
        lines.append(f"| Concurrency levels | {env.get('bench_concurrency', '—')} |")
        lines.append(f"| Warm-up | {env.get('bench_warmup_s', 5)} s |")
        lines.append(
            f"| Cooldown between levels | {env.get('bench_cooldown_s', 2)} s |"
        )
        lines.append('')

        # ── Raw lscpu ─────────────────────────────────────────────────────────
        lscpu = env.get('lscpu', '')
        if lscpu:
            lines += ['### CPU detail (`lscpu`)', '', '```text', lscpu, '```', '']

    return lines


def _fmt_signed_time(ns: float) -> str:
    """Format a signed nanosecond delta."""
    if ns == 0:
        return '0 ns'
    prefix = '+' if ns > 0 else '−'
    return f"{prefix}{_fmt_time(abs(ns))}"


def _render_pkcs11_overhead_section(
    overhead_data: dict[str, dict[str, object]], versions: list[str]
) -> list[str]:
    """Render valid PKCS#11 Ed25519 overhead tiers and internal phases."""
    available: dict[str, dict[str, object]] = {}
    for version in versions:
        data = overhead_data.get(version, {})
        if data.get('tiers') or data.get('phases'):
            available[version] = data
    if not available:
        return []

    lines = [
        '## PKCS#11 Ed25519 signing overhead',
        '',
        'These differential micro-benchmarks use the same Ed25519 key, payload,'
        ' server, runtime, and Criterion configuration. The JSON tiers target'
        ' `/kmip/2_1`; binary TTLV and the full PKCS#11 path target `/kmip`.'
        ' The typed binary and PKCS#11 values are A/B/A/B bracketed means (one'
        ' measurement before and one after each other) to reduce temporal drift.'
        ' Component-only rows'
        ' intentionally have no incremental delta; end-to-end rows compare with'
        ' the nearest lower-level path named in the **Compared with** column.',
        '',
        '> **Public reference:** the software benchmark report records'
        ' `ttlv-json` `eddsa-ed25519/sign` at'
        ' [87.0 µs](https://docs.cosmian.com/key_management_system/benchmarks/'
        'ckms_bench/report.html). That measurement uses a pre-serialized full'
        ' `RequestMessage` sent over raw HTTP and only collects then drops the'
        ' response. It is therefore not directly comparable with typed'
        ' `KmsClient::sign` or the full PKCS#11 path. The machine-local'
        ' **Published-equivalent full-message raw HTTP** tier below is the fair'
        ' reference for incremental comparisons.',
        '',
    ]
    tier_order = {
        name: index for index, (name, _, _) in enumerate(_PKCS11_OVERHEAD_TIERS)
    }
    phase_order = {name: index for index, name in enumerate(_PKCS11_PHASE_ORDER)}

    for version, data in available.items():
        ver_tag = f"v{version}" if version[:1].isdigit() else version
        lines += [f"### Version {ver_tag}", '']

        metadata = []
        for key, label in (
            ('payload_bytes', 'payload'),
            ('request_bytes', 'JSON request'),
            ('response_bytes', 'JSON response'),
            ('binary_request_bytes', 'binary request'),
            ('binary_response_bytes', 'binary response'),
        ):
            value = data.get(key)
            if isinstance(value, int):
                metadata.append(f'{label}: **{value} bytes**')
        if metadata:
            payload_mode = (
                'varying payloads'
                if data.get('varying_payload') is True
                else 'fixed payload'
            )
            lines += [f"Ed25519; {payload_mode}; {'; '.join(metadata)}.", '']

        raw_tiers = data.get('tiers', [])
        tiers = (
            [tier for tier in raw_tiers if str(tier.get('name')) in tier_order]
            if isinstance(raw_tiers, list)
            else []
        )
        if tiers:
            lines += [
                '#### Tier comparison',
                '',
                '| Protocol | Tier | Mean | Median | Mean 95% CI | Compared with |'
                ' Incremental delta | Incremental change |',
                '|---|---|---:|---:|---:|---|---:|---:|',
            ]
            tiers = sorted(
                tiers,
                key=lambda tier: (
                    tier_order.get(str(tier.get('name')), len(tier_order)),
                    str(tier.get('name')),
                ),
            )
            by_name = {str(tier['name']): tier for tier in tiers}
            for tier in tiers:
                name = str(tier['name'])
                mean_ns = float(tier['mean_ns'])
                label, baseline_name = _PKCS11_TIER_LABELS.get(
                    name, (f'`{name}`', None)
                )
                median = tier.get('median_ns')
                median_text = _fmt_time(float(median)) if median is not None else '—'
                lower = tier.get('lower_ns')
                upper = tier.get('upper_ns')
                ci_text = (
                    f"{_fmt_time(float(lower))}–{_fmt_time(float(upper))}"
                    if lower is not None and upper is not None
                    else '—'
                )
                baseline = by_name.get(baseline_name) if baseline_name else None
                if baseline is None:
                    compared_with = '—'
                    delta_text = '—'
                    percent_text = '—'
                else:
                    baseline_mean = float(baseline['mean_ns'])
                    delta = mean_ns - baseline_mean
                    compared_with = _PKCS11_TIER_LABELS[baseline_name][0]
                    delta_text = _fmt_signed_time(delta)
                    percent_text = f"{delta / baseline_mean:+.1%}"
                lines.append(
                    f'| `pkcs11` | {label} | {_fmt_time(mean_ns)} | {median_text} |'
                    f' {ci_text} | {compared_with} | {delta_text} |'
                    f' {percent_text} |'
                )
            lines.append('')

        raw_phases = data.get('phases', [])
        phases = raw_phases if isinstance(raw_phases, list) else []
        if phases:
            phases = sorted(
                phases,
                key=lambda phase: (
                    phase_order.get(str(phase.get('name')), len(phase_order)),
                    str(phase.get('name')),
                ),
            )
            lines += [
                '#### Internal phase boundaries',
                '',
                'Boundary timings are nested and inclusive: `C_SignMessage` body → session'
                ' callback → private-key Sign → backend remote Sign → Tokio `block_on`'
                ' → typed KMS client Sign. They are **not exclusive components and'
                ' must not be summed**. Session map lookup, per-session lock wait,'
                ' backend lookup, request construction, and signature copy are leaf'
                ' timings.',
                '',
                'The p50/p95/p99 values are approximate upper bounds from log2'
                ' histogram buckets. Mean and maximum values are exact.',
                '',
                '| Phase | Semantics | Mean (exact) | p50 upper bound |'
                ' p95 upper bound | p99 upper bound | Max (exact) | Samples |',
                '|---|---|---:|---:|---:|---:|---:|---:|',
            ]
            for phase in phases:
                name = str(phase['name'])
                mean_ns = float(phase['mean_ns'])

                def measurement(field: str) -> str:
                    value = phase.get(field)
                    return _fmt_time(float(value)) if value is not None else '—'

                if name in _PKCS11_INCLUSIVE_PHASES:
                    semantics = 'Inclusive boundary'
                elif name in _PKCS11_LEAF_PHASES:
                    semantics = 'Leaf timing'
                else:
                    semantics = 'Unclassified'
                label = _PKCS11_PHASE_LABELS.get(name, f'`{name}`')
                lines.append(
                    f'| {label} | {semantics} | {_fmt_time(mean_ns)} |'
                    f" {measurement('p50_ns')} | {measurement('p95_ns')} |"
                    f" {measurement('p99_ns')} | {measurement('max_ns')} |"
                    f" {phase['count']} |"
                )
            lines.append('')

    return lines


def _render_protocol_section(
    *, is_hsm: bool = False, is_hsm_kek: bool = False, is_pkcs11: bool = False
) -> list[str]:
    """Render the static ## Protocols section.

    When `is_hsm` is set, only ttlv-json is documented: `ttlv-bytes` and
    `jose` are both excluded (for different reasons — see below), so
    `--hsm` benchmarks exercise a single wire protocol.

    When `is_hsm_kek` is set, all three protocols are documented exactly as
    in the plain software report, preceded by a short note that this report
    benchmarks software crypto with an HSM-resident *key-wrapping* key
    (KEK), not HSM-delegated crypto operations (see the dedicated HSM
    report for that).

    When `is_pkcs11` is set, the caller-facing protocol is the real Cryptoki C
    ABI. The provider's remote Sign implementation then uses KMIP 2.1 binary
    TTLV over the `/kmip` octet-stream endpoint.
    """
    if is_pkcs11:
        return [
            '## Protocols',
            '',
            'The caller-facing protocol benchmarked here is the `cosmian_pkcs11`'
            " provider's real PKCS#11 v3.1 Cryptoki C ABI: the benchmark `dlopen()`s"
            ' the built'
            ' shared library (`libcosmian_pkcs11.{so,dylib}`) and resolves its'
            ' standard interface through `C_GetInterface` — the same call path'
            ' v3-aware PKCS#11'
            ' consumers (Oracle TDE, OpenSSH, disk-encryption tools) use. For remote'
            ' Sign, the provider wraps the KMIP operation in a KMIP 2.1'
            ' `RequestMessage`, serializes binary TTLV, and sends'
            ' `application/octet-stream` to `POST /kmip`; the binary TTLV response is'
            ' fully deserialized before `C_SignMessage` returns.',
            '',
            '| Interface | Transport | Description |',
            '|---|---|---|',
            '| **PKCS#11 (Cryptoki v3.1)** | `C_GetInterface` + C ABI | `C_Initialize`,'
            ' `C_OpenSession`, `C_EncryptInit`/`C_Encrypt`, `C_DecryptInit`/`C_Decrypt`,'
            ' `C_MessageSignInit`/`C_SignMessage`, `C_VerifyInit`/`C_Verify`,'
            ' `C_GenerateKey` |',
            '| **Provider → KMS Sign** | KMIP 2.1 binary TTLV over HTTP |'
            ' `POST /kmip`, `application/octet-stream` |',
            '',
            '',
        ]
    if is_hsm:
        return [
            '## Protocols',
            '',
            'This report benchmarks cryptographic operations delegated to an HSM'
            ' (PKCS#11) via the KMS `CryptoOracle`, exercised over a single wire'
            ' protocol: **ttlv-json**.',
            '',
            '| Protocol | Transport | Encoding | Endpoint | Description |',
            '|---|---|---|---|---|',
            '| **ttlv-json** | HTTP/1.1 | KMIP 2.1 JSON-TTLV | `POST /kmip/2_1` |'
            ' Primary interoperability protocol — any KMIP 2.1 compliant client can use it |',
            '',
            '**KMIP TTLV** (Tag-Type-Length-Value) is the native encoding of the KMIP 2.1 standard'
            ' (OASIS KMIP Spec v2.1, §9.1).'
            " The **JSON** variant wraps every field in a `{\"tag\": …, \"type\": …, \"value\": …}`"
            ' JSON object and base64-encodes binary values.',
            '',
            '**ttlv-bytes is not benchmarked here.** Measuring it would require running it'
            ' either against the same HSM-resident key/token as the ttlv-json sweep (strictly'
            ' after it completes) or on a fresh token started specifically for that purpose.'
            ' The former was tried first and rejected: cumulative SoftHSM2 token load from the'
            ' preceding ttlv-json sweep contaminated every ttlv-bytes measurement, making'
            ' ttlv-json appear *faster* than ttlv-bytes in every single operation — the'
            ' opposite of the software baseline (where ttlv-bytes is consistently faster, as'
            ' expected, since it skips JSON parsing). Rather than publish numbers that are'
            ' measurement artefacts of test ordering, ttlv-bytes is omitted from this report'
            ' until the harness can measure both protocols under equivalent conditions'
            ' (e.g. independent tokens per protocol).',
            '',
            '**JOSE is not benchmarked here.** The JOSE REST key-creation endpoint'
            ' (`POST /v1/crypto/keys`) has no parameter to request a caller-chosen'
            ' `kid`, and HSM-resident key delegation requires the client to choose'
            ' the `hsm::<slot>::<uuid>` unique identifier up front (the HSM has no'
            ' server-assigned ID scheme) — so an HSM-resident key cannot be created'
            ' through the JOSE endpoints at all.',
            '',
        ]
    return [
        '## Protocols',
        '',
        *(
            [
                '> **HSM-backed KEK, software crypto.** The root key-encryption-key (KEK)'
                ' used to wrap every benchmarked key is HSM-resident (SoftHSM2); only its'
                ' unwrap touches the HSM. Encrypt/Sign themselves still execute in KMS'
                ' software (OpenSSL), same as the plain software baseline — this report'
                ' isolates the cost of HSM-backed key wrapping. For benchmarks where the'
                ' cryptographic operation itself executes ON the HSM, see the dedicated'
                ' HSM-delegated-crypto report.',
                '',
            ]
            if is_hsm_kek
            else []
        ),
        'The KMS server was exercised over three distinct wire protocols.',
        'Each benchmark column is labelled with the protocol name it used.',
        '',
        '| Protocol | Transport | Encoding | Endpoint | Description |',
        '|---|---|---|---|---|',
        '| **ttlv-json** | HTTP/1.1 | KMIP 2.1 JSON-TTLV | `POST /kmip/2_1` |'
        ' Primary interoperability protocol — any KMIP 2.1 compliant client can use it |',
        '| **ttlv-bytes** | HTTP/1.1 | KMIP 2.1 binary TTLV | `POST /kmip` |'
        ' Binary wire format; eliminates JSON parsing overhead — typically 10–30 % faster |',
        '| **jose** | HTTP/1.1 | JWE / JWS (JOSE) | `POST /v1/crypto/` |'
        ' REST API for OAuth2/OIDC workloads that prefer JWA algorithm identifiers over KMIP |',
        '',
        '**KMIP TTLV** (Tag-Type-Length-Value) is the native encoding of the KMIP 2.1 standard'
        ' (OASIS KMIP Spec v2.1, §9.1).'
        " The **JSON** variant wraps every field in a `{\"tag\": …, \"type\": …, \"value\": …}`"
        ' JSON object and base64-encodes binary values.'
        ' The **binary** variant uses a compact 8-byte fixed header (3-byte tag, 1-byte type,'
        ' 4-byte length) per value, removing JSON tokenisation, base64, and UTF-8 overhead entirely.',
        '',
        '**JOSE** (JSON Object Signing and Encryption, RFC 7516 / RFC 7515)'
        ' exposes KMS key material through `/v1/crypto/` REST endpoints.'
        ' It is used by cloud integrations (Google CSE, Microsoft DKE, Azure EKM)'
        ' and any workload that speaks JWA algorithm identifiers (A256GCM, RS256, ES384 …)'
        ' rather than KMIP semantics.',
        '',
    ]


def _render_methodology_section(
    *, is_hsm: bool = False, is_hsm_kek: bool = False, is_pkcs11: bool = False
) -> list[str]:
    """Render the static ## Benchmark Methodology section."""
    if is_pkcs11:
        return [
            '## Benchmark Methodology',
            '',
            '### Real Cryptoki C ABI, one session per worker',
            '',
            'The benchmark binary (`cosmian_pkcs11_bench`, driven by'
            ' `mise bench:load-pkcs11`) `dlopen()`s the built `cosmian_pkcs11` shared'
            ' library, resolves the v3.1 function table through `C_GetInterface`,'
            ' and calls it directly — the same'
            ' code path a real PKCS#11 consumer application uses, as opposed to'
            ' `mise bench:load`, which drives the KMIP REST API directly through the'
            ' `ckms` client library.',
            '',
            'By default each worker thread owns a dedicated `C_OpenSession` handle.'
            ' The provider looks the handle up in its session map and serializes only'
            ' access to that individual session with a per-session lock, so unrelated'
            ' worker sessions can progress independently. `--shared-session` is an'
            ' opt-in comparison mode that reproduces the former single-session'
            ' contention model; it is not the default methodology.',
            '',
            'For the Ed25519 Sign path measured in this report,'
            ' `C_MessageSignInit` runs once during setup and each'
            ' `C_SignMessage` crosses the'
            ' synchronous PKCS#11 boundary, builds a KMIP 2.1 `RequestMessage`,'
            ' serializes it as binary TTLV, sends it to the `/kmip` octet-stream'
            ' endpoint, and parses the binary TTLV response before copying the'
            ' signature into the caller-owned buffer.',
            '',
            '### Independent operations',
            '',
            'Unlike the software/HSM reports above, where `encrypt` and `sign-verify`'
            ' each measure a single named request, this report measures every Cryptoki'
            ' operation **independently**: `encrypt` (`C_EncryptInit`/`C_Encrypt`),'
            ' `decrypt` (`C_DecryptInit`/`C_Decrypt`, against ciphertext produced once'
            ' during setup — not timed), Ed25519 `sign`'
            ' (`C_MessageSignInit` once + `C_SignMessage` per message), RSA `sign`'
            ' (`C_SignInit`/`C_Sign`), `verify`'
            ' (`C_VerifyInit`/`C_Verify`), and `key-creation`'
            ' (`C_GenerateKey`+`C_DestroyObject`, ephemeral AES key per iteration) each'
            ' get their own concurrency sweep and their own row/chart below.',
            '',
            '`C_VerifyInit`/`C_Verify` are implemented and benchmarked through the'
            ' same real Cryptoki function table. Verify rows are therefore ordinary'
            ' measured operations, not placeholders or unsupported-operation probes.',
            '',
            '`C_GenerateKeyPair` is not implemented either (asymmetric keys are always'
            ' created through the KMS REST API, not PKCS#11), so `key-creation` only'
            ' covers the one Cryptoki key-creation path the provider does support:'
            ' symmetric `C_GenerateKey`.',
            '',
            '### Load test (`mise bench:load-pkcs11`)',
            '',
            'The load test sweeps a configurable list of concurrency levels, mirroring'
            ' `mise bench:load`'
            "'s own sweep mechanics exactly: at each level *N* concurrent OS threads"
            ' call the target Cryptoki function in a tight loop for a fixed'
            ' **measurement window** (default: 20 s), preceded by a **warm-up phase**'
            ' (default: 5 s) that is excluded from measurements, followed by a'
            ' **cooldown** (default: 2 s) before the next level.',
            'Recorded metrics per *(operation, concurrency)* pair:',
            '',
            '- **Throughput** — Cryptoki calls per second',
            '- **p50 / p95 / p99** — per-call latency percentiles (ms)',
            '',
            '> **Infrastructure note:** The benchmark server uses a **local SQLite**'
            ' backend (temporary, discarded after the run). Throughput figures will'
            ' differ on a production deployment backed by PostgreSQL or Redis-Findex.',
            '',
        ]
    if is_hsm:
        return [
            '## Benchmark Methodology',
            '',
            '### HSM delegation model',
            '',
            'Every operation in this report is executed against an `hsm::<slot>::<uuid>`'
            ' unique identifier. The KMS server routes both key generation'
            ' (`Create`/`CreateKeyPair`) and cryptographic operations (`Encrypt`/`Sign`)'
            ' for such keys to the HSM'
            "'s `CryptoOracle` (PKCS#11) instead of executing them in KMS software —"
            ' the benchmarked latency/throughput is therefore dominated by the PKCS#11'
            ' round-trip to the HSM, not by in-process OpenSSL. `Verify` is not'
            ' implemented for HSM-resident keys at all yet, for any algorithm, and is'
            ' intentionally excluded from this report.',
            '',
            '> **Reference HSM:** SoftHSM2 (a software PKCS#11 simulator), single'
            ' SoftHSM2 token per benchmark run. A hardware HSM will exhibit different'
            ' absolute numbers (typically bound by the HSM'
            "'s own internal parallelism and network/PCIe transport latency rather than"
            ' loopback TCP), but the same operations and request shapes apply unchanged.',
            '',
            '### Algorithm coverage and SoftHSM2-specific constraints',
            '',
            'Every algorithm variant of the KMS'
            "'s `CryptoAlgorithm` (encrypt) and `SigningAlgorithm` (sign) oracle enums"
            ' reachable via an ordinary (non-prehashed-digest-only) KMIP request is'
            ' covered:',
            '',
            '| Category | Algorithms covered | Notes |',
            '|---|---|---|',
            '| Encrypt | AES-GCM, AES-CBC, RSA-OAEP-SHA256, RSA-OAEP-SHA1, RSA-PKCS1v15 | 2048-bit RSA, 256-bit AES |',
            '| Sign | RSA-PSS, RSA-PKCS1v15 (SHA1/256/384/512 hash-and-sign) | 2048-bit RSA |',
            '| Sign | ECDSA P-256 / P-384 | **Prehashed only** (`digested_data`): SoftHSM2 2.6.1 implements only the raw `CKM_ECDSA` mechanism, not the combined `CKM_ECDSA_SHA*` hash-and-sign mechanisms |',
            '| Sign | EdDSA Ed25519 / Ed448 | Non-FIPS only; pure, un-hashed `CKM_EDDSA` — the full message is sent, never a digest |',
            '| Key creation | AES-256, RSA-2048, EC P-256, Ed25519, Ed448 | P-521 excluded — see below |',
            '',
            'Two gaps are **not** HSM-delegation limitations and are excluded for'
            ' unrelated reasons:',
            '',
            '- **P-521 key creation**: `crate/crypto/src/crypto/elliptic_curves/operation.rs`'
            " derives the KMIP `CryptographicLength` from the generated private scalar's"
            ' serialized byte length rather than the curve'
            "'s nominal bit length, which can under-count P-521 keys by one byte and makes"
            ' `HSM::create_keypair` reject the result — a pre-existing bug unrelated to HSM'
            ' delegation, tracked as a follow-up.',
            '- **Bare `SigningAlgorithm::RsaPkcsV15`** (a raw `CKM_RSA_PKCS` sign over a'
            ' caller-supplied `DigestInfo` blob) has no ordinary KMIP request shape that'
            ' reaches it — `padding_method: PKCS1v15` without an explicit digest always'
            ' resolves to one of the hash-and-sign variants above, which exercise the'
            ' same PKCS#11 mechanism family end-to-end.',
            '',
            '### Payload sizes',
            '',
            'All encrypt benchmarks use a **64-byte** fixed-size random payload'
            ' (128 bytes for AES-CBC/PKCS1v15, which pad to a whole block); all sign'
            ' benchmarks use a **32-byte** fixed-size message (or, for prehashed ECDSA,'
            ' a 32-byte SHA-256 digest of that same message) — small enough that the'
            ' RSA-2048 modulus bounds every RSA variant without truncation.',
            '',
            '### SoftHSM2 per-token degradation (key creation only)',
            '',
            'Concurrent/cumulative RSA and EC key **generation** against a single'
            ' SoftHSM2 token progressively degrades that token — later PKCS#11'
            ' operations, even unrelated `Encrypt`/`Sign` calls against different keys,'
            ' can slow from milliseconds to *minutes* per request. This is a SoftHSM2'
            ' limitation (a software simulator, not built for heavy concurrent/cumulative'
            ' key generation on one token), not a KMS defect. Mitigations applied to keep'
            ' this report reproducible:',
            '',
            '- Load-test key-creation concurrency is capped at 4 regardless of the'
            ' requested sweep (`PreparedLoadOp::max_concurrency`).',
            '- The `bench/load-hsm --delegated` task runs `key-creation`, `encrypt`, and'
            ' `sign-verify` as three separate SoftHSM2 sessions (each with its own fresh'
            ' token) when `--mode all` (the default), so key-creation load never'
            ' contaminates the encrypt/sign token; results are merged into this single'
            ' report afterward.',
            '',
            '### Why ttlv-json only (no ttlv-bytes)',
            '',
            'An earlier version of this report benchmarked both `ttlv-json` and `ttlv-bytes`'
            ' for every HSM-delegated operation, sharing one HSM-resident key between the two'
            ' protocol variants and measuring `ttlv-json`'
            "'s full concurrency sweep before `ttlv-bytes`"
            "'s. Every single result inverted the expected direction — `ttlv-json` appeared"
            ' *faster* than `ttlv-bytes`, the opposite of the software baseline (where binary'
            ' TTLV is consistently faster, since it skips JSON parsing). Root cause: the'
            ' `ttlv-bytes` sweep always ran second against the same already-active HSM'
            ' session/token, so it inherited whatever cumulative SoftHSM2 degradation the'
            ' `ttlv-json` sweep had already caused (the same class of per-token degradation'
            ' described above, triggered here by sustained Encrypt/Sign call volume rather'
            ' than key generation) — a test-ordering artefact, not a real protocol'
            ' difference. This report therefore benchmarks `ttlv-json` only, until the'
            ' harness can measure both protocols under equivalent conditions (e.g.'
            ' independent SoftHSM2 tokens per protocol).',
            '',
            '### Load test (`ckms bench --load --hsm`)',
            '',
            'The load test sweeps a configurable list of concurrency levels.'
            ' At each level *N* concurrent async tasks send pre-serialised requests in tight loops'
            ' for a fixed **measurement window** (default: 20 s), preceded by a **warm-up phase**'
            ' (default: 5 s) that is excluded from measurements.'
            ' Pre-serialisation happens once at setup time and the same bytes are reused on every iteration,'
            ' isolating server-side (and HSM-side) latency from client-side encoding overhead.'
            ' Key **creation** cannot be pre-serialised the same way — the HSM has no'
            ' auto-generated ID, so each iteration builds a fresh request with a distinct'
            ' `hsm::` unique identifier.',
            'Recorded metrics per *(protocol, operation, concurrency)* triple:',
            '',
            '- **Throughput** — requests per second (req/s)',
            '- **p50 / p95 / p99** — round-trip latency percentiles (ms)',
            '',
            '### Criterion micro-benchmarks (`ckms bench --hsm`)',
            '',
            'Criterion (Rust, v0.5) measures the **round-trip latency of a single request**'
            ' from the ckms client library through the KMS server (and, for these'
            ' benchmarks, onward to the HSM) and back over a loopback TCP connection.'
            ' The server is started once and kept alive across all benchmarks in the suite.',
            'The reported value is the **mean ± 95 % confidence interval** over a configurable'
            ' number of samples (preset `quick`: 3 s warm-up + 5 s measurement per benchmark).',
            '',
            '> **Infrastructure note:** The load test and criterion benchmarks both use a'
            ' **local SQLite** backend (temporary, discarded after the run) for the KMS'
            ' server'
            "'s own metadata store — the key material itself resides on the HSM, never in"
            ' SQLite. Throughput figures will differ on a production deployment backed by'
            ' PostgreSQL or Redis-Findex, and even more so against a hardware HSM instead'
            ' of SoftHSM2.',
            '',
        ]
    return [
        '## Benchmark Methodology',
        '',
        *(
            [
                '> **HSM-backed KEK.** The server is started with a SoftHSM2-registered'
                ' `key_encryption_key` (KEK): every benchmarked software key is wrapped by'
                ' this HSM-resident KEK at rest, and unwrapped via a PKCS#11 round-trip on'
                ' each use. All other methodology below (payload sizes, load-test/criterion'
                ' procedure) is identical to the plain software baseline — the only'
                ' difference is this extra HSM unwrap step per operation.',
                '',
            ]
            if is_hsm_kek
            else []
        ),
        '### Plaintext / payload sizes',
        '',
        'All encrypt/decrypt benchmarks use a **fixed-size random payload**.'
        ' Sizes represent a realistic key-wrapping or small-message encryption workload'
        ' without introducing significant data-transfer overhead on a loopback connection.',
        '',
        '| Algorithm / category | Plaintext size | Notes |',
        '|---|---|---|',
        '| AES-GCM (128 / 192 / 256-bit key) | 64 bytes | FIPS 140-3 |',
        '| AES-GCM-SIV (128 / 256-bit key) | 64 bytes | Non-FIPS |',
        '| AES-XTS (128 / 256-bit AES = 256 / 512-bit key) | 64 bytes | FIPS 140-3; requires 16-byte IV |',
        '| ChaCha20-Poly1305 (256-bit key) | 64 bytes | Non-FIPS |',
        '| ECIES — P-256 / P-384 / P-521 | 64 bytes | Non-FIPS; EC public-key encryption |',
        '| Salsa Sealed Box (X25519) | 64 bytes | Non-FIPS |',
        '| Covercrypt (attribute-based encryption) | 64 bytes | Non-FIPS |',
        '| JOSE JWE — `dir` + AES-GCM (A128GCM / A192GCM / A256GCM) | 64 bytes | Symmetric (direct key agreement) |',
        '| JOSE JWE — RSA-OAEP + AES-GCM (2048 / 4096-bit) | 64 bytes | Asymmetric (RSA-OAEP CEK wrapping) |',
        '| RSA-OAEP (2048 / 3072 / 4096-bit) | 32 bytes | Limited by RSA block size |',
        '| RSA-PKCS#1 v1.5 (2048 / 3072 / 4096-bit) | 32 bytes | Non-FIPS |',
        '| RSA-AES Key Wrap — KWP (2048 / 3072 / 4096-bit) | 32 bytes | FIPS 140-3 |',
        '| Sign / Verify — all algorithms | 32 bytes | Message is hashed internally |',
        '| JOSE JWS / MAC | 32 bytes | |',
        '',
        '### Load test (`ckms bench --load`)',
        '',
        'The load test sweeps a configurable list of concurrency levels.'
        ' At each level *N* concurrent async tasks send pre-serialised requests in tight loops'
        ' for a fixed **measurement window** (default: 20 s), preceded by a **warm-up phase**'
        ' (default: 5 s) that is excluded from measurements.'
        ' Pre-serialisation happens once at setup time and the same bytes are reused on every iteration,'
        ' isolating server-side KMS latency from client-side encoding overhead.',
        'Recorded metrics per *(protocol, operation, concurrency)* triple:',
        '',
        '- **Throughput** — requests per second (req/s)',
        '- **p50 / p95 / p99** — round-trip latency percentiles (ms)',
        '',
        '### Criterion micro-benchmarks (`ckms bench`)',
        '',
        'Criterion (Rust, v0.5) measures the **round-trip latency of a single request**'
        ' from the ckms client library through the KMS server and back over a loopback TCP connection.'
        ' The server is started once and kept alive across all benchmarks in the suite.',
        'The reported value is the **mean ± 95 % confidence interval** over a configurable'
        ' number of samples (preset `quick`: 3 s warm-up + 5 s measurement per benchmark).',
        '',
        '> **Infrastructure note:** Both test types use a **local SQLite** backend'
        ' (temporary, discarded after the run).'
        ' This isolates pure cryptographic and KMIP serialisation overhead from database I/O.'
        ' Throughput figures will differ on a production deployment backed by PostgreSQL or Redis-Findex.',
        '',
    ]


def generate_report(
    out_dir: Path,
    versions: list[str],
    load_data: dict[str, list[dict]],
    criterion_data: dict[str, dict[str, float]],
    load_charts: list[str],
    crit_charts: list[str],
    env_data: dict[str, dict] | None = None,
    pkcs11_overhead_data: dict[str, dict[str, object]] | None = None,
    *,
    is_hsm: bool = False,
    is_hsm_kek: bool = False,
    is_pkcs11: bool = False,
) -> None:
    """Write report.md combining load-test and criterion sections."""
    sep = ['', '---', '']
    lines: list[str] = [
        '# KMS Performance Comparison',
        '',
        f"**Versions**: {', '.join(f'`v{v}`' if v[0:1].isdigit() else f'`{v}`' for v in versions)}  ",
        f"**Generated**: {date.today().isoformat()}",
        *sep,
    ]

    # ── Environment ───────────────────────────────────────────────────────────
    if env_data:
        env_lines = _render_env_section(env_data, versions)
        if env_lines:
            lines += env_lines
            lines += sep

    # ── Protocols ─────────────────────────────────────────────────────────────
    lines += _render_protocol_section(
        is_hsm=is_hsm, is_hsm_kek=is_hsm_kek, is_pkcs11=is_pkcs11
    )
    lines += sep

    # ── Methodology ───────────────────────────────────────────────────────────
    lines += _render_methodology_section(
        is_hsm=is_hsm, is_hsm_kek=is_hsm_kek, is_pkcs11=is_pkcs11
    )
    lines += sep

    # ── PKCS#11 Ed25519 overhead ──────────────────────────────────────────
    if is_pkcs11 and pkcs11_overhead_data:
        overhead_lines = _render_pkcs11_overhead_section(pkcs11_overhead_data, versions)
        if overhead_lines:
            lines += overhead_lines
            lines += sep

    # ── Load tests ────────────────────────────────────────────────────────
    has_load = any(load_data.get(v) for v in versions)
    if has_load:
        lines += ['## Load Tests', '']

        ops: list[str] = []
        for v in versions:
            for rec in load_data.get(v, []):
                op = rec.get('operation', '')
                if op and op not in ops:
                    ops.append(op)

        multi_version = len(versions) > 1
        for op in ops:
            safe = op.replace('/', '_')
            lines += [f"### {op}", '']

            # Collect (protocol, version) combos and concurrency levels.
            combos: list[tuple[str, str]] = []
            for v in versions:
                protos: list[str] = []
                for rec in load_data.get(v, []):
                    if rec.get('operation') == op:
                        p = rec.get('protocol', '')
                        if p not in protos:
                            protos.append(p)
                for p in sorted(protos, key=lambda p: _PROTOCOL_ORDER.get(p, 99)):
                    if (p, v) not in combos:
                        combos.append((p, v))

            concurrencies: list[int] = sorted(
                {
                    rec.get('concurrency', 0)
                    for v in versions
                    for rec in load_data.get(v, [])
                    if rec.get('operation') == op
                }
            )

            col_labels = (
                (f"{p}/v{v}" if v[:1].isdigit() else f"{p}/{v}") if multi_version else p
                for p, v in combos
            )
            header = '| Concurrency |' + ''.join(f" {c} (req/s) |" for c in col_labels)
            lines.append(header)
            lines.append('|---|' + '---|' * len(combos))
            for c in concurrencies:
                row = f"| {c} |"
                for proto, v in combos:
                    m = next(
                        (
                            r
                            for r in load_data.get(v, [])
                            if r.get('operation') == op
                            and r.get('protocol') == proto
                            and r.get('concurrency') == c
                        ),
                        None,
                    )
                    row += f" {m['throughput_rps']:,.0f} |" if m else ' N/A |'
                lines.append(row)
            lines.append('')

            svg = f"load/{safe}.svg"
            if svg in load_charts:
                lines.append(f"![Throughput — {op}]({svg})")
            lines.extend(sep)

    # ── Criterion benchmarks ──────────────────────────────────────────────
    if any(criterion_data.values()):
        lines += ['## Criterion Benchmarks', '']
        for chart_title, table_lines in _build_criterion_tables(
            versions, criterion_data
        ):
            lines += [f"### {chart_title}", '']
            lines += table_lines
            lines += ['']
            lines.extend(sep)

    report = out_dir / 'report.md'
    report.write_text('\n'.join(lines) + '\n', encoding='utf-8')
    print(f"  Report: {report}")


# ── Main ──────────────────────────────────────────────────────────────────────


def main() -> None:
    # Optional --hsm flag: may appear anywhere in argv. When set, the report
    # documents the HSM/CryptoOracle delegation model (Protocols/Methodology
    # sections) instead of the generic software-bench text.
    # Optional --kek flag: may appear anywhere in argv. When set, the report
    # is otherwise identical to the plain software-bench text but prefixed
    # with a short note that the KEK (not the benchmarked keys themselves)
    # is HSM-resident. Mutually exclusive with --hsm (--hsm takes priority).
    # Optional --pkcs11 flag: may appear anywhere in argv. When set, the report
    # documents the real dlopen()-based Cryptoki C ABI benchmark (see
    # `bench/load-pkcs11`) instead of any KMIP-wire-protocol text. Mutually
    # exclusive with --hsm/--kek (either of those takes priority).
    argv = sys.argv[1:]
    is_hsm = '--hsm' in argv
    is_hsm_kek = '--kek' in argv and not is_hsm
    is_pkcs11 = '--pkcs11' in argv and not is_hsm and not is_hsm_kek
    argv = [a for a in argv if a not in ('--hsm', '--kek', '--pkcs11')]

    if len(argv) < 2:
        print(
            f"Usage: {sys.argv[0]} <results_dir> <version1> [version2] ... "
            '[--hsm|--kek|--pkcs11]'
        )
        sys.exit(1)

    out_dir = Path(argv[0])
    versions = argv[1:]

    print('── Environment data ──')
    env_data: dict[str, dict] = {}
    for v in versions:
        env = parse_env_json(out_dir / v)
        env_data[v] = env
        if env:
            print(
                f"  [{v}] loaded (cpu: {env.get('cpu_model', '?')}, os: {env.get('os', '?')})"
            )
        else:
            print(f"  [{v}] no env.json — environment section will be omitted")

    print('── Load test data ──')
    load_data: dict[str, list[dict]] = {}
    for v in versions:
        records: list[dict] = []
        for jf in sorted((out_dir / v).glob('load_*.json')):
            records.extend(parse_load_json(jf))
        _normalize_load_records(records)
        load_data[v] = records
        if records:
            ops = {r.get('operation') for r in records}
            print(f"  [{v}] {len(ops)} operation(s), {len(records)} record(s)")
        else:
            print(f"  [{v}] no data")

    print('── Criterion data ──')
    criterion_data: dict[str, dict[str, float]] = {}
    for v in versions:
        data = parse_criterion_json(out_dir / v / 'criterion.json', v)
        criterion_data[v] = data
        print(f"  [{v}] {len(data)} benchmark(s)" if data else f"  [{v}] no data")

    pkcs11_overhead_data: dict[str, dict[str, object]] = {}
    if is_pkcs11:
        print('── PKCS#11 overhead data ──')
        for v in versions:
            data = parse_pkcs11_overhead_json(out_dir / v / 'pkcs11_overhead.json')
            pkcs11_overhead_data[v] = data
            tier_count = len(data.get('tiers', [])) if data else 0
            phase_count = len(data.get('phases', [])) if data else 0
            if tier_count or phase_count:
                print(f"  [{v}] {tier_count} tier(s), {phase_count} phase(s)")
            else:
                print(f"  [{v}] no valid overhead data")

            # The overhead ladder's `pkcs11-one-call` tier is the canonical
            # Ed25519 C_SignMessage measurement. Reuse that exact estimate in the generic
            # Sign / Verify table instead of accepting a duplicate benchmark run
            # from a later (potentially noisier) time window.
            one_call = next(
                (
                    tier
                    for tier in data.get('tiers', [])
                    if tier.get('name') == 'pkcs11-one-call-bracketed'
                ),
                None,
            )
            if isinstance(one_call, dict):
                mean_ns = _finite_number(one_call.get('mean_ns'), positive=True)
                if mean_ns is not None:
                    criterion_data.setdefault(v, {})[
                        'pkcs11_sign-verify_eddsa-ed25519/sign'
                    ] = mean_ns

    has_overhead_data = any(
        data.get('tiers') or data.get('phases')
        for data in pkcs11_overhead_data.values()
    )
    if (
        not any(load_data.values())
        and not any(criterion_data.values())
        and not has_overhead_data
    ):
        print('ERROR: no benchmark data found for any version')
        sys.exit(1)

    # All output goes into a version-named subdirectory so every run is self-contained.
    version_subdir = versions[0] if len(versions) == 1 else '_vs_'.join(versions)
    output_dir = out_dir / version_subdir
    output_dir.mkdir(parents=True, exist_ok=True)

    print('── Generating charts ──')
    load_charts = generate_load_charts(output_dir / 'load', versions, load_data)
    crit_charts = generate_criterion_charts(
        output_dir / 'criterion', versions, criterion_data
    )
    if load_charts:
        print(f"  {len(load_charts)} load chart(s)")
    if crit_charts:
        print(f"  {len(crit_charts)} criterion chart(s)")

    generate_report(
        output_dir,
        versions,
        load_data,
        criterion_data,
        load_charts,
        crit_charts,
        env_data=env_data or None,
        pkcs11_overhead_data=pkcs11_overhead_data or None,
        is_hsm=is_hsm,
        is_hsm_kek=is_hsm_kek,
        is_pkcs11=is_pkcs11,
    )


if __name__ == '__main__':
    main()
