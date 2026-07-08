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
    """Return True if the algorithm name suggests a symmetric cipher."""
    alg = algorithm.lower()
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
_PROTOCOL_ORDER: dict[str, int] = {'ttlv-json': 0, 'ttlv-bytes': 1, 'jose': 2}


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
_KNOWN_PROTOCOLS = ('ttlv-bytes', 'ttlv-json', 'jose')


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
            lines += ['### CPU detail (`lscpu`)', '', '```', lscpu, '```', '']

    return lines


def _render_protocol_section() -> list[str]:
    """Render the static ## Protocols section."""
    return [
        '## Protocols',
        '',
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


def _render_methodology_section() -> list[str]:
    """Render the static ## Benchmark Methodology section."""
    return [
        '## Benchmark Methodology',
        '',
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
    lines += _render_protocol_section()
    lines += sep

    # ── Methodology ───────────────────────────────────────────────────────────
    lines += _render_methodology_section()
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
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <results_dir> <version1> [version2] ...")
        sys.exit(1)

    out_dir = Path(sys.argv[1])
    versions = sys.argv[2:]

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

    if not any(load_data.values()) and not any(criterion_data.values()):
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
    )


if __name__ == '__main__':
    main()
