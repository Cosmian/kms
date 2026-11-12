#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Report for `mise run bench:jose-cek-switch`: latency timelines (gnuplot SVG) and report.md.

Usage:
    python3 plot_cek_switch.py <out_dir> <run_dir> [<run_dir> ...]

A run dir holds what the task wrote: cek_switch_summary.json, cek_switch_timeline.json,
env.json, version.txt, gate.txt and kms<N>.unwraps. The copies kept under
<out_dir>/<label>/ have the same files, so CI artifacts can be recombined later.
Runs are sorted by env.json "date" (oldest first); the label is the directory name.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path

COPIED = (
    'cek_switch_summary.json',
    'cek_switch_timeline.json',
    'env.json',
    'version.txt',
    'gate.txt',
)


def read_text(path: Path) -> str:
    return path.read_text() if path.exists() else ''


def load_run(run_dir: Path) -> dict:
    """Read one run directory."""
    env = json.loads(read_text(run_dir / 'env.json') or '{}')
    unwraps = {}
    for f in sorted(run_dir.glob('kms*.unwraps')):
        order: list[str] = []
        counts: Counter = Counter()
        for line in read_text(f).splitlines():
            uid = line.rsplit(' ', 1)[-1]
            if uid not in counts:
                order.append(uid)
            counts[uid] += 1
        unwraps[f.stem] = [counts[u] for u in order]
    return {
        'label': run_dir.name,
        'dir': run_dir,
        'env': env,
        'summary': json.loads((run_dir / 'cek_switch_summary.json').read_text()),
        'timeline': [
            json.loads(l)
            for l in read_text(run_dir / 'cek_switch_timeline.json').splitlines()
            if l
        ],
        'version': read_text(run_dir / 'version.txt').strip().strip('"'),
        'gate': [l for l in read_text(run_dir / 'gate.txt').splitlines() if l.strip()],
        'unwraps': unwraps,
    }


def gnuplot(out_dir: Path, name: str, script: str) -> bool:
    if shutil.which('gnuplot') is None:
        print(f'WARNING: gnuplot not found, skipping {name}')
        return False
    path = out_dir / name.replace('.svg', '.gnuplot')
    path.write_text(script)
    r = subprocess.run(['gnuplot', path.name], cwd=out_dir, capture_output=True)
    if r.returncode != 0:
        print(f'  gnuplot error ({name}): {r.stderr.decode().strip()}')
    return r.returncode == 0


def plot(
    out_dir: Path,
    name: str,
    title: str,
    switch_s: float,
    series: list[tuple[str, list[tuple[float, float]]]],
) -> bool:
    """One log-scale line chart: x = s since the measurement start, y = ms."""
    blocks, plots = [], []
    for i, (label, pts) in enumerate(series):
        blocks.append(
            f'$S{i} << EOD\n' + ''.join(f'{x} {y}\n' for x, y in pts) + 'EOD\n'
        )
        plots.append(f"$S{i} using 1:2 with lines lw 1.5 title '{label}'")
    script = (
        "set terminal svg size 1000,500 enhanced font 'Helvetica,12'\n"
        f"set output '{name}'\n"
        f"set title '{title}'\n"
        "set grid\nset xlabel 'seconds since the start of the measurement'\n"
        "set ylabel 'message latency (ms, from scheduled time)'\nset logscale y\n"
        f"set arrow from {switch_s},graph 0 to {switch_s},graph 1 nohead dashtype 2 lc rgb 'red'\n"
        f"set label 'CEK switch' at {switch_s},graph 0.95 offset 1,0 textcolor rgb 'red'\n"
        + ''.join(blocks)
        + 'plot '
        + ', '.join(plots)
        + '\n'
    )
    return gnuplot(out_dir, name, script)


def series(timeline: list[dict], server: str, field: str) -> list[tuple[float, float]]:
    # log scale: drop zero latencies
    return [
        (b['t_ms'] / 1000, b[field])
        for b in timeline
        if b['server'] == server and b[field] > 0
    ]


def uniq(runs: list[dict], key: str) -> str:
    """Distinct values of a summary field across runs, in run order."""
    return ', '.join(dict.fromkeys(str(r['summary'][key]) for r in runs))


def fmt(v, digits: int = 1) -> str:
    return '-' if v is None else (f'{v:.{digits}f}' if isinstance(v, float) else str(v))


def run_section(r: dict, out_dir: Path) -> list[str]:
    s, label = r['summary'], r['label']
    switch_s = s['switch_at_s']
    images = []
    if plot(
        out_dir,
        f'timeline_{label}.svg',
        f'{label}: message latency, all servers',
        switch_s,
        [
            ('p50', series(r['timeline'], 'all', 'message_p50_ms')),
            ('p99', series(r['timeline'], 'all', 'message_p99_ms')),
            ('max', series(r['timeline'], 'all', 'message_max_ms')),
        ],
    ):
        images.append(f'![{label} timeline](timeline_{label}.svg)')
    servers = [p['server'] for p in s['per_server'] if p['server'] != 'all']
    if plot(
        out_dir,
        f'timeline_{label}_servers.svg',
        f'{label}: message p99 per server',
        switch_s,
        [(srv, series(r['timeline'], srv, 'message_p99_ms')) for srv in servers],
    ):
        images.append(f'![{label} per-server p99](timeline_{label}_servers.svg)')

    gate = '**PASS**' if not r['gate'] else '**FAIL** — ' + '; '.join(r['gate'])
    lines = [
        f'### Run `{label}`',
        '',
        f"Target {s['rate_target']} msg/s, {s['workers']} senders, warmup {s['warmup_s']} s, measurement {s['duration_s']} s, "
        f"CEK switch at +{s['switch_at_s']} s; achieved {s['rate_achieved']:.0f} msg/s ({s['unsent']} messages unsent).",
        '',
        f'Performance gate (≥ 95 % of target rate completed, 0 errors, recovery within the window): {gate}',
        '',
        '| server | pre p50 ms | pre p99 ms | first 1 s p99 ms | first 1 s max ms | peak ms | recovery ms | slow messages | errors | HSM unwraps cek0 | HSM unwraps cek1 |',
        '|---|---|---|---|---|---|---|---|---|---|---|',
    ]
    for p in s['per_server']:
        u = (
            r['unwraps'].get(f"kms{p['server'][3:]}", [])
            if p['server'] != 'all'
            else None
        )
        cek0, cek1 = (
            ('', '')
            if u is None
            else (u[0] if len(u) > 0 else 0, u[1] if len(u) > 1 else 0)
        )
        lines.append(
            f"| {p['server']} | {fmt(p['pre_switch']['message_p50_ms'])} | {fmt(p['pre_switch']['message_p99_ms'])} "
            f"| {fmt(p['post_switch_1s']['message_p99_ms'])} | {fmt(p['post_switch_1s']['message_max_ms'])} "
            f"| {fmt(p['peak_message_ms'])} | {fmt(p['recovery_ms'])} | {p['slow_messages']} | {p['errors']} | {cek0} | {cek1} |"
        )
    return lines + [''] + images + ['']


def comparison(runs: list[dict]) -> list[str]:
    labels = [r['label'] for r in runs]
    rows = [
        ('achieved msg/s', [f"{r['summary']['rate_achieved']:.0f}" for r in runs]),
        ('gate', ['PASS' if not r['gate'] else 'FAIL' for r in runs]),
        (
            'peak message ms (all)',
            [fmt(r['summary']['per_server'][0]['peak_message_ms']) for r in runs],
        ),
        (
            'recovery ms (all)',
            [fmt(r['summary']['per_server'][0]['recovery_ms']) for r in runs],
        ),
    ]
    servers = [
        p['server'] for p in runs[0]['summary']['per_server'] if p['server'] != 'all'
    ]
    for srv in servers:
        rows.append(
            (
                f'HSM unwraps of cek1, {srv}',
                [
                    fmt((r['unwraps'].get(f'kms{srv[3:]}', []) + [0, 0])[1])
                    for r in runs
                ],
            )
        )
    return (
        [
            '## Comparison',
            '',
            '| | ' + ' | '.join(labels) + ' |',
            '|---|' + '---|' * len(labels),
        ]
        + [f'| {name} | ' + ' | '.join(vals) + ' |' for name, vals in rows]
        + ['']
    )


def main(argv: list[str]) -> int:
    if len(argv) < 3:
        print(__doc__)
        return 2
    out_dir = Path(argv[1])
    out_dir.mkdir(parents=True, exist_ok=True)
    runs = [
        load_run(Path(d))
        for d in argv[2:]
        if (Path(d) / 'cek_switch_summary.json').exists()
    ]
    if not runs:
        print('ERROR: no run directory with cek_switch_summary.json')
        return 1
    # "YYYY-MM-DD HH:MM:SS UTC" sorts lexically; artifact downloads do not keep mtimes.
    runs.sort(key=lambda r: r['env'].get('date', ''))

    first = runs[0]
    s, env = first['summary'], first['env']
    md = [
        f"# JOSE CEK switch under load — {env.get('hsm_backend') or 'unknown HSM'}",
        '',
        '| Setting | Value |',
        '|---|---|',
        f"| KMS servers | {len(s['urls'])} |",
        f"| Target rate | {uniq(runs, 'rate_target')} msg/s (one message = one decrypt + one re-encrypt) |",
        '| Achieved rate | '
        + ', '.join(
            f"{r['label']}: {r['summary']['rate_achieved']:.0f} msg/s" for r in runs
        )
        + ' |',
        f"| Senders | {uniq(runs, 'workers')} |",
        f"| JWE algorithm | {s['alg']} + A256GCM |",
        f"| Plaintext | {s['plaintext_size']} bytes |",
        f"| Warmup / measurement / CEK switch | {uniq(runs, 'warmup_s')} s / {uniq(runs, 'duration_s')} s / +{uniq(runs, 'switch_at_s')} s |",
        f"| HSM | {env.get('hsm_backend') or '-'} |",
        f"| KMS version | {first['version'] or '-'} |",
        f"| CPU | {env.get('cpu_model', '-')} ({env.get('cpu_logical_cores', '?')} logical cores) |",
        f"| Command | `{env.get('command') or '-'}` |",
        '',
        '## Scenario',
        '',
        'Metacrypt receives JWEs from Estreem and sends each to the KMS: `POST /v1/crypto/decrypt` '
        '(RSA-OAEP unwrap of the CEK with the HSM private key), then `POST /v1/crypto/encrypt` '
        '(`dir` + A256GCM under Ksymbank). Estreem keeps one AES CEK for an hour, then switches to a new one. '
        'It must wrap each CEK once: all messages of a CEK then carry the same `encrypted_key`. '
        'RSA-OAEP is randomized, so re-wrapping the same CEK for every message would unwrap on the HSM every time. '
        'Each KMS process caches the unwrapped CEK under `sha256(key uid ‖ encrypted_key)`; there is no cross-node '
        'sharing, so every KMS unwraps the new CEK on its own. The cache entry expires after '
        '`unwrapped_cache_max_age` (default 15 min idle), and `unwrapped_cache_max_ttl`, when set below 60 min, forces a '
        're-unwrap in the middle of the hour. The load generator, all KMS processes and the HSM token run on one host, '
        'so absolute latencies include CPU contention. `cek_cache` debug logging is enabled (one log line per cache hit '
        'and per unwrap); the HSM unwrap counts come from those lines. Latency is measured from the scheduled send time '
        '(open loop), so queueing behind a slow request is included.',
        '',
        '## Runs',
        '',
    ]
    for r in runs:
        md += run_section(r, out_dir)
    if len(runs) >= 2:
        md += comparison(runs)
    (out_dir / 'report.md').write_text('\n'.join(md))

    for r in runs:
        dest = out_dir / r['label']
        if dest.resolve() == r['dir'].resolve():
            continue
        dest.mkdir(parents=True, exist_ok=True)
        for name in (*COPIED, *(f.name for f in r['dir'].glob('kms*.unwraps'))):
            if (r['dir'] / name).exists():
                shutil.copy2(r['dir'] / name, dest / name)
    print(f'Report written to {out_dir / "report.md"}')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
