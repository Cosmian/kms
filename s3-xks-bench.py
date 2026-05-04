#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
s3-xks-bench.py v2 - Benchmark S3 + KMS XKS (upload + decrypt + cleanup)
Usage: python3 s3-xks-bench.py --bucket <bucket> --kms-key-id <arn> [options]
"""

import argparse
import os
import statistics
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import boto3
from botocore.config import Config
from tqdm import tqdm


def parse_args():
    p = argparse.ArgumentParser(description='Benchmark S3 + KMS XKS')
    p.add_argument('--bucket', required=True, help='Nom du bucket S3')
    p.add_argument(
        '--region', default='eu-west-1', help='AWS region (default: eu-west-1)'
    )
    p.add_argument('--kms-key-id', required=True, help='ARN de la cle KMS')
    p.add_argument(
        '--n', type=int, default=1000, help='Number of objects (default: 1000)'
    )
    p.add_argument(
        '--objectsize',
        type=int,
        default=64000,
        help='Object size in bytes (default: 64000)',
    )
    p.add_argument(
        '--concurrency', type=int, default=64, help='Parallel workers (default: 64)'
    )
    p.add_argument(
        '--warmup', type=int, default=10, help='Warmup objects (default: 10)'
    )
    p.add_argument('--no-retry', action='store_true', help='Disable SDK retries')
    p.add_argument(
        '--no-cleanup', action='store_true', help='Keep objects after the run'
    )
    p.add_argument('--no-decrypt', action='store_true', help='Skip decrypt phase')
    return p.parse_args()


def make_s3_client(region, no_retry, concurrency):
    # Single shared client: pool size = concurrency + 20 covers all threads simultaneously.
    # Previously each thread created its own client with pool_size=concurrency+20, giving
    # concurrency*(concurrency+20) configured slots but only concurrency actually used —
    # a thundering herd of TLS handshakes on first use and zero cross-thread connection reuse.
    pool_size = min(concurrency + 20, 500)
    cfg = Config(
        region_name=region,
        retries={'max_attempts': 1 if no_retry else 3, 'mode': 'standard'},
        max_pool_connections=pool_size,
    )
    return boto3.client('s3', config=cfg)


def upload_object(client, bucket, key, data, kms_key_id):
    t0 = time.monotonic()
    try:
        client.put_object(
            Bucket=bucket,
            Key=key,
            Body=data,
            ServerSideEncryption='aws:kms',
            SSEKMSKeyId=kms_key_id,
        )
        return (time.monotonic() - t0) * 1000, None
    except Exception as e:
        return (time.monotonic() - t0) * 1000, str(e)


def download_object(client, bucket, key):
    t0 = time.monotonic()
    try:
        resp = client.get_object(Bucket=bucket, Key=key)
        resp['Body'].read()
        return (time.monotonic() - t0) * 1000, None
    except Exception as e:
        return (time.monotonic() - t0) * 1000, str(e)


def batch_delete(client, bucket, keys):
    for i in range(0, len(keys), 1000):
        batch = [{'Key': k} for k in keys[i : i + 1000]]
        client.delete_objects(Bucket=bucket, Delete={'Objects': batch})


def percentile(data, p):
    if not data:
        return 0.0
    s = sorted(data)
    idx = int(len(s) * p / 100)
    return s[min(idx, len(s) - 1)]


def print_results(label, latencies, errors_list, objectsize, total_ms):
    n_success = len(latencies)
    n_errors = len(errors_list)
    total_bytes = n_success * objectsize
    throughput_mbs = (
        (total_bytes / (total_ms / 1000)) / (1024 * 1024) if total_ms > 0 else 0
    )
    tps = (n_success / (total_ms / 1000)) if total_ms > 0 else 0

    print(f"\n{label}")
    print(f"  Success      : {n_success} | Errors : {n_errors}")
    if latencies:
        print(f"  min          : {min(latencies):.1f} ms")
        print(f"  p50          : {percentile(latencies, 50):.1f} ms")
        print(f"  p95          : {percentile(latencies, 95):.1f} ms")
        print(f"  p99          : {percentile(latencies, 99):.1f} ms")
        print(f"  max          : {max(latencies):.1f} ms")
        print(f"  avg          : {statistics.mean(latencies):.1f} ms")
        print(
            f"  stdev        : {statistics.stdev(latencies) if len(latencies) > 1 else 0:.1f} ms"
        )
    print(f"  TPS          : {tps:.1f} req/s")
    print(f"  Throughput   : {throughput_mbs:.2f} MB/s")
    print(f"  Total time   : {total_ms / 1000:.3f} s")


def run_phase(label, fn_list, concurrency):
    latencies = []
    errors_list = []
    start = time.monotonic()
    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = {executor.submit(fn): i for i, fn in enumerate(fn_list)}
        with tqdm(total=len(fn_list), desc=f"[{label:<10}]", unit='obj') as bar:
            for fut in as_completed(futures):
                i = futures[fut]
                lat, err = fut.result()
                if err:
                    errors_list.append((i, err))
                else:
                    latencies.append(lat)
                bar.update(1)
    total_ms = (time.monotonic() - start) * 1000
    return latencies, errors_list, total_ms


def main():
    args = parse_args()
    payload = os.urandom(args.objectsize)
    keys = [f"bench/obj-{i:06d}" for i in range(args.n)]

    pool_size = min(args.concurrency + 20, 500)
    client = make_s3_client(args.region, args.no_retry, args.concurrency)

    print(f"\n{'='*60}")
    print(f"Bucket       : {args.bucket}")
    print(f"KMS Key      : {args.kms_key_id}")
    print(f"Objects      : {args.n}")
    print(f"Object size  : {args.objectsize} bytes ({args.objectsize/1024:.1f} KB)")
    print(f"Concurrency  : {args.concurrency} threads")
    print(f"Pool size    : {pool_size} connexions (shared)")
    print(f"Warmup       : {args.warmup} objects (parallel)")
    print(f"Retry        : {'disabled' if args.no_retry else 'enabled (max 3)'}")
    print(f"Cleanup      : {'no' if args.no_cleanup else 'yes'}")
    print(f"{'='*60}")

    # Warmup — run through the thread pool so all worker threads establish their
    # connections before the measured phase begins. With a shared client the pool is
    # pre-populated (no cold-start TLS burst at t=0 of the real benchmark).
    warmup_count = max(args.warmup, args.concurrency)
    warmup_keys = [f"bench/warmup-{i:03d}" for i in range(warmup_count)]
    warmup_fns = [
        (
            lambda k: lambda: upload_object(
                client, args.bucket, k, payload, args.kms_key_id
            )
        )(key)
        for key in warmup_keys
    ]
    run_phase('Warmup', warmup_fns, args.concurrency)
    try:
        batch_delete(client, args.bucket, warmup_keys)
    except Exception as e:
        print(f"[Warmup] Impossible de supprimer les objects de warmup : {e}")

    # Upload
    upload_fns = [
        (
            lambda k: lambda: upload_object(
                client, args.bucket, k, payload, args.kms_key_id
            )
        )(key)
        for key in keys
    ]
    up_latencies, up_errors, up_total_ms = run_phase(
        'Upload', upload_fns, args.concurrency
    )
    up_error_indices = {e[0] for e in up_errors}
    uploaded_keys = [keys[i] for i in range(args.n) if i not in up_error_indices]

    # Decrypt
    dl_latencies, dl_errors, dl_total_ms = [], [], 0
    if not args.no_decrypt and uploaded_keys:
        dl_fns = [
            (lambda k: lambda: download_object(client, args.bucket, k))(key)
            for key in uploaded_keys
        ]
        dl_latencies, dl_errors, dl_total_ms = run_phase(
            'Decrypt', dl_fns, args.concurrency
        )

    # Cleanup
    if not args.no_cleanup and uploaded_keys:
        cleanup_errors = []
        try:
            with tqdm(total=len(uploaded_keys), desc='[Cleanup  ]', unit='obj') as bar:
                for i in range(0, len(uploaded_keys), 1000):
                    batch = uploaded_keys[i : i + 1000]
                    try:
                        batch_delete(client, args.bucket, batch)
                    except Exception as e:
                        cleanup_errors.append(str(e))
                    bar.update(len(batch))
        except Exception as e:
            print(f"\n[Cleanup] Erreur fatale : {e}")
        if cleanup_errors:
            print(f"\n[Cleanup] {len(cleanup_errors)} erreur(s) :")
            for err in cleanup_errors:
                print(f"  {err[:120]}")

    # Rapport
    print(f"\n{'='*60}")
    print('RESULTS')
    print(f"{'='*60}")
    print_results(
        'UPLOAD (encrypt)', up_latencies, up_errors, args.objectsize, up_total_ms
    )
    if not args.no_decrypt:
        print_results(
            'DECRYPT (download)', dl_latencies, dl_errors, args.objectsize, dl_total_ms
        )

    all_errors = [('UPLOAD', i, e) for i, e in up_errors] + [
        ('DECRYPT', i, e) for i, e in dl_errors
    ]
    print(f"\nERRORS ({len(all_errors)} total)")
    if all_errors:
        seen = {}
        for _, i, err in all_errors:
            k = err[:100]
            seen[k] = seen.get(k, 0) + 1
        for msg, count in seen.items():
            print(f"  [{count}x] {msg}")
    else:
        print('  (aucune)')
    print(f"{'='*60}\n")


if __name__ == '__main__':
    main()
