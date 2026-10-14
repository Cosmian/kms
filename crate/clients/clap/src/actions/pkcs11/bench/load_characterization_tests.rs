use std::time::Duration;

use super::summarize;

fn ms(values: &[u64]) -> Vec<Duration> {
    values.iter().map(|v| Duration::from_millis(*v)).collect()
}

#[test]
fn characterization_summarize_percentiles_and_throughput() {
    let latencies = ms(&[5, 1, 4, 2, 3]);
    let r = summarize("op/label", 3, &latencies, Duration::from_millis(500));
    assert_eq!(
        format!(
            "{} {} {} {} {} {} {}",
            r.operation, r.concurrency, r.throughput_ops, r.p50_ms, r.p95_ms, r.p99_ms, r.samples
        ),
        "op/label 3 10 3 5 5 5"
    );
}

#[test]
fn characterization_summarize_single_sample() {
    let r = summarize("one", 1, &ms(&[7]), Duration::from_secs(2));
    assert_eq!(
        format!(
            "{} {} {} {} {} {}",
            r.concurrency, r.throughput_ops, r.p50_ms, r.p95_ms, r.p99_ms, r.samples
        ),
        "1 0.5 7 7 7 1"
    );
}

#[test]
fn characterization_summarize_hundred_samples() {
    let values: Vec<u64> = (1..=100).rev().collect();
    let r = summarize("hundred", 8, &ms(&values), Duration::from_secs(4));
    assert_eq!(
        format!(
            "{} {} {} {} {}",
            r.throughput_ops, r.p50_ms, r.p95_ms, r.p99_ms, r.samples
        ),
        "25 51 95 99 100"
    );
}

#[test]
fn characterization_summarize_empty_and_zero_elapsed() {
    let r = summarize("none", 2, &[], Duration::from_secs(1));
    assert_eq!(
        format!(
            "{} {} {} {} {}",
            r.throughput_ops, r.p50_ms, r.p95_ms, r.p99_ms, r.samples
        ),
        "0 0 0 0 0"
    );
    let z = summarize("zero", 2, &ms(&[1, 2]), Duration::ZERO);
    assert_eq!(
        format!(
            "{} {} {} {} {}",
            z.throughput_ops, z.p50_ms, z.p95_ms, z.p99_ms, z.samples
        ),
        "0 2 2 2 2"
    );
}
