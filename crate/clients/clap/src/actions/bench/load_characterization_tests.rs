use std::fs;

use serial_test::serial;

use super::{
    LoadResult, criterion_home, generate_html_output, generate_load_json_output,
    generate_markdown_load_output_combined, load_percentile, parse_concurrency_levels,
};

fn result(operation: &str, concurrency: usize, scale: f64) -> LoadResult {
    LoadResult {
        operation: operation.to_owned(),
        concurrency,
        throughput_rps: 1234.5678 * scale,
        p50_ms: 1.23456 * scale,
        p95_ms: 4.56789 * scale,
        p99_ms: 9.87654 * scale,
        samples: 100 * concurrency,
        errors: 0,
    }
}

fn sorted(len: u32) -> Vec<f64> {
    (1..=len).map(f64::from).collect()
}

#[test]
fn characterization_load_percentile_table() {
    let ps = [0.0, 0.5, 0.95, 0.99, 1.0];
    let mut got: Vec<Vec<f64>> = Vec::new();
    for len in [1_u32, 2, 5, 100] {
        let data = sorted(len);
        got.push(ps.iter().map(|p| load_percentile(&data, *p)).collect());
    }
    let expected: Vec<Vec<f64>> = vec![
        vec![1.0, 1.0, 1.0, 1.0, 1.0],
        vec![1.0, 2.0, 2.0, 2.0, 2.0],
        vec![1.0, 3.0, 5.0, 5.0, 5.0],
        vec![1.0, 51.0, 95.0, 99.0, 100.0],
    ];
    assert_eq!(got, expected);
}

#[test]
fn characterization_load_percentile_empty() {
    assert_eq!(load_percentile(&[], 0.5).to_bits(), 0.0_f64.to_bits());
}

#[test]
fn characterization_parse_concurrency_levels_values() {
    assert_eq!(parse_concurrency_levels("1, 2,16").unwrap(), vec![1, 2, 16]);
    assert_eq!(parse_concurrency_levels("0").unwrap(), vec![0]);
    assert_eq!(parse_concurrency_levels("1,,2,").unwrap(), vec![1, 2]);
    assert_eq!(
        parse_concurrency_levels("a").unwrap_err().to_string(),
        "Invalid concurrency level 'a': invalid digit found in string"
    );
}

#[test]
#[serial(bench_files)]
fn characterization_generate_load_json_output_lines() {
    let slug = "characterization-json";
    let results = vec![
        result("characterization-json/encrypt/aes-gcm", 1, 1.0),
        result("other/sign/rsa", 16, 2.5),
    ];
    generate_load_json_output(&results, slug).unwrap();
    let path = criterion_home().join("load_characterization-json.json");
    let content = fs::read_to_string(&path).unwrap();
    fs::remove_file(&path).unwrap();
    assert_eq!(
        content,
        "{\"protocol\":\"characterization-json\",\"operation\":\"encrypt/aes-gcm\",\"concurrency\":1,\"throughput_rps\":1234.57,\"p50_ms\":1.235,\"p95_ms\":4.568,\"p99_ms\":9.877}\n{\"protocol\":\"characterization-json\",\"operation\":\"other/sign/rsa\",\"concurrency\":16,\"throughput_rps\":3086.42,\"p50_ms\":3.086,\"p95_ms\":11.420,\"p99_ms\":24.691}\n"
    );
}

#[test]
fn characterization_generate_load_json_output_empty() {
    generate_load_json_output(&[], "characterization-empty").unwrap();
    assert!(
        !criterion_home()
            .join("load_characterization-empty.json")
            .exists()
    );
}

#[test]
#[serial(bench_files)]
fn characterization_generate_markdown_load_output_combined_tables() {
    let proto = vec![
        (
            "ttlv-json",
            vec![
                result("ttlv-json/encrypt/aes-gcm", 1, 1.0),
                result("ttlv-json/encrypt/aes-gcm", 4, 2.0),
                result("ttlv-json/sign/rsa", 4, 0.5),
            ],
        ),
        (
            "jose",
            vec![
                result("jose/encrypt/aes-gcm", 1, 3.0),
                result("jose/encrypt/aes-gcm", 16, 4.0),
            ],
        ),
    ];
    generate_markdown_load_output_combined(&proto).unwrap();
    let path = criterion_home().join("load.md");
    let content = fs::read_to_string(&path).unwrap();
    fs::remove_file(&path).unwrap();
    assert_eq!(
        content,
        "### encrypt/aes-gcm\n\n| Concurrency | ttlv-json (req/s) | jose (req/s) |\n|-------------|-----------------|-----------------|\n| 1           | 1234.6          | 3703.7          |\n| 4           | 2469.1          | -               |\n| 16          | -               | 4938.3          |\n\n### sign/rsa\n\n| Concurrency | ttlv-json (req/s) | jose (req/s) |\n|-------------|-----------------|-----------------|\n| 1           | -               | -               |\n| 4           | 617.3           | -               |\n| 16          | -               | -               |\n\n"
    );
}

#[test]
fn characterization_generate_markdown_load_output_combined_empty() {
    generate_markdown_load_output_combined(&[]).unwrap();
}

#[test]
#[serial(bench_files)]
fn characterization_generate_html_output_dat_and_sections() {
    let results = vec![
        result("characterization/html op", 1, 1.0),
        result("characterization/html op", 8, 2.0),
    ];
    generate_html_output(&results).unwrap();
    let dir = criterion_home().join("load-report");
    let dat = fs::read_to_string(dir.join("characterization_html-op.dat")).unwrap();
    let html = fs::read_to_string(dir.join("index.html")).unwrap();
    fs::remove_dir_all(&dir).unwrap();
    assert_eq!(
        dat,
        "# concurrency  throughput_rps  p50_ms  p95_ms  p99_ms  samples\n1              1234.57         1.23     4.57     9.88     100\n8              2469.14         2.47     9.14     19.75    800\n"
    );
    let start = html.find("<section>").unwrap();
    let end = html.find("</section>").unwrap();
    let section = html.get(start..end).unwrap();
    let table = section.get(section.find("<table>").unwrap()..).unwrap();
    assert_eq!(
        section.lines().nth(1).unwrap(),
        "<h2>characterization/html op</h2>"
    );
    assert_eq!(
        table,
        "<table>\n<tr><th>Concurrency</th><th>Throughput (req/s)</th><th>p50 (ms)</th><th>p95 (ms)</th><th>p99 (ms)</th><th>Samples</th></tr>\n<tr><td>1</td><td>1234.6</td><td>1.2</td><td>4.6</td><td>9.9</td><td>100</td></tr>\n<tr><td>8</td><td>2469.1</td><td>2.5</td><td>9.1</td><td>19.8</td><td>800</td></tr>\n</table>\n"
    );
}
