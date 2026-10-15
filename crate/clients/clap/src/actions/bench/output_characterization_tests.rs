use super::{BenchPoint, render_group_table};

fn point(function_id: &str, value_str: &str, time_ns: f64) -> BenchPoint {
    BenchPoint {
        function_id: function_id.to_owned(),
        value_str: value_str.to_owned(),
        time_ns,
    }
}

#[test]
fn characterization_render_group_table_flat_no_params_with_description() {
    let points = vec![point("encrypt", "", 850.0), point("decrypt", "", 12_500.0)];
    assert_eq!(
        render_group_table("encrypt/aes-gcm", &points),
        "### encrypt/aes-gcm\n\nAES-GCM encrypt and decrypt (128/192/256-bit keys, 64-byte plaintext).\n\n| | `encrypt` | `decrypt` |\n| :--- | :--- | :--- |\n| | `850.00 ns` | `12.50 µs` |\n"
    );
}

#[test]
fn characterization_render_group_table_flat_no_params_unknown_group() {
    let points = vec![point("op", "", 2_500_000.0)];
    assert_eq!(
        render_group_table("unknown/group", &points),
        "### unknown/group\n\n| | `op` |\n| :--- | :--- |\n| | `2.50 ms` |\n"
    );
}

#[test]
fn characterization_render_group_table_pivot_params() {
    let points = vec![
        point("encrypt", "50 requests", 3_000_000_000.0),
        point("encrypt", "1 request", 1_500.0),
        point("decrypt", "1 request", 2_000_000.0),
        point("encrypt", "abc", 10.0),
    ];
    assert_eq!(
        render_group_table("encrypt/aes-gcm", &points),
        "### encrypt/aes-gcm\n\nAES-GCM encrypt and decrypt (128/192/256-bit keys, 64-byte plaintext).\n\n| | `encrypt` | `decrypt` |\n| :--- | :--- | :--- |\n| **`1 request`** | `1.50 µs` | `2.00 ms` |\n| **`50 requests`** | `3.00 s` | `N/A` |\n| **`abc`** | `10.00 ns` | `N/A` |\n"
    );
}

#[test]
fn characterization_render_group_table_empty_points() {
    assert_eq!(
        render_group_table("unknown/group", &[]),
        "### unknown/group\n\n| |\n| :--- |\n| |\n"
    );
}
