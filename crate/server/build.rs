use std::{env, fs, path::Path};

use chrono::{DateTime, Duration, Utc};

const DEMO_TIMEOUT: i64 = 90; // 3 months in days

fn main() {
    if cfg!(feature = "timeout") {
        let now = Utc::now();
        let three_months_later = now + Duration::days(DEMO_TIMEOUT);
        let start = DateTime::parse_from_rfc2822(&now.to_rfc2822()).unwrap();
        let end = DateTime::parse_from_rfc2822(&three_months_later.to_rfc2822()).unwrap();
        println!("cargo:warning=Timeout set for demo version");
        println!("cargo:warning=- date of compilation: \t{}", start);
        println!(
            "cargo:warning=- end of demo in {} days:\t{}",
            DEMO_TIMEOUT, end
        );
        let out_dir = env::var_os("OUT_DIR").unwrap();
        let dest_path = Path::new(&out_dir).join("demo_timeout.rs");
        fs::write(
            &dest_path,
            format!(
                "const DEMO_TIMEOUT: &[u8] = &{:?};
            ",
                end.to_rfc2822().as_bytes()
            ),
        )
        .unwrap();
        println!("cargo:rerun-if-changed=build.rs");
    }
}
