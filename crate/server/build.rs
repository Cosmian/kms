use std::{env, fs, path::Path};

use time::{ext::NumericalDuration, format_description::well_known::Rfc2822, OffsetDateTime};

const DEMO_TIMEOUT: i64 = 90; // 3 months in days

fn main() {
    if cfg!(feature = "timeout") {
        let now = OffsetDateTime::now_utc();
        let three_months_later = now + DEMO_TIMEOUT.days();

        let now_formatted = now.format(&Rfc2822).unwrap();
        let three_months_later_formatted = three_months_later.format(&Rfc2822).unwrap();

        println!("cargo:warning=Timeout set for demo version");
        println!("cargo:warning=- date of compilation: \t{now_formatted}");
        println!(
            "cargo:warning=- end of demo in {DEMO_TIMEOUT} days:\t{three_months_later_formatted}"
        );
        let out_dir = env::var_os("OUT_DIR").unwrap();
        let dest_path = Path::new(&out_dir).join("demo_timeout.rs");
        fs::write(
            dest_path,
            format!(
                "const DEMO_TIMEOUT: &[u8] = &{:?};
            ",
                three_months_later_formatted.as_bytes()
            ),
        )
        .unwrap();
        println!("cargo:rerun-if-changed=build.rs");
    }
}
