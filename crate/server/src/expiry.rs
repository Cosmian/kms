use std::time::Duration;

use chrono::{DateTime, Utc};
use tracing_log::log::warn;

// check every 1 hour
const ONE_HOUR: Duration = Duration::from_secs(60 * 60); // 1 hour

// include timeout datetime defined at compile-time (see `build.rs` file)
include!(concat!(env!("OUT_DIR"), "/demo_timeout.rs"));

/// # Panics
///
/// Will panic if automatically generated datetime cannot be stringified back
pub async fn demo_timeout() {
    loop {
        {
            let now = Utc::now();
            let end = DateTime::parse_from_rfc2822(
                &String::from_utf8(DEMO_TIMEOUT.to_vec())
                    .expect("should be ok to convert back to String"),
            )
            .expect("should be able to parse rfc2822 datetime");
            if now > end {
                warn!("Shutting down...");
                warn!("Demo version expired ! If you ❤️  this software please buy a license 🦀");
                warn!("Reach us at https://cosmian.com/contact-us");
                break
            }
        }
        actix_rt::time::sleep(ONE_HOUR).await;
    }
}
