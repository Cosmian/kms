use std::time::Duration;

// check every 1 hour
const ONE_HOUR: Duration = Duration::from_secs(60 * 60); // 1 hour

pub(crate) async fn demo_timeout() {
    // Demo timeout feature disabled - no expiration logic
    loop {
        actix_rt::time::sleep(ONE_HOUR).await;
    }
}
