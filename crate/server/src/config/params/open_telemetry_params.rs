#[derive(Clone, Debug)]
pub struct OpenTelemetryConfig {
    /// The OTLP collector URL for gRPC
    /// (for instance, <http://localhost:4317>)
    /// If not set, the telemetry system will not be initialized
    pub otlp_url: Option<String>,

    /// Enable metering in addition to tracing when telemetry is enabled
    pub enable_metering: bool,

    /// The name of the environment (development, test, production, etc.)
    /// This will be added to the telemetry data if telemetry is enabled
    pub environment: Option<String>,
}
