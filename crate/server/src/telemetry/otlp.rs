use opentelemetry::KeyValue;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{runtime, trace as sdktrace, Resource};
use opentelemetry_semantic_conventions::resource::SERVICE_NAME;

use crate::{error::KmsError, result::KResult};

pub(crate) fn init_otlp_tracer(url: String) -> KResult<opentelemetry_sdk::trace::Tracer> {
    opentelemetry_otlp::new_pipeline()
        .tracing()
        .with_exporter(
            opentelemetry_otlp::new_exporter()
                .tonic()
                .with_endpoint(url),
        )
        .with_trace_config(
            sdktrace::Config::default().with_resource(Resource::new(vec![KeyValue::new(
                SERVICE_NAME,
                "cosmian_kms_server",
            )])),
        )
        .install_batch(runtime::Tokio)
        .map_err(|e| KmsError::ServerError(format!("Failed to initialize OTLP telemetry: {e}")))
}
