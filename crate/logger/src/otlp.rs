use std::time::Duration;

use opentelemetry::{KeyValue, global};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{
    Resource,
    metrics::{MeterProviderBuilder, PeriodicReader, SdkMeterProvider},
    trace::{RandomIdGenerator, Sampler, SdkTracerProvider},
};
use opentelemetry_semantic_conventions::{
    SCHEMA_URL,
    attribute::{DEPLOYMENT_ENVIRONMENT_NAME, SERVICE_NAME, SERVICE_VERSION},
};

use crate::LoggerError;

fn resource(service_name: &str, version: Option<String>, environment: Option<String>) -> Resource {
    let mut attributes = vec![KeyValue::new(SERVICE_NAME, service_name.to_owned())];
    if let Some(version) = version {
        attributes.push(KeyValue::new(SERVICE_VERSION, version));
    }
    if let Some(environment) = environment {
        attributes.push(KeyValue::new(DEPLOYMENT_ENVIRONMENT_NAME, environment));
    }
    Resource::builder()
        .with_service_name(service_name.to_owned())
        .with_schema_url(attributes, SCHEMA_URL)
        .build()
}

/// Internal function to initialize the OTLP tracer
/// that returns a Result with the `SdkTracerProvider`
pub(crate) fn init_tracer_provider(
    service_name: &str,
    url: &str,
    version: Option<String>,
    environment: Option<String>,
) -> Result<SdkTracerProvider, LoggerError> {
    let otlp_exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_endpoint(url.to_owned())
        .with_timeout(Duration::from_secs(3))
        .build()
        .map_err(|e| {
            LoggerError::Otlp(format!(
                "Failed to create OTLP provider exporter. Make sure the endpoint is correct and \
                 the server is running: {e}"
            ))
        })?;

    let tracer_provider = SdkTracerProvider::builder()
        .with_batch_exporter(otlp_exporter)
        .with_id_generator(RandomIdGenerator::default())
        .with_sampler(Sampler::AlwaysOn)
        .with_resource(resource(service_name, version, environment))
        .with_max_events_per_span(64)
        .with_max_attributes_per_span(16)
        .build();

    global::set_tracer_provider(tracer_provider.clone());

    Ok(tracer_provider)
}

// Construct MeterProvider for MetricsLayer
pub(crate) fn init_meter_provider(
    service_name: &str,
    url: &str,
    version: Option<String>,
    environment: Option<String>,
) -> Result<SdkMeterProvider, LoggerError> {
    let exporter = opentelemetry_otlp::MetricExporter::builder()
        .with_tonic()
        .with_temporality(opentelemetry_sdk::metrics::Temporality::default())
        .with_endpoint(url.to_owned())
        .build()
        .map_err(|e| {
            LoggerError::Otlp(format!(
                "Failed to create OTLP meter exporter. Make sure the endpoint is correct and the \
                 server is running: {e}"
            ))
        })?;

    let reader = PeriodicReader::builder(exporter)
        .with_interval(Duration::from_secs(30))
        .build();

    // For debugging in development
    let stdout_reader =
        PeriodicReader::builder(opentelemetry_stdout::MetricExporter::default()).build();

    let meter_provider = MeterProviderBuilder::default()
        .with_resource(resource(service_name, version, environment))
        .with_reader(reader)
        .with_reader(stdout_reader)
        .build();

    global::set_meter_provider(meter_provider.clone());

    Ok(meter_provider)
}
