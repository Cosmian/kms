use thiserror::Error;

#[derive(Error, Debug)]
pub enum LoggerError {
    #[error("OTLP error: {0}")]
    Otlp(String),

    #[error("Parsing error: {0}")]
    Parsing(String),

    #[error("Tracing subscriber error: {0}")]
    TracingSubscriber(String),

    #[error("IO error: {0}")]
    IOError(String),
}

#[cfg(feature = "full")]
impl From<opentelemetry_otlp::ExporterBuildError> for LoggerError {
    fn from(e: opentelemetry_otlp::ExporterBuildError) -> Self {
        Self::Otlp(e.to_string())
    }
}

impl From<tracing_subscriber::filter::ParseError> for LoggerError {
    fn from(e: tracing_subscriber::filter::ParseError) -> Self {
        Self::Parsing(e.to_string())
    }
}

impl From<tracing_subscriber::util::TryInitError> for LoggerError {
    fn from(value: tracing_subscriber::util::TryInitError) -> Self {
        Self::TracingSubscriber(value.to_string())
    }
}

impl From<std::ffi::NulError> for LoggerError {
    fn from(e: std::ffi::NulError) -> Self {
        Self::Parsing(e.to_string())
    }
}
