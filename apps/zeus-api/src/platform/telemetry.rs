use std::env;

use opentelemetry::{KeyValue, global, trace::TracerProvider as _};
use opentelemetry_sdk::{Resource, trace::SdkTracerProvider};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

pub struct TelemetryGuard {
    provider: Option<SdkTracerProvider>,
}

/// Installs structured JSON logging and optional OTLP trace export.
///
/// OTLP is enabled only when `OTEL_EXPORTER_OTLP_ENDPOINT` or
/// `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` is present. Exporter headers remain in
/// the standard OpenTelemetry environment variables and are never logged.
///
/// # Errors
///
/// Returns an error when the tracing subscriber or configured exporter cannot
/// be initialized.
pub fn init() -> anyhow::Result<TelemetryGuard> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let json = tracing_subscriber::fmt::layer()
        .json()
        .with_current_span(false)
        .with_target(false);
    let otlp_enabled = env::var_os("OTEL_EXPORTER_OTLP_ENDPOINT").is_some()
        || env::var_os("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT").is_some();

    if !otlp_enabled {
        tracing_subscriber::registry()
            .with(filter)
            .with(json)
            .try_init()?;
        return Ok(TelemetryGuard { provider: None });
    }

    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_http()
        .build()?;
    let resource = Resource::builder()
        .with_service_name("zeus-api")
        .with_attribute(KeyValue::new("service.version", env!("CARGO_PKG_VERSION")))
        .build();
    let provider = SdkTracerProvider::builder()
        .with_resource(resource)
        .with_batch_exporter(exporter)
        .build();
    let tracer = provider.tracer("zeus-api");
    global::set_tracer_provider(provider.clone());
    tracing_subscriber::registry()
        .with(filter)
        .with(json)
        .with(tracing_opentelemetry::layer().with_tracer(tracer))
        .try_init()?;
    Ok(TelemetryGuard {
        provider: Some(provider),
    })
}

impl TelemetryGuard {
    /// Flushes and shuts down the configured trace provider.
    ///
    /// # Errors
    ///
    /// Returns an error when the provider cannot flush pending spans.
    pub fn shutdown(self) -> anyhow::Result<()> {
        if let Some(provider) = self.provider {
            provider
                .shutdown()
                .map_err(|error| anyhow::anyhow!("OpenTelemetry shutdown failed: {error}"))?;
        }
        Ok(())
    }
}
