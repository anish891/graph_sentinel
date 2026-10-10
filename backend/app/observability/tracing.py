"""OpenTelemetry tracing. Spans are no-ops unless OTEL_EXPORTER_OTLP_ENDPOINT is set."""

from __future__ import annotations

from opentelemetry import trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

_configured = False


def configure_tracing(otlp_endpoint: str | None, service_name: str = "graphsentinel-backend") -> bool:
    """Install an OTLP exporter if an endpoint is configured. Returns True when exporting."""
    global _configured  # noqa: PLW0603
    if _configured or not otlp_endpoint:
        return _configured
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

    provider = TracerProvider(resource=Resource.create({"service.name": service_name}))
    provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=otlp_endpoint.rstrip("/") + "/v1/traces")))
    trace.set_tracer_provider(provider)
    _configured = True
    return True


tracer = trace.get_tracer("graphsentinel")
