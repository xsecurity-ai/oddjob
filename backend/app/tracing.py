"""OpenTelemetry tracing, off unless an OTLP endpoint is configured.

Nothing here runs by default. `setup_tracing` returns immediately unless
OTEL_EXPORTER_OTLP_ENDPOINT is set, so an install that does not want
tracing pays nothing and behaves exactly as before. The exporter packages
are an optional extra (`uv sync --extra tracing`); without them the import
below fails and tracing stays off rather than taking the app down with it.

Three decisions worth stating, because each one is a trap:

  bodies            Nothing captures request or response bodies. The agent
                    traffic is sealed by AgentSeal and a span attribute
                    holding a decrypted scan result would undo that — the
                    whole point of sealing is that the route sees plaintext
                    and nothing else does.
  excluded URLs     The ghost agents poll /api/ghosts/heartbeat and the
                    container healthcheck hits /api/auth/setup-required on
                    a timer. Tracing those is thousands of identical spans
                    a day that bury the requests anyone cares about, so
                    they are excluded by default.
  failure mode      An unreachable collector must never become an outage.
                    BatchSpanProcessor drops spans when its queue fills and
                    the exporter's own errors are swallowed, so a dead
                    collector costs spans, not requests.
"""
from __future__ import annotations

import logging
import os

log = logging.getLogger(__name__)

# Standard OTel variable, not an ODDJOB_ one: every OTel SDK, collector and
# piece of documentation already uses this name, and inventing a synonym
# would mean the one thing an operator already knows does not work.
ENDPOINT = (os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT") or "").strip()

# Endpoints whose spans would be noise. Overridable, but the default is the
# set this app actually polls itself.
EXCLUDED_URLS = os.environ.get(
    "OTEL_PYTHON_FASTAPI_EXCLUDED_URLS",
    "api/ghosts/heartbeat,api/auth/setup-required,api/events,healthz,metrics",
)



def _sqlalchemy_instrumentable() -> bool:
    """True when the installed SQLAlchemy is inside the instrumentor's range."""
    try:
        from importlib.metadata import version

        major, minor = (int(part) for part in version("sqlalchemy").split(".")[:2])
    except Exception:                                        # noqa: BLE001
        return False
    return (major, minor) < (2, 1)

def setup_tracing(app) -> bool:
    """Instrument `app` and return whether tracing was actually enabled."""
    if not ENDPOINT:
        return False

    try:
        from opentelemetry import trace
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        from opentelemetry.instrumentation.asyncpg import AsyncPGInstrumentor
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
        from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
        from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
    except ImportError:
        # The extra is not installed. Say so once and carry on untraced;
        # a missing optional dependency is not a reason to refuse to boot.
        log.warning(
            "OTEL_EXPORTER_OTLP_ENDPOINT is set but the tracing extra is not "
            "installed; run `uv sync --extra tracing`. Continuing untraced."
        )
        return False

    # OTEL_SERVICE_NAME is read by Resource.create() along with
    # OTEL_RESOURCE_ATTRIBUTES; naming the service here only supplies a
    # default for the deployment that sets neither.
    resource = Resource.create({"service.name": os.environ.get("OTEL_SERVICE_NAME", "oddjob")})

    provider = TracerProvider(resource=resource)
    provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
    trace.set_tracer_provider(provider)

    # instrument_app, not the global instrumentor: this attaches middleware
    # to THIS app rather than patching FastAPI itself, so the test suite can
    # build other apps without inheriting a tracer pointed at a collector
    # that is not there.
    FastAPIInstrumentor.instrument_app(app, excluded_urls=EXCLUDED_URLS)

    # SQLAlchemyInstrumentor pins itself to sqlalchemy < 2.1.0 and, on
    # anything newer, logs an ERROR and then instruments nothing. This
    # project is already on 2.1, so calling it unconditionally buys a
    # frightening line in the log at every boot that describes a no-op.
    # Version-gate it instead, and let it start working by itself when the
    # instrumentor catches up. The Postgres query spans come from asyncpg
    # below either way; on SQLite there are none from either package.
    if _sqlalchemy_instrumentable():
        # enable_commenter writes the trace id into the SQL as a comment,
        # which is what lets a slow query in pg_stat_statements be traced
        # back to the request that issued it.
        SQLAlchemyInstrumentor().instrument(enable_commenter=True)

    AsyncPGInstrumentor().instrument()
    HTTPXClientInstrumentor().instrument()

    log.info("tracing enabled, exporting to %s", ENDPOINT)
    return True
