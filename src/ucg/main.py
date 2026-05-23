from fastapi import FastAPI

from ucg.api.router import api_router
from ucg.core.config import get_settings
from ucg.core.logging import configure_logging


def create_app() -> FastAPI:
    settings = get_settings()
    configure_logging(settings.log_level)

    app = FastAPI(
        title="Unified Context Graph",
        version="0.1.0",
        description=(
            "Context graph APIs for cyber, agentic SOC, risk, privacy, identity, "
            "and AI trust."
        ),
    )
    app.include_router(api_router)
    return app


app = create_app()
