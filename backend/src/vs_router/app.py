import os
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

from .api import auth, versions
from .api.errors import install_errors, issue


def create_app(engine=None, *, database_url=None, clock=None) -> FastAPI:
    app = FastAPI(title="vs-router", version="0.1.0")
    if engine is None:
        url = database_url or os.environ.get("VS_ROUTER_DATABASE_URL", "sqlite:///vs-router.db")
        options = {"connect_args": {"check_same_thread": False}} if url.startswith("sqlite:") else {}
        if url in ("sqlite://", "sqlite:///:memory:"):
            options["poolclass"] = StaticPool
        engine = create_engine(url, **options)
    # Tables are created by Alembic, never implicitly at application startup.
    app.state.engine = engine
    app.state.auth = auth.AuthState(**({"clock": clock} if clock is not None else {}))
    install_errors(app)

    @app.middleware("http")
    async def same_origin(request: Request, call_next):
        if request.method not in {"GET", "HEAD", "OPTIONS"}:
            origin = request.headers.get("origin")
            expected = f"{request.url.scheme}://{request.url.netloc}"
            if (origin is not None and origin != expected) or request.headers.get("sec-fetch-site") == "cross-site":
                return JSONResponse(issue("request.cross_origin"), status_code=403)
        return await call_next(request)

    app.include_router(auth.router, prefix="/api")
    app.include_router(versions.router, prefix="/api")

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    return app


app = create_app()
