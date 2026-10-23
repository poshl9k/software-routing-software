"""Public portal app: isolated routes, database, auth and internal transport."""
import os
from threading import RLock

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from . import auth, devices
from .errors import install_errors, nested
from .internal import InternalClient
from .models import make_engine


def create_app(engine=None, *, database_url=None, clock=None, internal_transport=None):
    app = FastAPI(title='vs-portal', lifespan=devices.lifespan)
    app.state.engine = engine if engine is not None else make_engine(database_url)
    app.state.auth = auth.AuthState(clock=clock)
    app.state.internal = InternalClient(transport=internal_transport)
    app.state.device_lock = RLock()
    install_errors(app)

    @app.middleware('http')
    async def same_origin(request: Request, call_next):
        if request.method not in {'GET', 'HEAD', 'OPTIONS'}:
            origin = request.headers.get('origin')
            expected = f'{request.url.scheme}://{request.url.netloc}'
            if (origin is not None and origin != expected) or request.headers.get('sec-fetch-site') == 'cross-site':
                return JSONResponse(nested('request.cross_origin'), status_code=403,
                                    headers={'Cache-Control': 'no-store'})
        response = await call_next(request)
        if request.url.path.startswith('/api/portal/'):
            response.headers['Cache-Control'] = 'no-store'
        return response

    app.include_router(auth.router, prefix='/api/portal')
    app.include_router(devices.router, prefix='/api/portal')

    @app.get('/health')
    async def health() -> dict[str, str]:
        return {'status': 'ok'}

    # The portal shell: any non-API path (e.g. /invite/<token>) serves the SPA.
    static_dir = os.environ.get('VS_PORTAL_STATIC_DIR')
    if static_dir:
        from pathlib import Path
        from fastapi.staticfiles import StaticFiles
        from fastapi.responses import FileResponse
        assets = Path(static_dir) / 'assets'
        if assets.is_dir():
            app.mount('/assets', StaticFiles(directory=assets), name='assets')

            @app.get('/{spa_path:path}', include_in_schema=False)
            async def spa(spa_path: str) -> FileResponse:
                return FileResponse(Path(static_dir) / 'index.html')

    return app


app = create_app()
