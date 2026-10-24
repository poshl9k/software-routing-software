"""Master portal administrator application."""
import os
from threading import RLock

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from vs_portal.errors import install_errors, nested

from . import accounts, admin_api, auth, exports, portal_api
from .models import make_engine


def create_master_app(engine=None, database_url=None, clock=None):
    app = FastAPI(title='vs-master', docs_url=None)
    app.state.engine = engine if engine is not None else make_engine(database_url)
    app.state.auth = auth.AuthState(clock=clock)
    app.state.portal_auth = accounts.AuthState(clock=clock)
    app.state.device_lock = RLock()
    app.state.node_client_factory = None
    install_errors(app)

    @app.middleware('http')
    async def secure_api(request: Request, call_next):
        if request.method not in {'GET', 'HEAD', 'OPTIONS'}:
            origin = request.headers.get('origin')
            expected = f'{request.url.scheme}://{request.url.netloc}'
            if (origin is not None and origin != expected) or \
                    request.headers.get('sec-fetch-site') == 'cross-site':
                return JSONResponse(nested('request.cross_origin'), status_code=403,
                                    headers={'Cache-Control': 'no-store'})
        response = await call_next(request)
        if request.url.path.startswith('/api/'):
            response.headers['Cache-Control'] = 'no-store'
        return response

    app.include_router(auth.router, prefix='/api/admin')
    app.include_router(accounts.router, prefix='/api/portal')
    app.include_router(admin_api.router)
    app.include_router(portal_api.router)
    app.include_router(exports.router)

    @app.get('/health')
    async def health():
        return {'status': 'ok'}

    # The admin SPA: any non-API path (e.g. deep /nodes link) serves the shell.
    static_dir = os.environ.get('VS_MASTER_STATIC_DIR')
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


app = create_master_app()
