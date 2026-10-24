"""Master portal administrator application."""
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from vs_portal.errors import install_errors, nested

from . import admin_api, auth
from .models import make_engine


def create_master_app(engine=None, database_url=None, clock=None):
    app = FastAPI(title='vs-master', docs_url=None)
    app.state.engine = engine if engine is not None else make_engine(database_url)
    app.state.auth = auth.AuthState(clock=clock)
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
    app.include_router(admin_api.router)

    @app.get('/health')
    async def health():
        return {'status': 'ok'}

    return app


app = create_master_app()
