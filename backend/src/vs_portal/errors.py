"""Portal-only nested public errors; panel response shape is unchanged."""
from fastapi import Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException

from vs_router.api.errors import APIError, issue, validation_details


def nested(code, details=None):
    return {'error': issue(code, details)}


def install_errors(app):
    @app.exception_handler(APIError)
    async def api_error(request: Request, exc: APIError):
        return JSONResponse(nested(exc.code, exc.details), status_code=exc.status,
                            headers={'Cache-Control': 'no-store'})

    @app.exception_handler(RequestValidationError)
    async def invalid_request(request: Request, exc: RequestValidationError):
        return JSONResponse(nested('request.invalid', validation_details(exc)), status_code=422,
                            headers={'Cache-Control': 'no-store'})

    @app.exception_handler(HTTPException)
    async def http_error(request: Request, exc: HTTPException):
        return JSONResponse(nested(f'http.{exc.status_code}'), status_code=exc.status_code,
                            headers={'Cache-Control': 'no-store', **(exc.headers or {})})

    @app.exception_handler(Exception)
    async def internal_error(request: Request, exc: Exception):
        return JSONResponse(nested('internal.error'), status_code=500,
                            headers={'Cache-Control': 'no-store'})
