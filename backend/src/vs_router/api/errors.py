"""Public errors never contain submitted values or exception messages."""
from fastapi import Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException


class APIError(Exception):
    def __init__(self, status: int, code: str, details=None):
        self.status = status
        self.code = code
        self.details = details if details is not None else []


def issue(code: str, details=None):
    return {"code": code, "message": code, "details": details or []}


def validation_details(exc):
    # Even error messages/context can contain private input (e.g. ipaddress).
    return [{"path": list(e["loc"]), "type": e["type"]} for e in exc.errors()]


def install_errors(app):
    @app.exception_handler(APIError)
    async def api_error(request: Request, exc: APIError):
        return JSONResponse(issue(exc.code, exc.details), status_code=exc.status)

    @app.exception_handler(RequestValidationError)
    async def invalid_request(request: Request, exc: RequestValidationError):
        return JSONResponse(issue("request.invalid", validation_details(exc)), status_code=422)

    @app.exception_handler(HTTPException)
    async def http_error(request: Request, exc: HTTPException):
        return JSONResponse(issue(f"http.{exc.status_code}"), status_code=exc.status_code,
                            headers=exc.headers)

    @app.exception_handler(Exception)
    async def internal_error(request: Request, exc: Exception):
        return JSONResponse(issue("internal.error"), status_code=500)
