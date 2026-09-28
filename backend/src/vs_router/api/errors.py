"""Public errors never contain submitted values or exception messages."""
import re

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
    def humanize(e):
        msg = e.get("msg", "")
        # Only expose our own short validator codes (e.g. interface.vlan_parent).
        # Third-party messages (ipaddress etc.) embed user input — never echo those.
        if msg.startswith("Value error, "):
            msg = msg[len("Value error, "):]
        if not re.fullmatch(r"[a-z0-9]+(?:\.[a-z0-9_]+)+", msg):
            msg = ""
        return {"path": list(e["loc"]), "type": e["type"], "message": msg}
    return [humanize(e) for e in exc.errors()]


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
