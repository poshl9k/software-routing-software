"""Authenticated, uncached read-only host service telemetry."""
from fastapi import APIRouter, Depends, Response
from fastapi.responses import JSONResponse

from ..agent.rpc import EmptyParams
from .auth import current_user
from .errors import APIError, issue
from .versions import agent_call

router = APIRouter(dependencies=[Depends(current_user)])


@router.get('/status/services')
def services(response: Response):
    response.headers['Cache-Control'] = 'no-store'
    try:
        return agent_call('service_status', EmptyParams())
    except APIError as exc:
        code = 'agent.unavailable' if exc.code == 'agent.internal_error' else exc.code
        status = 503 if code == 'agent.unavailable' else exc.status
        return JSONResponse(issue(code, exc.details), status_code=status,
                            headers={'Cache-Control': 'no-store'})
