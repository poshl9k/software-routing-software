"""Authenticated, uncached runtime reads and typed engine/Clash controls."""
from typing import Annotated, Literal

from fastapi import APIRouter, Body, Depends, Path, Query, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from ..agent.rpc import (EmptyParams, EngineControlParams, ClashCloseParams,
                         ClashLogsParams, ClashSelectParams, ClashDelayParams)
from .auth import current_user
from .errors import APIError, issue
from .versions import agent_call

router = APIRouter(dependencies=[Depends(current_user)])
Tag = Annotated[str, Path(pattern=r'^[a-zA-Z0-9_][a-zA-Z0-9_.-]*$', max_length=128)]
ConnectionID = Annotated[str, Path(pattern=r'^[a-zA-Z0-9_-]+$', max_length=128)]
Action = Annotated[Literal['start', 'stop', 'restart'], Path()]


class SelectBody(BaseModel):
    model_config = ConfigDict(extra='forbid')
    name: str = Field(min_length=1, max_length=128,
                      pattern=r'^[a-zA-Z0-9_][a-zA-Z0-9_.-]*$')


def call(response: Response, method, params):
    response.headers['Cache-Control'] = 'no-store'
    try:
        return agent_call(method, params)
    except APIError as exc:
        code = 'agent.unavailable' if exc.code == 'agent.internal_error' else exc.code
        return JSONResponse(issue(code, exc.details),
                            status_code=503 if code in ('agent.unavailable', 'clash.unavailable') else exc.status,
                            headers={'Cache-Control': 'no-store'})


@router.get('/runtime/engine')
def engine_status(response: Response):
    return call(response, 'engine_status', EmptyParams())


@router.post('/runtime/engine/{action}')
def engine_control(action: Action, response: Response):
    return call(response, 'engine_control', EngineControlParams(action=action))


@router.get('/runtime/connections')
def connections(response: Response):
    return call(response, 'clash_connections', EmptyParams())


@router.post('/runtime/connections/{id}/close')
def close(id: ConnectionID, response: Response):
    return call(response, 'clash_close', ClashCloseParams(id=id))


@router.get('/runtime/logs')
def logs(response: Response, level: Literal['debug', 'info', 'warning', 'error'] = 'info',
         limit: int = Query(default=50, ge=1, le=200)):
    return call(response, 'clash_logs', ClashLogsParams(level=level, limit=limit))


@router.get('/runtime/proxies')
def proxies(response: Response):
    return call(response, 'clash_proxies', EmptyParams())


@router.post('/runtime/proxies/{group}/select')
def select(group: Tag, response: Response, body: SelectBody = Body()):
    return call(response, 'clash_select', ClashSelectParams(group=group, name=body.name))


@router.get('/runtime/proxies/{tag}/delay')
def delay(tag: Tag, response: Response, url: str = Query(max_length=2048),
          timeout_ms: int = Query(default=3000, ge=100, le=10000)):
    return call(response, 'clash_delay', ClashDelayParams(tag=tag, url=url, timeout_ms=timeout_ms))
