"""Subscription previews and draft-only refresh proposals; no persistence or engine changes."""
from fastapi import APIRouter, Body, Depends, Response
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..agent.rpc import SubscriptionPreviewParams, SubscriptionRefreshParams
from ..db import ConfigurationRow
from ..schema import ProxySubscription
from .auth import admin, current_user, get_db
from .errors import APIError, issue
from .versions import agent_call

router = APIRouter(dependencies=[Depends(current_user)])


def _confirmed(db: Session, name: str):
    row = db.scalars(select(ConfigurationRow).where(ConfigurationRow.status == 'confirmed')
                     .order_by(ConfigurationRow.id.desc())).first()
    if row is not None:
        for subscription in row.configuration.proxies.subscriptions:
            if subscription.name == name:
                return subscription, row.configuration.proxies
    raise APIError(404, 'subscription.not_found')


def _members(settings, subscription):
    group = next((g for g in settings.groups if g.tag == subscription.name), None)
    tags = set(group.outbounds) if group else set()
    return [outbound for outbound in settings.outbounds if outbound.tag in tags and outbound.tag.startswith('sub_')]


def _call(method, params):
    try:
        return agent_call(method, params)
    except APIError as exc:
        code = 'agent.unavailable' if exc.code == 'agent.internal_error' else exc.code
        return JSONResponse(issue(code, exc.details), status_code=503 if code == 'agent.unavailable' else exc.status,
                            headers={'Cache-Control': 'no-store'})


@router.post('/proxy/subscriptions/preview', dependencies=[Depends(admin)])
def preview(body: SubscriptionPreviewParams, response: Response):
    response.headers['Cache-Control'] = 'no-store'
    return _call('subscription_preview', body)


@router.post('/proxy/subscriptions/{name}/refresh', dependencies=[Depends(admin)])
def refresh(name: str, response: Response, db: Session = Depends(get_db),
            body: dict = Body(default_factory=dict)):
    response.headers['Cache-Control'] = 'no-store'
    subscription, settings = _confirmed(db, name)
    # The URL comes exclusively from the confirmed snapshot, never the request.
    if body and (set(body) != {'authorized'} or type(body['authorized']) is not bool):
        raise APIError(422, 'subscription.invalid_request')
    params = SubscriptionRefreshParams(subscription=subscription, current_members=tuple(_members(settings, subscription)),
                                       authorized=body.get('authorized', False))
    return _call('subscription_refresh', params)


@router.get('/proxy/subscriptions/{name}/members')
def members(name: str, response: Response, db: Session = Depends(get_db)):
    response.headers['Cache-Control'] = 'no-store'
    subscription, settings = _confirmed(db, name)
    return [{'tag': o.tag, 'label': o.server or o.tag, 'protocol': o.type,
             'server': o.server, 'port': o.port, 'excluded': o.tag in subscription.excluded_members}
            for o in _members(settings, subscription)]


@router.patch('/proxy/subscriptions/{name}', dependencies=[Depends(admin)])
def patch_subscription(name: str, response: Response, db: Session = Depends(get_db),
                       changes: dict = Body()):
    """Validate patch, return proposal; caller saves via PUT /api/draft."""
    response.headers['Cache-Control'] = 'no-store'
    subscription, _ = _confirmed(db, name)
    allowed = {'enabled', 'mode', 'url_test', 'test_interval_minutes', 'test_tolerance_ms',
               'filter_include', 'filter_exclude', 'active_member', 'excluded_members',
               'interval_hours', 'headers'}
    if not set(changes) <= allowed:
        raise APIError(422, 'subscription.invalid_request')
    try:
        candidate = ProxySubscription.model_validate({**subscription.model_dump(mode='json'), **changes})
    except ValueError:
        raise APIError(422, 'subscription.invalid_request') from None
    return {field: getattr(candidate, field) for field in changes}
