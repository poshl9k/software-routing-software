"""Public read-only publication of client rule-sets (no secrets, exact version)."""
from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from vs_router.api.errors import APIError

from .models import RuleSet

router = APIRouter(prefix='/api/rulesets')


def get_db(request: Request):
    with Session(request.app.state.engine) as db:
        yield db


def _yaml(content):
    lines = ['payload:']
    lines.extend(f'  - {_quote(entry)}' for entry in content.splitlines())
    return '\n'.join(lines) + '\n'


def _quote(entry):
    # Entries are validated to a safe charset, so quoting stays trivial.
    return '"' + entry + '"'


@router.get('/{kind}/{version}.yaml')
def serve(kind: str, version: str, db: Session = Depends(get_db)):
    record = db.scalar(select(RuleSet).where(RuleSet.kind == kind, RuleSet.version == version))
    if record is None:
        raise APIError(404, 'master.ruleset_not_found')
    body = _yaml(record.content)
    return Response(body, media_type='application/yaml; charset=utf-8',
                    headers={'ETag': f'"{record.sha256}"', 'Cache-Control': 'public, max-age=300'})
