"""Alias import/export: JSON bundles with includes, TXT and CSV simple lists."""
import csv
import io
import ipaddress
import json
import re

from fastapi import APIRouter, Body, Depends
from fastapi.responses import Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..db import ConfigurationRow
from ..schema import Alias, Configuration
from ..validators import port_range
from .auth import admin, get_db
from .errors import APIError
from .versions import draft

router = APIRouter()

HOSTNAME = re.compile(r'^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$')


def _source_rows(db: Session):
    """Aliases of the current draft, falling back to the latest confirmed version."""
    row = db.scalar(select(ConfigurationRow).where(ConfigurationRow.status == 'draft'))
    if row is None:
        row = db.scalars(select(ConfigurationRow).where(ConfigurationRow.status == 'confirmed')
                         .order_by(ConfigurationRow.id.desc())).first()
    return row.configuration.aliases if row else ()


@router.post('/aliases/export', dependencies=[Depends(admin)])
def export_aliases(body: dict = Body(), db: Session = Depends(get_db)):
    fmt = body.get('format')
    names = body.get('names')
    if fmt not in {'json', 'txt', 'csv'} or (names is not None and not isinstance(names, list)):
        raise APIError(400, 'alias.export_invalid')
    rows = [a for a in _source_rows(db) if names is None or a.name in names]
    if fmt == 'json':
        data = json.dumps({'schema_version': 1, 'aliases': [
            {'name': a.name, 'type': a.type, 'description': '',
             'elements': list(a.elements), 'includes': list(a.includes)} for a in rows]},
            ensure_ascii=False)
    elif fmt == 'txt':
        data = '\n'.join(v for a in rows for v in a.elements)
    else:
        out = io.StringIO()
        writer = csv.writer(out)
        writer.writerow(['value', 'description'])
        for a in rows:
            for v in a.elements:
                writer.writerow([v, ''])
        data = out.getvalue()
    return Response(data, media_type={'json': 'application/json', 'txt': 'text/plain',
                                      'csv': 'text/csv'}[fmt],
                    headers={'Content-Disposition': f'attachment; filename="aliases.{fmt}"'})


def _valid_address(value):
    if '-' in value and '/' not in value:
        lo, hi = value.split('-', 1)
        lo_ip, hi_ip = ipaddress.ip_address(lo), ipaddress.ip_address(hi)
        if lo_ip.version != hi_ip.version or int(lo_ip) > int(hi_ip):
            raise ValueError()
    else:
        ipaddress.ip_network(value, strict=False)


def parse_import(data):
    """Returns (aliases, errors); accepts JSON shapes, TXT and CSV text."""
    errors, aliases = [], []
    if isinstance(data, str):
        lines = data.splitlines()
        rows = []
        if lines and lines[0].strip().lower().replace(' ', '') == 'value,description':
            for n, row in enumerate(csv.reader(lines), 1):
                if n == 1 or not row:
                    continue
                rows.append((n, row[0], row[1] if len(row) > 1 else ''))
        else:
            rows = [(n, s.split('#', 1)[0].strip(), '')
                    for n, s in enumerate(lines, 1) if s.split('#', 1)[0].strip()]
        is_ports = any(re.match(r'^(tcp|udp)/', v) for _, v, _ in rows)
        groups = {}
        for n, v, _ in rows:
            try:
                if is_ports:
                    match = re.fullmatch(r'(tcp|udp)/(\d+(?:-\d+)?)', v)
                    if not match:
                        raise ValueError()
                    port_range(match[2])
                    value = f'{match[1]}/{match[2]}'
                else:
                    _valid_address(v)
                    value = v
                groups.setdefault('imported', []).append(value)
            except Exception:
                errors.append({'line': n, 'message': 'alias.invalid_element'})
        if groups:
            aliases = [{'name': 'imported', 'type': 'port' if is_ports else 'address',
                        'elements': groups['imported'], 'includes': []}]
    elif isinstance(data, list):
        aliases = data
    elif isinstance(data, dict) and data.get('schema_version') == 1:
        aliases = data.get('aliases', [])
    else:
        errors.append({'line': 1, 'message': 'alias.invalid_document'})
    return aliases, errors


@router.post('/aliases/import-preview', dependencies=[Depends(admin)])
def import_preview(body: dict = Body(), db: Session = Depends(get_db)):
    aliases, errors = parse_import(body.get('data', body.get('aliases', [])))
    existing = {a.name for a in _source_rows(db)}
    seen, parsed = set(), []
    for i, a in enumerate(aliases, 1):
        try:
            x = Alias.model_validate(a)
            if x.type == 'address':
                for el in x.elements:
                    _valid_address(el)
            else:
                for el in x.elements:
                    port_range(el)
            parsed.append(x.model_dump(mode='json'))
            if x.name in existing or x.name in seen:
                errors.append({'line': i, 'message': 'alias.duplicate_name'})
            seen.add(x.name)
        except ValueError:
            errors.append({'line': i, 'message': 'alias.invalid_element'})
        except Exception:
            errors.append({'line': i, 'message': 'alias.invalid'})
    by = {a['name']: a for a in parsed}
    for a in parsed:
        for inc in a.get('includes', []):
            target = by.get(inc)
            if target and target['type'] != a['type']:
                errors.append({'line': 1, 'message': 'alias.incompatible_include'})
    visiting, visited = set(), set()

    def walk(name):
        if name in visiting:
            raise ValueError()
        if name in visited:
            return
        visiting.add(name)
        for inc in by.get(name, {}).get('includes', []):
            if inc in by:
                walk(inc)
        visiting.remove(name)
        visited.add(name)

    try:
        for name in by:
            walk(name)
    except ValueError:
        errors.append({'line': 1, 'message': 'alias.cycle'})
    return {'ok': not errors, 'errors': errors, 'aliases': parsed}


@router.post('/aliases/import', dependencies=[Depends(admin)])
def import_aliases(body: dict = Body(), db: Session = Depends(get_db)):
    parsed = import_preview({'aliases': body.get('aliases', [])}, db)
    if not parsed['ok']:
        raise APIError(422, 'alias.import_invalid', parsed['errors'])
    mode = body.get('mode', 'replace')
    if mode not in ('replace', 'skip'):
        raise APIError(400, 'alias.import_mode')
    row = db.scalar(select(ConfigurationRow).where(ConfigurationRow.status == 'draft'))
    if row is None:
        previous = db.scalars(select(ConfigurationRow).where(ConfigurationRow.status == 'confirmed')
                              .order_by(ConfigurationRow.id.desc())).first()
        row = ConfigurationRow(id=(db.scalar(select(func.max(ConfigurationRow.id))) or 0) + 1,
                               status='draft',
                               configuration=previous.configuration if previous else Configuration())
        db.add(row)
        db.flush()
    current = {a.name: a for a in row.configuration.aliases}
    for a in parsed['aliases']:
        if a['name'] not in current or mode == 'replace':
            current[a['name']] = Alias.model_validate(a)
    row.configuration = Configuration.model_validate(
        {**row.configuration.model_dump(mode='json'),
         'aliases': [a.model_dump(mode='json') for a in current.values()]})
    db.commit()
    return {'imported': len(parsed['aliases'])}
