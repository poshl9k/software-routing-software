"""Configuration backup: JSON export with optional password-encrypted secrets."""
import base64
import json
import os

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from fastapi import APIRouter, Body, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..db import ConfigurationRow, UserRow
from ..schema import Configuration
from .auth import admin, get_db
from .configuration import redact
from .errors import APIError

router = APIRouter()

MARKER = {'secret': 'encrypted'}

SECRET_FIELDS = {'private_key', 'preshared_key', 'certificate', 'private_key', 'dns_api_token', 'api_token'}


def _derive_key(password, salt):
    return base64.urlsafe_b64encode(PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt,
                                               iterations=390000).derive(password.encode()))


def _replace_markers(value):
    if isinstance(value, dict):
        if value == {'redacted': True}:
            return MARKER
        return {k: _replace_markers(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_replace_markers(v) for v in value]
    return value


def _blank_markers(value):
    if isinstance(value, dict):
        if value == MARKER:
            return None
        return {k: _blank_markers(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_blank_markers(v) for v in value]
    return value


def _drop_empty_secrets(value):
    if isinstance(value, dict):
        return {k: _drop_empty_secrets(v) for k, v in value.items()
                if not (k in SECRET_FIELDS and v is None)}
    if isinstance(value, list):
        return [_drop_empty_secrets(v) for v in value]
    return value


@router.get('/backup/export', dependencies=[Depends(admin)])
def export(include_secrets: bool = False, password: str | None = None, db: Session = Depends(get_db)):
    versions = []
    for row in db.scalars(select(ConfigurationRow).order_by(ConfigurationRow.id)):
        data = row.snapshot().model_dump(mode='json')
        if include_secrets and password:
            raw = json.dumps(data['configuration']).encode()
            salt = os.urandom(16)
            data['secret_blob'] = {'salt': base64.b64encode(salt).decode(),
                                   'ciphertext': Fernet(_derive_key(password, salt)).encrypt(raw).decode()}
            data['configuration'] = redact(data['configuration'])
        else:
            data['configuration'] = _replace_markers(redact(data['configuration']))
        versions.append(data)
    return {'schema_version': 1, 'versions': versions,
            'users': [{'username': u.username, 'role': u.role}
                      for u in db.scalars(select(UserRow))]}


@router.post('/backup/restore', dependencies=[Depends(admin)])
def restore(body: dict = Body(), db: Session = Depends(get_db)):
    try:
        if body.get('schema_version') != 1 or not isinstance(body.get('versions'), list):
            raise ValueError()
        configs = []
        for item in body['versions']:
            config = item['configuration']
            if item.get('secret_blob') and body.get('password'):
                blob = item['secret_blob']
                salt = base64.b64decode(blob['salt'])
                config = json.loads(Fernet(_derive_key(body['password'], salt))
                                    .decrypt(blob['ciphertext'].encode()))
            config = _blank_markers(config)
            config = _drop_empty_secrets(config)
            if not isinstance(config, dict):
                raise ValueError()
            # Encrypted schema fields cannot be empty: omit whole secret-bearing
            # records whose secrets were not restored (they must be re-entered).
            config['tunnels'] = [x for x in config.get('tunnels', []) if x.get('private_key')]
            config['ddns'] = [x for x in config.get('ddns', []) if x.get('api_token')]
            config['sites'] = [x for x in config.get('sites', [])
                               if x.get('certificate_mode') != 'manual'
                               or (x.get('certificate') and x.get('private_key'))]
            configs.append(Configuration.model_validate(config))
    except Exception:
        raise APIError(400, 'backup.bad_payload') from None
    next_id = db.scalar(select(func.max(ConfigurationRow.id))) or 0
    db.query(ConfigurationRow).filter(ConfigurationRow.status == 'draft').delete(synchronize_session=False)
    for offset, config in enumerate(configs):
        db.add(ConfigurationRow(id=next_id + offset + 1, status='confirmed', configuration=config))
    db.commit()
    return {'restored': len(configs)}
