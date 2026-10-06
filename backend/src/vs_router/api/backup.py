"""Configuration backup: JSON export with optional password-encrypted secrets."""
import base64
import json
import os
from typing import Any, cast

from cryptography.fernet import Fernet
from cryptography.fernet import InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from fastapi import APIRouter, Body, Depends, Response
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..db import ConfigurationRow, UserRow
from ..generators.wireguard import materialize_addresses
from ..schema import Configuration
from .auth import admin, get_db
from .configuration import encrypt_inputs, redact
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


def _secrets_match_host(value, key):
    if isinstance(value, dict):
        if value.get('encrypted') is True and 'ciphertext' in value:
            try:
                Fernet(key).decrypt(value['ciphertext'].encode())
            except (InvalidToken, ValueError, TypeError):
                return False
            return True
        return all(_secrets_match_host(item, key) for item in value.values())
    if isinstance(value, list):
        return all(_secrets_match_host(item, key) for item in value)
    return True


def _portable_secrets(value, key):
    """Place plaintext only inside the password-encrypted archive payload."""
    if isinstance(value, dict):
        if value.get('encrypted') is True and 'ciphertext' in value:
            return {'plaintext': Fernet(key).decrypt(value['ciphertext'].encode()).decode()}
        return {name: _portable_secrets(item, key) for name, item in value.items()}
    if isinstance(value, list):
        return [_portable_secrets(item, key) for item in value]
    return value


@router.get('/backup/export', dependencies=[Depends(admin)])
def export_redacted(response: Response, db: Session = Depends(get_db)):
    response.headers['Cache-Control'] = 'no-store'
    return export_archive(False, None, db)


@router.post('/backup/export', dependencies=[Depends(admin)])
def export(response: Response, body: dict = Body(), db: Session = Depends(get_db)):
    include_secrets = body.get('include_secrets') is True
    password = body.get('password')
    if include_secrets and (not isinstance(password, str) or not password):
        raise APIError(422, 'backup.password_required')
    response.headers['Cache-Control'] = 'no-store'
    return export_archive(include_secrets, password, db)


def export_archive(include_secrets, password, db):
    versions = []
    for row in db.scalars(select(ConfigurationRow).order_by(ConfigurationRow.id)):
        data = row.snapshot().model_dump(mode='json')
        if include_secrets and password:
            try:
                raw = json.dumps(_portable_secrets(data['configuration'], os.environ.get(
                    'VS_ROUTER_SECRET_KEY', '').encode())).encode()
            except (InvalidToken, ValueError, TypeError, UnicodeDecodeError):
                raise APIError(503, 'backup.secret_key_unavailable') from None
            salt = os.urandom(16)
            data['secret_blob'] = {'format': 'plaintext-v1', 'salt': base64.b64encode(salt).decode(),
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
    versions = body.get('versions')
    if body.get('schema_version') != 1 or not isinstance(versions, list) or not versions:
        raise APIError(400, 'backup.bad_payload')
    item = versions[-1]
    if isinstance(item, dict) and item.get('secret_blob') and not body.get('password'):
        raise APIError(400, 'backup.password_required')
    try:
        config = item['configuration']
        if item.get('secret_blob'):
            blob = item['secret_blob']
            salt = base64.b64decode(blob['salt'])
            config = json.loads(Fernet(_derive_key(body['password'], salt))
                                .decrypt(blob['ciphertext'].encode()))
            if blob.get('format') == 'plaintext-v1':
                config = encrypt_inputs(config)
            elif blob.get('format') is not None:
                raise ValueError()
        config = _blank_markers(config)
        config = _drop_empty_secrets(config)
        if not isinstance(config, dict):
            raise ValueError()
        config = cast(dict[str, Any], config)
        # Omit secret-bearing records whose secrets were not restored.
        partial = (any(not x.get('private_key') for x in config.get('tunnels', []))
                   or any(not x.get('api_token') for x in config.get('ddns', []))
                   or any(x.get('certificate_mode') == 'manual'
                          and (not x.get('certificate') or not x.get('private_key'))
                          for x in config.get('sites', [])))
        config['tunnels'] = [x for x in config.get('tunnels', []) if x.get('private_key')]
        config['ddns'] = [x for x in config.get('ddns', []) if x.get('api_token')]
        config['sites'] = [x for x in config.get('sites', [])
                           if x.get('certificate_mode') != 'manual'
                           or (x.get('certificate') and x.get('private_key'))]
        configuration = Configuration.model_validate(config)
    except APIError:
        raise
    except Exception:
        raise APIError(400, 'backup.bad_payload') from None
    if not _secrets_match_host(configuration.model_dump(mode='json'),
                               os.environ.get('VS_ROUTER_SECRET_KEY', '').encode()):
        raise APIError(400, 'backup.secret_key_mismatch')
    if db.scalar(select(ConfigurationRow.id).where(ConfigurationRow.status == 'draft')) is not None:
        raise APIError(409, 'draft.exists')
    if partial and body.get('allow_partial') is not True:
        raise APIError(409, 'backup.partial_requires_confirmation')
    # Materialize the deterministic tunnel/peer addresses, as a draft save does.
    configuration = materialize_addresses(configuration)
    next_id = db.scalar(select(func.max(ConfigurationRow.id))) or 0
    # Import one snapshot for explicit apply. Old archive history is not host state.
    db.add(ConfigurationRow(id=next_id + 1, status='draft', configuration=configuration))
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise APIError(409, 'draft.exists') from None
    return {'restored': 1, 'skipped': len(versions) - 1}
