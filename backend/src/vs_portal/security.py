"""Key retrieval shared with panel's Fernet secret, never generated at runtime."""
import os
from pathlib import Path

from cryptography.fernet import Fernet

from vs_router.api.errors import APIError


def get_secret_key() -> bytes:
    raw = os.environ.get('VS_ROUTER_SECRET_KEY')
    if raw is None:
        path = Path(os.environ.get('VS_ROUTER_SECRET_KEY_FILE', '/etc/vs-router/secrets.key'))
        try:
            raw = path.read_text().strip()
            if raw.startswith('VS_ROUTER_SECRET_KEY='):
                raw = raw.split('=', 1)[1].strip().strip('"')
        except OSError:
            raise APIError(503, 'secret.encryption_unavailable') from None
    try:
        key = raw.encode()
        Fernet(key)
        return key
    except (ValueError, TypeError):
        raise APIError(503, 'secret.encryption_unavailable') from None
