"""Typed PPPoE artifact bundle and fixed host-side validation."""
import json
import re
from ..generators import generate_pppoe

FILES = {'pppoe': 'pppoe.json'}
_PEER = re.compile(r'/etc/ppp/peers/vs-router-([A-Za-z][A-Za-z0-9_.-]{0,14})\Z')
_SECRETS = {'/etc/ppp/pap-secrets', '/etc/ppp/chap-secrets'}


def interfaces(bundle):
    files = json.loads(bundle)
    if not isinstance(files, dict):
        raise ValueError('pppoe.invalid_bundle')
    names = []
    for path, content in files.items():
        match = _PEER.fullmatch(path)
        if match:
            names.append(match.group(1))
        elif path not in _SECRETS:
            raise ValueError('pppoe.invalid_bundle')
        if not isinstance(content, str):
            raise ValueError('pppoe.invalid_bundle')
    if (len(set(names)) != len(names) or
            (set(files) & _SECRETS not in (set(), _SECRETS)) or
            (bool(names) != bool(set(files) & _SECRETS))):
        raise ValueError('pppoe.invalid_bundle')
    return files, sorted(names)


def generate(version, key):
    return json.dumps(generate_pppoe(version, key), sort_keys=True)
