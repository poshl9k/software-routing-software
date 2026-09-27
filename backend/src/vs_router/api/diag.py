"""Diagnostics: ping, traceroute and firewall rule counters via the agent RPC."""
import ipaddress
import re

from fastapi import APIRouter, Body, Depends

from .auth import admin
from .errors import APIError
from .versions import agent_call

router = APIRouter(dependencies=[Depends(admin)])

HOSTNAME = re.compile(r'^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$')
IFACE = re.compile(r'^[A-Za-z0-9_.-]{1,15}$')


def valid_host(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return bool(HOSTNAME.fullmatch(host))


def parse_ping(output):
    sent = int(re.search(r'(\d+) packets transmitted', output).group(1))
    received = int(re.search(r'(\d+) (?:packets )?received', output).group(1))
    loss = float(re.search(r'([\d.]+)% packet loss', output).group(1))
    stats = re.search(r'(?:round-trip|min/avg/max(?:/mdev)? = )([\d.]+)/([\d.]+)/([\d.]+)', output)
    return {'sent': sent, 'received': received, 'loss_pct': loss,
            'min_avg_max_ms': list(map(float, stats.groups())) if stats else None}


@router.post('/diag/ping')
def ping(body: dict = Body()):
    host = body.get('host')
    count = body.get('count', 1)
    iface = body.get('source_interface')
    if (not isinstance(host, str) or not valid_host(host)
            or type(count) is not int or not 1 <= count <= 5
            or (iface is not None and not IFACE.fullmatch(iface))):
        raise APIError(422, 'diag.invalid_input')
    return agent_call('diag_ping', {'host': host, 'count': count, 'source_interface': iface})


@router.post('/diag/traceroute')
def traceroute(body: dict = Body()):
    host = body.get('host')
    if not isinstance(host, str) or not valid_host(host):
        raise APIError(422, 'diag.invalid_input')
    return agent_call('diag_traceroute', {'host': host})


@router.get('/diag/rules-counters')
def counters():
    try:
        return agent_call('nft_counters', {})
    except APIError:
        raise
    except Exception:
        raise APIError(503, 'nft.unavailable') from None
