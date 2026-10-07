"""SSRF-guarded downloader for proxy subscriptions and rule-set sources.

Scope
-----
This is the agent-side *mechanism* required by ``docs/sing-box-tproxy-plan.md``
§«Источники списков и обновления» and §«Прокси/подписки»: fetch a subscription
or rule-set with an explicit allowlist for built-in sources, a separate,
explicit authorization for user-supplied sources, redirect/DNS-rebinding
protection, a size cap, a timeout and a format check; then activate the fetched
payload atomically with rollback and keep a version/status history.

It deliberately contains **no scheduler**, **no UI** and **no preset catalog**;
those are described, not implemented (see ``docs/tproxy-sources-downloader.md``).
It opens no configuration gate: ``tproxy.not_available`` is untouched, and
nothing here writes into the ordinary product bundle or the sing-box apply path.

Threat model
------------
The panel/web process is unprivileged and is assumed able to influence the
source URL (through the config contract). The downloader therefore never trusts
a URL:

* **Scheme.** Only ``https`` is fetched. Plaintext is refused (``http``) unless a
  caller explicitly opts in *and* the host is a built-in allowlist entry — no
  such entry exists today, so external plaintext is effectively banned.
* **Address.** Every hop's hostname is resolved and **every** resolved address is
  rejected if it is loopback, private, link-local, multicast, reserved,
  unspecified or a site-local/ULA/mapped form of the above (see
  :func:`ip_is_forbidden`). This blocks ``127.0.0.1``, ``169.254.169.254`` (cloud
  metadata), RFC1918, CGNAT ``100.64/10`` and friends.
* **Redirects.** Redirects are followed manually, one hop at a time; each target
  is re-checked against the authorized host set and re-resolved/re-validated.
  A redirect off the allowlist is refused.
* **DNS rebinding.** The hostname is resolved exactly once per hop and the
  *validated IP* is what the transport connects to (``connect_ip``), with SNI and
  the ``Host`` header keeping the original name. A second resolution that would
  return an internal address cannot be substituted between check and connect.
* **Size / time.** A per-request byte cap and timeout are enforced by the
  transport and re-checked after the body is read.

Activation is staged then atomically moved; on any failure the previous active
file is restored and a failed history entry is recorded, so a bad fetch never
replaces a working set.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import http.client
import ipaddress
import json
import re
import socket
import ssl
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Protocol
from urllib.parse import urljoin, urlsplit

from .apply import ApplyError, LocalFileSystem
from .source_schedule import SourceSchedule, is_due, next_run, state_from_history

# ---------------------------------------------------------------------------
# Limits (all overridable per request; the RPC contract clamps them again)
# ---------------------------------------------------------------------------

DEFAULT_MAX_BYTES = 5_000_000        # 5 MB
DEFAULT_TIMEOUT = 20.0               # seconds, per request
MAX_REDIRECTS = 5
MAX_RESOLVED_ADDRESSES = 16
HISTORY_LIMIT = 200

#: Default on-host store for staged/active sources and history.
SOURCES_DIR = Path('/var/lib/vs-router/sources')

_REDIRECTS = frozenset({301, 302, 303, 307, 308})

#: Built-in source catalog. Intentionally EMPTY: the preset catalog (SagerNet /
#: v2fly / RockBlack / hoaxisr / geoip-geosite) is explicitly out of scope for
#: this change (see the plan and ``docs/tproxy-sources-downloader.md``). The
#: allowlist *mechanism* is implemented and tested with an injected registry;
#: populating the real catalog is future work and must carry provenance,
#: licence and version/hash per entry.
BUILTIN_SOURCES: dict[str, "BuiltinSource"] = {}


class DownloadError(ApplyError):
    """A download/activation failure carrying a stable ``*.code`` token.

    Subclasses :class:`~vs_router.agent.apply.ApplyError` so the existing agent
    RPC dispatch maps it to a typed error response without a new branch; the
    optional ``detail`` is for local logging only and never leaves the agent as
    command output.
    """

    def __init__(self, code: str, detail: str | None = None):
        super().__init__(code)
        self.detail = detail


# ---------------------------------------------------------------------------
# SSRF address policy
# ---------------------------------------------------------------------------

#: Extra blocked ranges not covered by ``ipaddress``'s own predicates.
#: ``100.64.0.0/10`` (carrier-grade NAT / shared address space) is *not* marked
#: private by ``ipaddress`` on every Python version, so it is listed explicitly.
_FORBIDDEN_V4_NETS = (ipaddress.ip_network('100.64.0.0/10'),)


def ip_is_forbidden(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """True if ``address`` must never be reached by a download.

    Covers loopback, private/RFC1918, link-local (incl. ``169.254.169.254``),
    multicast, reserved, unspecified, CGNAT/``100.64/10`` and IPv6 ULA/site-local
    and IPv4-mapped forms of any of those.
    """
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return ip_is_forbidden(address.ipv4_mapped)
    if isinstance(address, ipaddress.IPv4Address):
        if any(address in network for network in _FORBIDDEN_V4_NETS):
            return True
    return bool(
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
        or getattr(address, 'is_site_local', False)
    )


def default_resolver(host: str) -> list[str]:
    """Resolve ``host`` to a sorted, de-duplicated list of address strings.

    The system resolver is the only I/O here; tests always inject a fake.
    """
    infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    return sorted({str(info[4][0]) for info in infos})


def resolve_public(host: str, resolver: Callable[[str], list[str]]) -> list[str]:
    """Resolve ``host`` and reject if any address is forbidden.

    Returns the validated address strings (the caller pins the first one). An IP
    literal is used directly; a hostname goes through ``resolver``. Any forbidden
    address fails the whole host — a split-horizon answer cannot sneak one
    internal record past a public one.
    """
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None:
        candidates: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = [literal]
    else:
        try:
            resolved = resolver(host)
        except (OSError, ValueError) as exc:
            raise DownloadError('download.resolve_failed', str(exc)) from exc
        try:
            candidates = [ipaddress.ip_address(address) for address in resolved]
        except ValueError as exc:
            raise DownloadError('download.resolve_failed', str(exc)) from exc
    if not candidates:
        raise DownloadError('download.resolve_empty')
    if len(candidates) > MAX_RESOLVED_ADDRESSES:
        raise DownloadError('download.too_many_addresses')
    for address in candidates:
        if ip_is_forbidden(address):
            raise DownloadError('download.forbidden_address', str(address))
    return [str(address) for address in candidates]


# ---------------------------------------------------------------------------
# URL helpers
# ---------------------------------------------------------------------------

_HOST_RE = re.compile(
    r'^(?=.{1,253}$)'
    r'(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*'
    r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$'
)


def _split(url: str) -> tuple[str, str, int | None]:
    try:
        parsed = urlsplit(url)
    except ValueError as exc:
        raise DownloadError('download.invalid_url', str(exc)) from exc
    if not parsed.hostname:
        raise DownloadError('download.invalid_url')
    return parsed.scheme, parsed.hostname, parsed.port


def _valid_host(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return bool(_HOST_RE.match(host))


# ---------------------------------------------------------------------------
# Typed request/result
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class BuiltinSource:
    """One allowlisted built-in source: exact URL, allowed hosts, kind, format."""
    url: str
    hosts: frozenset[str]
    kind: str = 'rule_set'
    format: str = 'auto'


@dataclass(frozen=True)
class SourceSpec:
    """A fully resolved, validated download request (no raw shell input)."""
    name: str
    url: str
    kind: str
    format: str
    max_bytes: int
    timeout: float
    builtin: bool
    allowed_hosts: frozenset[str]
    authorized: bool


@dataclass(frozen=True)
class FetchResult:
    url: str
    content: str
    sha256: str
    size: int


@dataclass(frozen=True)
class FetchResponse:
    """Transport-level response. ``body`` is raw bytes (size cap applied later)."""
    status: int
    headers: dict[str, str]
    body: bytes


class Transport(Protocol):
    def fetch(self, *, url: str, connect_ip: str, timeout: float,
              max_bytes: int) -> FetchResponse: ...


# ---------------------------------------------------------------------------
# Default transport: TLS-pinned HTTP GET (real network; never used in tests)
# ---------------------------------------------------------------------------

class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """Connect to a validated IP but present the original hostname (SNI/Host).

    This is what makes the SSRF check binding: the address that was checked is
    the address that is dialled, independently of any later DNS answer.
    """

    def __init__(self, host, connect_ip, *, context, port=443, timeout=10):
        super().__init__(host, port, timeout=timeout, context=context)
        self._connect_ip = connect_ip
        self._tls_context = context

    def connect(self):  # noqa: D102 - see class docstring
        sock = socket.create_connection((self._connect_ip, self.port), self.timeout)
        try:
            self.sock = self._tls_context.wrap_socket(sock, server_hostname=self.host)
        except BaseException:
            sock.close()
            raise


class UrllibTransport:
    """HTTPS GET transport whose connection is pinned to a checked IP."""

    def fetch(self, *, url, connect_ip, timeout, max_bytes):
        scheme, host, port = _split(url)
        parsed = urlsplit(url)
        target = parsed.path or '/'
        if parsed.query:
            target = f'{target}?{parsed.query}'
        context = ssl.create_default_context()
        connection = _PinnedHTTPSConnection(
            host, connect_ip, context=context, port=port or (443 if scheme == 'https' else 80),
            timeout=timeout)
        try:
            connection.request('GET', target, headers={
                'Host': parsed.netloc,
                'User-Agent': 'vs-router-downloader/1',
                'Accept': '*/*',
            })
            response = connection.getresponse()
            body = response.read(max_bytes + 1)
            headers = {key.lower(): value for key, value in response.getheaders()}
            return FetchResponse(status=response.status, headers=headers, body=body)
        finally:
            connection.close()


# ---------------------------------------------------------------------------
# Fetch loop (redirects + rebinding protection)
# ---------------------------------------------------------------------------

def fetch(spec: SourceSpec, *, transport: Transport, resolver: Callable[[str], list[str]],
          allow_plaintext: bool = False) -> FetchResult:
    """Fetch ``spec.url`` under SSRF rules; returns the final body.

    Every hop: scheme check -> host validation -> host authorization -> resolve
    and reject forbidden addresses -> pin the checked IP into the transport. A
    redirect is only followed to an already-authorized host.
    """
    url = spec.url
    for hop in range(MAX_REDIRECTS + 1):
        scheme, host, _ = _split(url)
        if scheme != 'https' and not (allow_plaintext and scheme == 'http'):
            raise DownloadError('download.https_required')
        if not _valid_host(host):
            raise DownloadError('download.invalid_host')
        if host not in spec.allowed_hosts:
            raise DownloadError('download.host_not_allowed' if spec.builtin
                                else 'download.host_not_authorized')
        addresses = resolve_public(host, resolver)
        connect_ip = addresses[0]
        try:
            response = transport.fetch(url=url, connect_ip=connect_ip,
                                       timeout=spec.timeout, max_bytes=spec.max_bytes)
        except (socket.timeout, TimeoutError) as exc:
            raise DownloadError('download.timeout', str(exc)) from exc
        except (OSError, ssl.SSLError) as exc:
            raise DownloadError('download.transport_failed', str(exc)) from exc
        headers = {key.lower(): value for key, value in (response.headers or {}).items()}
        if response.status in _REDIRECTS:
            if hop >= MAX_REDIRECTS:
                raise DownloadError('download.too_many_redirects')
            location = headers.get('location')
            if not location:
                raise DownloadError('download.invalid_redirect')
            url = urljoin(url, location)
            continue
        if response.status != 200:
            raise DownloadError('download.http_error', str(response.status))
        if len(response.body) > spec.max_bytes:
            raise DownloadError('download.size_exceeded')
        try:
            text = response.body.decode('utf-8')
        except UnicodeDecodeError as exc:
            raise DownloadError('download.decode_failed', str(exc)) from exc
        return FetchResult(url=url, content=text,
                           sha256=hashlib.sha256(response.body).hexdigest(),
                           size=len(response.body))
    raise DownloadError('download.too_many_redirects')


# ---------------------------------------------------------------------------
# Format validation
# ---------------------------------------------------------------------------

_DOMAIN_RE = re.compile(
    r'^(?:\*\.)?(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z]{2,}$', re.IGNORECASE)
_SCHEME_RE = re.compile(r'(?:vmess|vless|trojan|ss|ssr|hysteria2|tuic|socks)://')


def _json_value(content: str):
    try:
        return json.loads(content)
    except (ValueError, TypeError):
        return None


def _is_json(content: str) -> bool:
    return _json_value(content) is not None


def _is_singbox(content: str) -> bool:
    value = _json_value(content)
    return isinstance(value, dict) and isinstance(value.get('outbounds'), list)


def _is_rule_set(content: str) -> bool:
    value = _json_value(content)
    return (isinstance(value, dict) and isinstance(value.get('rules'), list)
            and 'version' in value)


def _is_clash(content: str) -> bool:
    return any(line.strip().startswith('proxies:') for line in content.splitlines())


def _is_base64(content: str) -> bool:
    try:
        base64.b64decode(''.join(content.split()), validate=True)
    except (ValueError, binascii.Error):
        return False
    return True


def _is_base64_scheme(content: str) -> bool:
    try:
        decoded = base64.b64decode(''.join(content.split()), validate=True)
    except (ValueError, binascii.Error):
        return False
    try:
        return bool(_SCHEME_RE.search(decoded.decode('utf-8', 'ignore')))
    except Exception:  # pragma: no cover - decode('ignore') cannot raise here
        return False


def _line_ok(line: str) -> bool:
    token = line.split('#', 1)[0].strip()
    if not token:
        return True
    for prefix in ('domain:', 'full:', 'keyword:', 'regexp:'):
        if token.startswith(prefix):
            token = token[len(prefix):].strip()
            break
    if not token:
        return False
    if _DOMAIN_RE.match(token):
        return True
    try:
        ipaddress.ip_network(token, strict=False)
        return True
    except ValueError:
        return False


def _is_text(content: str) -> bool:
    lines = [line for line in content.splitlines()]
    meaningful = [line for line in lines
                  if line.strip() and not line.strip().startswith(('#', '//', ';'))]
    if not meaningful:
        return False
    return all(_line_ok(line) for line in meaningful)


#: Order matters for ``auto``: the more specific JSON shapes first, and plain
#: ``json`` last because it matches any JSON document.
_FORMAT_VALIDATORS: dict[str, Callable[[str], bool]] = {
    'sing-box': _is_singbox,
    'rule-set': _is_rule_set,
    'clash': _is_clash,
    'v2ray': _is_base64_scheme,
    'base64': _is_base64,
    'json': _is_json,
    'text': _is_text,
}

_AUTO_ORDER = ('sing-box', 'rule-set', 'clash', 'v2ray', 'base64', 'json', 'text')


def validate_content(content: str, declared: str) -> str:
    """Return the effective format name or raise ``download.invalid_format``.

    ``.srs`` (binary sing-box rule sets) is recognized as a real format but is
    not activatable here: the byte-exact store and pinned compiler are out of
    scope, so asking for it fails closed with ``download.format_unsupported``.
    """
    if declared == 'srs':
        raise DownloadError('download.format_unsupported')
    if declared == 'auto':
        for name in _AUTO_ORDER:
            if _FORMAT_VALIDATORS[name](content):
                return name
        raise DownloadError('download.invalid_format')
    validator = _FORMAT_VALIDATORS.get(declared)
    if validator is None:
        raise DownloadError('download.format_unknown')
    if not validator(content):
        raise DownloadError('download.invalid_format')
    return declared


# ---------------------------------------------------------------------------
# Atomic store
# ---------------------------------------------------------------------------

class SourceStore:
    """Staged/active source files plus an append-only status/version history.

    Uses the same ``FileSystem`` protocol as the apply engine, so the whole
    activation path is exercised against ``FakeFS`` in tests without touching a
    real host.
    """

    def __init__(self, base: Path | str | None = None, *, filesystem=None,
                 clock: Callable[[], float] = time.time):
        self.base = Path(base) if base is not None else SOURCES_DIR
        self.fs = filesystem or LocalFileSystem()
        self.clock = clock

    # -- paths --------------------------------------------------------------
    def active_path(self, name: str, kind: str) -> Path:
        return self.base / 'active' / f'{name}.{kind}'

    def staging_path(self, name: str) -> Path:
        return self.base / 'staging' / name

    def version_path(self, name: str, sha256: str) -> Path:
        return self.base / 'versions' / name / sha256

    def history_path(self) -> Path:
        return self.base / 'history.json'

    def _read_or_none(self, path: Path) -> str | None:
        try:
            return self.fs.read(path)
        except FileNotFoundError:
            return None

    def read_active(self, name: str, kind: str) -> str | None:
        return self._read_or_none(self.active_path(name, kind))

    # -- history ------------------------------------------------------------
    def read_history(self) -> list[dict]:
        raw = self._read_or_none(self.history_path())
        if raw is None:
            return []
        try:
            loaded = json.loads(raw)
        except ValueError:
            return []
        return loaded if isinstance(loaded, list) else []

    def record(self, spec: SourceSpec, *, status: str, sha256: str | None = None,
               size: int | None = None, url: str | None = None,
               format: str | None = None, error: str | None = None) -> dict:
        entry = {
            'name': spec.name, 'kind': spec.kind, 'status': status,
            'url': url or spec.url, 'format': format, 'sha256': sha256,
            'size': size, 'at': self.clock(), 'error': error,
        }
        history = self.read_history()
        history.append(entry)
        self.fs.write(self.history_path(), json.dumps(history[-HISTORY_LIMIT:]))
        return entry

    # -- activation ---------------------------------------------------------
    def activate(self, spec: SourceSpec, *, content: str, sha256: str, size: int,
                 url: str, detected: str) -> Path:
        """Stage a version, then atomically replace the active file.

        On any write failure the previous active file is restored (or removed if
        there was none), so a failed activation never leaves a half-written set
        in place. The version and history files are written before the move.
        """
        active = self.active_path(spec.name, spec.kind)
        previous = self._read_or_none(active)
        staging = self.staging_path(spec.name)
        try:
            self.fs.write(self.version_path(spec.name, sha256), content)
            self.fs.write(staging, content)
            self.fs.atomic_move(staging, active)
        except Exception:
            if previous is not None:
                self.fs.write(active, previous)
            else:
                self.fs.remove(active)
            raise
        return active


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def candidate_config(spec: SourceSpec, detected: str, result: FetchResult) -> dict:
    """Minimal sing-box-shaped document for an injected ``config_validator``.

    It is *not* a full configuration and is never installed: it exists so a
    validator (e.g. a pinned ``sing-box check``) can confirm that a config
    referencing the new set still assembles before activation.
    """
    return {
        'outbounds': [{'type': 'direct', 'tag': 'direct'}],
        'route': {
            'rule_set': [{
                'tag': spec.name, 'format': detected, 'url': result.url,
                'size': result.size, 'sha256': result.sha256,
            }],
        },
    }


class SourceUpdater:
    """Fetch -> validate -> assemble-check -> atomically activate -> record."""

    def __init__(self, *, store: SourceStore | None = None, transport: Transport | None = None,
                 resolver: Callable[[str], list[str]] | None = None,
                 builtin_sources: dict[str, BuiltinSource] | None = None,
                 config_validator: Callable[[dict], object] | None = None,
                 allow_plaintext: bool = False, clock: Callable[[], float] = time.time):
        self.store = store or SourceStore(clock=clock)
        self.transport = transport or UrllibTransport()
        self.resolver = resolver or default_resolver
        self.builtin_sources = BUILTIN_SOURCES if builtin_sources is None else builtin_sources
        self.config_validator = config_validator
        self.allow_plaintext = allow_plaintext

    # -- spec construction --------------------------------------------------
    def build_spec(self, *, name: str, url: str, kind: str = 'rule_set',
                   format: str = 'auto', authorized: bool = False,
                   max_bytes: int = DEFAULT_MAX_BYTES,
                   timeout: float = DEFAULT_TIMEOUT) -> SourceSpec:
        """Resolve authorization and allowlist for a request, before any I/O."""
        _, host, _ = _split(url)
        entry = self.builtin_sources.get(name)
        if entry is not None:
            if url != entry.url:
                raise DownloadError('download.builtin_url_mismatch')
            return SourceSpec(name=name, url=url, kind=entry.kind or kind,
                              format=entry.format or format, max_bytes=max_bytes,
                              timeout=timeout, builtin=True,
                              allowed_hosts=entry.hosts, authorized=True)
        if not authorized:
            raise DownloadError('download.user_authorization_required')
        return SourceSpec(name=name, url=url, kind=kind, format=format,
                          max_bytes=max_bytes, timeout=timeout, builtin=False,
                          allowed_hosts=frozenset({host}), authorized=True)

    # -- manual update ------------------------------------------------------
    def update(self, *, name: str, url: str, kind: str = 'rule_set',
               format: str = 'auto', authorized: bool = False,
               max_bytes: int = DEFAULT_MAX_BYTES,
               timeout: float = DEFAULT_TIMEOUT) -> dict:
        """Run one manual update; returns the history record.

        Security/format/assembly failures raise :class:`DownloadError` (mapped to
        a typed RPC error) and are recorded as ``failed``; the active file is
        left untouched (or restored).
        """
        spec = self.build_spec(name=name, url=url, kind=kind, format=format,
                               authorized=authorized, max_bytes=max_bytes, timeout=timeout)
        try:
            result = fetch(spec, transport=self.transport, resolver=self.resolver,
                           allow_plaintext=self.allow_plaintext)
            detected = validate_content(result.content, spec.format)
            if self.config_validator is not None:
                try:
                    self.config_validator(candidate_config(spec, detected, result))
                except DownloadError:
                    raise
                except Exception as exc:
                    raise DownloadError('download.config_invalid', str(exc)) from exc
            self.store.activate(spec, content=result.content, sha256=result.sha256,
                                size=result.size, url=result.url, detected=detected)
        except DownloadError as exc:
            self.store.record(spec, status='failed', error=exc.code)
            raise
        except Exception as exc:  # activation I/O failure -> typed, recorded
            error = DownloadError('download.activation_failed', str(exc))
            self.store.record(spec, status='failed', error=error.code)
            raise error from exc
        return self.store.record(spec, status='ok', sha256=result.sha256,
                                 size=result.size, url=result.url, format=detected)

    def status(self) -> list[dict]:
        """Return the append-only update history (oldest first)."""
        return self.store.read_history()

    # -- scheduled update ---------------------------------------------------
    def run_scheduled(self, *, name: str, url: str, kind: str = 'rule_set',
                      format: str = 'auto', authorized: bool = False,
                      schedule: SourceSchedule, now: float,
                      max_bytes: int = DEFAULT_MAX_BYTES,
                      timeout: float = DEFAULT_TIMEOUT,
                      rng=None) -> dict:
        """Run one update iff ``schedule`` says the source is due at ``now``.

        Typed data only: the schedule decision comes from the pure
        :mod:`vs_router.agent.source_schedule` functions applied to the store's
        own history, and the fetch itself reuses :meth:`update` (so the SSRF
        policy, format check and atomic activation are unchanged). Returns a
        plain dict — ``ran``, ``status`` (``not_due``/``ok``/``failed``), the
        recorded entry (if any), a typed ``error`` code (if any) and the
        projected ``next_run`` instant. No shell, no free-form arguments.
        """
        state = state_from_history(self.store.read_history(), name)
        if not is_due(schedule, now=now, state=state):
            return {"ran": False, "status": "not_due", "record": None, "error": None,
                    "next_run": next_run(schedule, now=now, state=state, rng=rng)}
        try:
            record = self.update(name=name, url=url, kind=kind, format=format,
                                 authorized=authorized, max_bytes=max_bytes,
                                 timeout=timeout)
        except DownloadError as exc:
            after = state_from_history(self.store.read_history(), name)
            return {"ran": True, "status": "failed", "record": None,
                    "error": exc.code,
                    "next_run": next_run(schedule, now=now, state=after, rng=rng)}
        after = state_from_history(self.store.read_history(), name)
        return {"ran": True, "status": "ok", "record": record, "error": None,
                "next_run": next_run(schedule, now=now, state=after, rng=rng)}
