"""Subscription fetch boundary and pure stable-tag diff. No store/scheduler/logging."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable
from urllib.parse import urldefrag, urlsplit

from ..schema import ProxySubscription
from . import downloader
from .subscription_parse import Member, Parsed, SubscriptionParseError, parse_body


@dataclass(frozen=True)
class Diff:
    added: tuple[Member, ...]
    updated: tuple[Member, ...]
    unchanged: tuple[Member, ...]
    orphans: tuple[Member, ...]


def refresh(current: Parsed, fetched: Parsed) -> Diff:
    """Compare by stable tag; orphan entries remain for caller to preserve."""
    old = {m.tag: m for m in current.members}
    new = {m.tag: m for m in fetched.members}
    def visible(m: Member):
        # Fernet ciphertext is randomized: comparing ciphertext gives false updates.
        return (m.label, m.protocol, m.server, m.port, m.sni, m.transport,
                m.security, m.method, m.tls_insecure)
    return Diff(tuple(m for tag, m in new.items() if tag not in old),
                tuple(m for tag, m in new.items() if tag in old and visible(m) != visible(old[tag])),
                tuple(m for tag, m in new.items() if tag in old and visible(m) == visible(old[tag])),
                tuple(m for tag, m in old.items() if tag not in new))


def fetch(subscription: ProxySubscription, *, key: bytes, authorized: bool = False,
          downloader_fetch: Callable = downloader.fetch, transport: downloader.Transport | None = None,
          resolver: Callable[[str], list[str]] | None = None,
          bootstrap_resolver: Callable[[str], list[str]] | None = None) -> Parsed:
    """Caller must authorize URL from confirmed config. Inject safe downloader.fetch.

    Headers are NOT forwarded: existing pinned HTTPS transport has no custom
    header interface. Explicitly reject rather than silently ignore them.
    """
    if subscription.inline:
        return parse_body(subscription.inline_content or '', key=key)
    if subscription.headers:
        raise SubscriptionParseError('subscription.headers_unsupported')
    try:
        parsed_url = urlsplit(subscription.url)
    except ValueError as exc:
        raise downloader.DownloadError('download.invalid_url') from exc
    # A fragment is a client-side label (e.g. ``.../singbox/?asn=x#Mike``) and is
    # never sent to the server; drop it instead of rejecting the whole URL. Embedded
    # credentials are still refused.
    if parsed_url.username is not None or parsed_url.password is not None:
        raise downloader.DownloadError('download.invalid_url')
    url = urldefrag(subscription.url).url
    if not authorized:
        raise downloader.DownloadError('download.user_authorization_required')
    builder = downloader.SourceUpdater()
    spec = builder.build_spec(name=subscription.name, url=url,
                              kind='subscription', format=subscription.format,
                              authorized=True, max_bytes=downloader.DEFAULT_MAX_BYTES,
                              timeout=downloader.DEFAULT_TIMEOUT)
    options = {'transport': transport or downloader.UrllibTransport(),
               'resolver': resolver or downloader.default_resolver}
    if bootstrap_resolver is not None or downloader_fetch is downloader.fetch:
        options['bootstrap_resolver'] = (bootstrap_resolver if bootstrap_resolver is not None
                                         else downloader.bootstrap_dns.resolve if resolver is None else None)
    result = downloader_fetch(spec, **options)
    if result.not_modified:
        raise SubscriptionParseError('subscription.not_modified_requires_previous')
    return parse_body(result.content, key=key)


def preview(subscription: ProxySubscription, *, key: bytes, authorized: bool = False,
            downloader_fetch: Callable = downloader.fetch,
            transport: downloader.Transport | None = None,
            resolver: Callable[[str], list[str]] | None = None,
            bootstrap_resolver: Callable[[str], list[str]] | None = None) -> tuple[Parsed, list, list]:
    """Thin orchestrator; caller persists returned members/outbounds/groups."""
    from .subscription_parse import materialize
    parsed = fetch(subscription, key=key, authorized=authorized,
                   downloader_fetch=downloader_fetch, transport=transport, resolver=resolver,
                   bootstrap_resolver=bootstrap_resolver)
    outbounds, groups = materialize(subscription, parsed.members)
    return parsed, outbounds, groups
