"""One-shot migration of a node's local portal database into the master (ADR-0035 D5).

Run during node onboarding: the node's portal process is still readable, but the
master is about to become the single source of truth. The script:

- maps every portal ``Tariff`` onto the master (matched by name, created when new);
- creates one master ``Account`` per portal ``Account``; the Telegram ID is the
  master identity, but the portal schema does not carry a usable one — a
  stable placeholder ``pending:<subscriber_name>`` is stored and the bot
  binding (stage 2) replaces it on the subscriber's first ``/start``;
- carries every subscription, preserving status and ``expires_at``;
- re-attaches every device to the target node (``node_id``) and records the
  node-local subscriber name (``node_subscriber``) the node bridge addresses
  operations by;
- re-encrypts device key material: the node DB holds secrets under the NODE's
  ``VS_ROUTER_SECRET_KEY``, the master stores them under its own.

The script is idempotent: a subscriber whose placeholder identity already
exists on the master is updated in place instead of duplicated, and devices are
matched by (account, node, name). DeviceOp rows are NOT migrated — drain the
node's pending operations before migrating. Peers in the node's applied router
configuration are untouched; the master learns them through the bridge.
"""
from sqlalchemy import select
from sqlalchemy.orm import Session

from vs_master.models import Account, Device, Subscription, Tariff
from vs_portal.models import Account as PortalAccount
from vs_portal.models import Device as PortalDevice
from vs_portal.models import Subscription as PortalSubscription
from vs_portal.models import Tariff as PortalTariff
from vs_router.secrets import decrypt_secret, encrypt_secret


def placeholder_identity(subscriber_name):
    return f'pending:{subscriber_name}'


def _portal_identity(src, subscriber_name):
    portal = src.get(PortalAccount, subscriber_name)
    return portal.telegram_chat_id if portal and portal.telegram_chat_id else placeholder_identity(subscriber_name)


def migrate_portal_db(portal_engine, master_engine, node, node_key, master_key):
    """Copy portal rows into the master; returns per-kind counters."""
    created = {'accounts': 0, 'tariffs': 0, 'subscriptions': 0, 'devices': 0, 'updated': 0}
    with Session(portal_engine) as src, Session(master_engine, expire_on_commit=False) as dst:
        for portal in src.scalars(select(PortalTariff).order_by(PortalTariff.id)):
            tariff = dst.scalar(select(Tariff).where(Tariff.name == portal.name))
            if tariff is None:
                dst.add(Tariff(name=portal.name, device_limit=portal.device_limit,
                               term_days=portal.term_days, price_amount=portal.price_amount))
                created['tariffs'] += 1
        dst.flush()
        tariffs = {t.name: t for t in dst.scalars(select(Tariff))}
        for portal in src.scalars(select(PortalAccount).order_by(PortalAccount.subscriber_name)):
            identity = portal.telegram_chat_id or placeholder_identity(portal.subscriber_name)
            account = dst.scalar(select(Account).where(Account.telegram_chat_id == identity))
            if account is None:
                account = Account(display_name=portal.subscriber_name, telegram_chat_id=identity,
                                  password_hash=portal.password_hash, status=portal.status)
                dst.add(account)
                dst.flush()
                created['accounts'] += 1
            else:
                account.display_name = portal.subscriber_name
                created['updated'] += 1
            subscription = src.get(PortalSubscription, portal.subscriber_name)
            if subscription is not None:
                tariff_name = _tariff_name(src, subscription.tariff_id)
                if tariff_name not in tariffs:
                    continue
                existing = dst.scalar(select(Subscription).where(Subscription.account_id == account.id))
                if existing is None:
                    dst.add(Subscription(account_id=account.id,
                                         tariff_id=tariffs[tariff_name].id,
                                         expires_at=subscription.expires_at, status=subscription.status))
                    created['subscriptions'] += 1
                else:
                    existing.tariff_id = tariffs[tariff_name].id
                    existing.expires_at = subscription.expires_at
                    existing.status = subscription.status
        dst.flush()
        for portal in src.scalars(select(PortalDevice).where(PortalDevice.status != 'removed')
                                  .order_by(PortalDevice.id)):
            identity = _portal_identity(src, portal.subscriber_name)
            account = dst.scalar(select(Account).where(Account.telegram_chat_id == identity))
            if account is None:
                continue
            device = dst.scalar(select(Device).where(
                Device.account_id == account.id, Device.node_id == node.id,
                Device.name == portal.name))
            material = {}
            for field in ('private_key', 'preshared_key'):
                value = getattr(portal, field)
                if value is not None:
                    try:
                        material[field] = encrypt_secret(decrypt_secret(value, node_key), master_key)
                    except Exception:
                        material[field] = None
            if device is None:
                dst.add(Device(account_id=account.id, node_id=node.id,
                               node_subscriber=portal.subscriber_name,
                               name=portal.name, label=portal.label,
                               public_key=portal.public_key,
                               private_key=material.get('private_key'),
                               preshared_key=material.get('preshared_key'),
                               allowed_ips=list(portal.allowed_ips or []),
                               status=portal.status, tunnel_name=portal.tunnel_name))
                created['devices'] += 1
            else:
                device.label = portal.label
                device.public_key = portal.public_key
                device.private_key = material.get('private_key')
                device.preshared_key = material.get('preshared_key')
                device.allowed_ips = list(portal.allowed_ips or [])
                device.status = portal.status
                device.tunnel_name = portal.tunnel_name
        dst.commit()
    return created


def _tariff_name(src, tariff_id):
    portal = src.get(PortalTariff, tariff_id)
    return portal.name if portal else None
