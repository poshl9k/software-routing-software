"""Hourly source-update entry point. All mutations use the typed agent RPC."""
import os
import time
import logging

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from ..db import ConfigurationRow
from .daemon import SOCKET_PATH, UnixSocketTransport
from .rpc import AgentClient, AgentRPCError
from .source_schedule import SourceSchedule, is_due, state_from_history

log = logging.getLogger(__name__)


def confirmed_sources(database):
    """Read only the last confirmed snapshot; a draft never authorizes fetches."""
    with Session(database) as session:
        row = session.scalars(select(ConfigurationRow)
                              .where(ConfigurationRow.status == 'confirmed')
                              .order_by(ConfigurationRow.id.desc())).first()
        if row is None:
            return None, ()
        configuration = row.configuration
        return SourceSchedule.from_contract(configuration.tproxy.update_schedule,
                                            timezone=os.environ.get('TZ', 'UTC')), configuration.rule_sets


def run(client, schedule, sources, *, now):
    """Attempt each due source once; the agent rechecks apply state atomically."""
    marker = client.call('status')
    if marker and marker.get('status') not in ('confirmed', 'rolled_back'):
        return 0
    history = client.call('source_status') or []
    count = 0
    for source in sources:
        if not is_due(schedule, now=now, state=state_from_history(history, source.name)):
            continue
        try:
            client.call('update_source', {
                'name': source.name, 'url': source.url, 'kind': 'rule_set',
                'format': 'auto', 'authorized': True, 'scheduled': True,
                'max_bytes': source.max_bytes,
            })
        except AgentRPCError as exc:
            if exc.error.message == 'agent.apply_pending':
                break
            log.warning('source update failed for %s: %s', source.name, exc.error.message)
            continue
        count += 1
    return count


def main():
    logging.basicConfig(level=logging.INFO)
    database = create_engine(os.environ.get('VS_ROUTER_DATABASE_URL', 'sqlite:///vs-router.db'))
    schedule, sources = confirmed_sources(database)
    if schedule is None or not sources:
        return
    client = AgentClient(UnixSocketTransport(os.environ.get('VS_ROUTER_AGENT_SOCKET', SOCKET_PATH)))
    run(client, schedule, sources, now=time.time())


if __name__ == '__main__':
    main()
