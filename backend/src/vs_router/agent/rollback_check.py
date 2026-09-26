"""Timer entry point; rollback runs in the serialized agent server."""
import os
import time
from .apply import ApplyEngine
from .daemon import SOCKET_PATH, UnixSocketTransport
from .rpc import AgentClient


def check_deadline(marker, rollback, clock=time.time):
    if (marker and marker.get('deadline') is not None
            and marker.get('status') not in ('confirmed', 'rolled_back')
            and clock() >= marker['deadline']):
        rollback('timeout')
        return True
    return False


def main():
    # The status RPC checks the deadline in the server, avoiding a stale read
    # racing a confirmation or a subsequent apply.
    client = AgentClient(UnixSocketTransport(os.environ.get('VS_ROUTER_AGENT_SOCKET', SOCKET_PATH)))
    check_deadline(ApplyEngine().status(), lambda reason: client.call('status'))


if __name__ == '__main__':
    main()
