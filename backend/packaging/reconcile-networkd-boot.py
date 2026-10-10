"""Remove stale vs-router networkd files after restoring the applied bundle.

Runs before networkd starts. A missing bundle means first boot: leave the
installer's temporary uplink configuration alone.
"""

from pathlib import Path
import re

from vs_router.generators.networkd import deserialize_networkd


OWNED = re.compile(r"10-vs-router-[a-zA-Z][a-zA-Z0-9_.-]{0,14}\.(?:network|netdev)\Z")


def reconcile(applied=Path('/etc/vs-router/applied/networkd.conf'),
              network_dir=Path('/etc/systemd/network')) -> None:
    if not applied.is_file():
        return
    expected = deserialize_networkd(applied.read_text())
    for path in network_dir.iterdir():
        if OWNED.fullmatch(path.name) and path.name not in expected:
            path.unlink()


if __name__ == '__main__':
    reconcile()
