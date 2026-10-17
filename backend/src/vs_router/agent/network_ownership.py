"""Who configures a link, other than this product (ADR-0027, ADR-0021).

The panel owns no host addressing, so on a panel the uplink pinned by the host
record must not get a ``.network`` file from us. The exclusion is only safe when
something else already configures that link: writing nothing for a link whose only
configuration is ours loses the address — at the next reboot, or silently earlier
when a DHCP lease expires and nobody renews it. That is the lockout ADR-0021
exists to prevent, so the check comes before the exclusion, not after it.

``foreign_owner`` is pure: it is given every candidate file as (path, content) and
reads nothing. ``host_config_candidates`` does the reading and stays thin.
"""
import re
from fnmatch import fnmatchcase
from pathlib import Path

#: Files this product writes. Never an owner of the link, however they match.
OURS = re.compile(r'10-vs-router-')

NETWORK_DIRS = (Path('/etc/systemd/network'), Path('/run/systemd/network'),
                Path('/usr/lib/systemd/network'))
NETPLAN_DIR = Path('/etc/netplan')
_SUFFIXES = ('.network', '.link', '.netdev', '.yaml', '.yml')


def foreign_owner(interface: str, candidates) -> bool:
    """True when a file that is not ours configures this interface.

    A netplan source names the link anywhere in the document; a networkd file
    names it in ``Name=``, where a wildcard counts because it would take the link
    over just the same.
    """
    for path, content in candidates:
        name = Path(path).name
        if OURS.match(name):
            continue
        if name.endswith(('.yaml', '.yml')):
            if re.search(rf'\b{re.escape(interface)}\b', content):
                return True
            continue
        for line in content.splitlines():
            stripped = line.strip()
            if stripped.startswith('Name='):
                # systemd matches with shell-style globs, so `en*` takes the link
                # over exactly as a literal name would.
                if any(fnmatchcase(interface, value)
                       for value in stripped.split('=', 1)[1].split()):
                    return True
    return False


def host_config_candidates(netplan_dir: Path = NETPLAN_DIR, dirs=NETWORK_DIRS):
    """Every host config file that could own a link, as (path, content).

    Unreadable files are skipped: this decides whether to leave a link alone, and
    a file we cannot read is not a reason to claim ownership of it.
    """
    for directory in (netplan_dir, *dirs):
        try:
            entries = sorted(directory.iterdir())
        except OSError:
            continue
        for entry in entries:
            if not entry.is_file() or entry.suffix not in _SUFFIXES:
                continue
            try:
                yield str(entry), entry.read_text(encoding='utf-8')
            except (OSError, UnicodeDecodeError):
                continue
