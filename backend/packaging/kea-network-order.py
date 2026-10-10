"""Install Kea unit overrides without network-online DHCP waits.

Systemd dependency lists in vendor [Unit] cannot be reset by drop-ins. Copy
vendor units to /etc with only network-online.target removed; preserve all other
Debian service directives and unit-specific sandbox/capabilities.
"""
from pathlib import Path
import re

UNITS = ('kea-ctrl-agent', 'kea-dhcp4-server')


def install(source=Path('/usr/lib/systemd/system'), target=Path('/etc/systemd/system')):
    for name in UNITS:
        file = f'{name}.service'
        data = (source / file).read_text()
        if 'network-online.target' not in data:
            raise ValueError(f'{file}: expected network-online dependency missing')
        lines = []
        section = ''
        for line in data.splitlines():
            if line.startswith('['):
                section = line
            if section == '[Unit]' and re.match(r'^(After|Wants)=', line):
                key, _, value = line.partition('=')
                items = [item for item in value.split() if item != 'network-online.target']
                if key == 'After' and 'network-online.target' in value.split():
                    items.append('network.target')
                if items:
                    line = key + '=' + ' '.join(items)
                else:
                    continue
            lines.append(line)
        destination = target / file
        destination.write_text('\n'.join(lines) + '\n')
        destination.chmod(0o644)


if __name__ == '__main__':
    install()
