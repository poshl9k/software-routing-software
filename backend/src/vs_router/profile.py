"""Installer-owned product identity; absence preserves legacy capability policy."""
import argparse
import os
from pathlib import Path
import sys
import tempfile

PROFILE_PATH = Path('/etc/vs-router/profile')
PROFILES = ('router', 'panel')
# Readable by the unprivileged web process: the product identity is not a secret
# (version.json publishes the same value) and the panel must stamp it on a new
# draft, which it cannot do by reading a root-only file.
PROFILE_MODE = 0o644


def read_profile(path=PROFILE_PATH) -> str | None:
    """Read a known marker, treating absent, unreadable or invalid data as unset."""
    try:
        profile = Path(path).read_text(encoding='utf-8').strip()
    except (OSError, ValueError):
        return None
    return profile if profile in PROFILES else None


def record_profile(profile: str, path=PROFILE_PATH) -> None:
    """Atomically replace the marker, never touching the host for an unknown value."""
    if profile not in PROFILES:
        raise ValueError('profile.unknown')
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(dir=path.parent)
    try:
        os.fchmod(fd, PROFILE_MODE)
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            stream.write(profile + '\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
        directory = os.open(path.parent, os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        Path(name).unlink(missing_ok=True)


def capability_conflict(profile: str | None, dhcp: bool) -> str | None:
    """A declared product must match its host's DHCP engine capability."""
    if (profile == 'panel' and dhcp) or (profile == 'router' and not dhcp):
        return 'profile.capability_mismatch'
    return None


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description='Профиль продукта на хосте')
    parser.add_argument('--path', type=Path, default=PROFILE_PATH,
                        help='путь к маркеру профиля')
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('show', help='показать профиль или unset')
    write = commands.add_parser('write', help='записать профиль атомарно')
    write.add_argument('profile', choices=PROFILES)
    args = parser.parse_args(argv)
    if args.command == 'show':
        print(read_profile(args.path) or 'unset')
        return 0
    try:
        record_profile(args.profile, args.path)
    except (OSError, ValueError) as error:
        print(f'Не удалось записать профиль: {error}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
