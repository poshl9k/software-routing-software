#!/usr/bin/env bash
set -euo pipefail

requirements=${1:?Usage: install-runtime-deps.sh <requirements-lock>}
[[ -f $requirements ]] || { printf 'Missing dependency lock: %s\n' "$requirements" >&2; exit 1; }

# Remove only prior pip-managed copies. Debian-owned packages often lack pip
# RECORD metadata, so asking pip to uninstall them can fail or damage dpkg state.
python3 - "$requirements" <<'PY'
from importlib import metadata
from pathlib import Path
import subprocess
import sys

requirements = Path(sys.argv[1])
names = []
for line in requirements.read_text().splitlines():
    if line and not line[0].isspace() and not line.startswith('#'):
        names.append(line.split('==', 1)[0])

pip_managed = []
for name in names:
    try:
        distribution = metadata.distribution(name)
    except metadata.PackageNotFoundError:
        continue
    installer = distribution.read_text('INSTALLER')
    if installer is not None and installer.strip().lower() == 'pip':
        pip_managed.append(distribution.metadata['Name'])

if pip_managed:
    subprocess.run([sys.executable, '-m', 'pip', 'uninstall', '--break-system-packages', '--yes', *pip_managed], check=True)
PY

python3 -m pip install --break-system-packages --ignore-installed --require-hashes -r "$requirements"
