#!/usr/bin/env bash
set -euo pipefail

requirements=${1:?Usage: install-runtime-deps.sh <requirements-lock>}
[[ -f $requirements ]] || { printf 'Missing dependency lock: %s\n' "$requirements" >&2; exit 1; }

# The optional override is a single isolated site directory (for unprivileged
# tests). The normal install still uses the interpreter's standard locations.
if [[ -n ${VS_ROUTER_DEPS_SITE_DIRS:-} ]]; then
    [[ -d $VS_ROUTER_DEPS_SITE_DIRS ]] || { printf 'Missing dependency site: %s\n' "$VS_ROUTER_DEPS_SITE_DIRS" >&2; exit 1; }
    target=(--target "$VS_ROUTER_DEPS_SITE_DIRS")
else
    target=()
fi

# pip uninstall resolves only one dist-info per project. Enumerate every
# installed distribution instead, and remove only copies marked pip-managed.
python3 - "$requirements" "${VS_ROUTER_DEPS_SITE_DIRS:-}" <<'PY'
from importlib import metadata
from pathlib import Path
import csv
import io
import re
import shutil
import site
import sys


def normalized(name):
    return re.sub(r'[-_.]+', '-', name).lower()


names = set()
for line in Path(sys.argv[1]).read_text().splitlines():
    if line and not line[0].isspace() and not line.startswith('#'):
        names.add(normalized(line.split('==', 1)[0]))

if sys.argv[2]:
    locations = [Path(sys.argv[2])]
else:
    locations = [Path(path) for path in site.getsitepackages()]
    locations.append(Path(site.getusersitepackages()))
    locations.extend(Path(path) for path in sys.path
                     if path.endswith(('site-packages', 'dist-packages')))
locations = list(dict.fromkeys(path.resolve() for path in locations if path.is_dir()))

for location in locations:
    installed = list(metadata.distributions(path=[str(location)]))
    # Check ownership per distribution: a dpkg copy must not be removed even
    # when another version of the same project was installed with pip.
    pip_copies = [dist for dist in installed
                  if normalized(dist.metadata.get('Name', '')) in names
                  and (dist.read_text('INSTALLER') or '').strip().lower() == 'pip']
    protected = set()
    for dist in installed:
        if dist in pip_copies:
            continue
        if not dist.files:
            continue
        protected.update(Path(str(file)).parts[0] for file in dist.files
                         if Path(str(file)).parts and not str(file).startswith('..'))

    for dist in pip_copies:
        info = Path(dist._path)  # importlib.metadata's on-disk dist-info path
        if info.parent.resolve() != location or not info.name.endswith('.dist-info'):
            raise RuntimeError('Unsafe distribution metadata path')
        record = dist.read_text('RECORD')
        if record is None:
            raise RuntimeError('pip distribution without RECORD: ' + info.name)
        roots = set()
        for row in csv.reader(io.StringIO(record)):
            if not row:
                continue
            parts = Path(row[0]).parts
            if not parts or parts[0] in ('..', '.') or parts[0] == info.name:
                continue
            root = parts[0]
            if root in protected:
                # Shared with an unrelated or Debian-owned distribution: do
                # not remove its files. Such a collision needs manual repair.
                raise RuntimeError('Shared package root: ' + root)
            if len(parts) > 1 and not root.endswith(('.dist-info', '.data')):
                roots.add(root)
            elif len(parts) == 1 and root.endswith(('.py', '.so', '.pyd')):
                roots.add(root)
        for root in sorted(roots):
            path = location / root
            if path.is_dir() and not path.is_symlink():
                shutil.rmtree(path)
            elif path.exists() or path.is_symlink():
                path.unlink()
        shutil.rmtree(info)
PY

python3 -m pip install --break-system-packages --ignore-installed --require-hashes "${target[@]}" -r "$requirements"
