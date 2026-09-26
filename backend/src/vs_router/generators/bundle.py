"""Strict deterministic flat-file bundles shared by secret-bearing generators."""
import re


def serialize(files):
    result = ''.join(f'### FILE: {name}\n{content.rstrip(chr(10))}\n'
                     for name, content in sorted(files.items()))
    if deserialize(result) != {n: c.rstrip('\n') + '\n' for n, c in files.items()}:
        raise ValueError('bundle.invalid')
    return result


def deserialize(content):
    files, name = {}, None
    for line in content.splitlines(keepends=True):
        if line.startswith('### FILE: '):
            name = line[10:].rstrip('\n')
            if not re.fullmatch(r'[a-zA-Z][a-zA-Z0-9_.-]*', name) or name in files:
                raise ValueError('bundle.invalid')
            files[name] = ''
        elif name is None:
            raise ValueError('bundle.invalid')
        else:
            files[name] += line
    return files
