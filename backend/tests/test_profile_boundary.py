"""Static, host-free checks for explicit backend module profile boundaries."""

import ast
from pathlib import Path

import pytest

from test_agent_apply import FakeExecutor, FakeFS, snapshot
from vs_router.agent import apply as apply_mod
from vs_router.agent.apply import APPLIED_DIR, FILES, PHASE_TOOLS, ApplyEngine, ApplyError, host_files
from vs_router.profiles import KNOWN_CROSS_PROFILE_EDGES, MODULE_PROFILES, module_profile


SOURCE = Path(__file__).parents[1] / 'src'
INVENTORY_PACKAGES = ('vs_router', 'vs_master')
POLICY_PACKAGES = ('vs_router', 'vs_master', 'vs_portal')
VALID_PROFILES = {'core', 'router', 'panel', 'master'}


def module_name(path, root):
    parts = path.relative_to(root).with_suffix('').parts
    if parts[-1] == '__init__':
        parts = parts[:-1]
    return '.'.join(parts)


def inspect_boundary(root, profiles, exceptions):
    """Check shared inventory and direct AST graph; return observed module edges."""
    inventory_roots = [root / package for package in INVENTORY_PACKAGES
                       if (root / package).is_dir()]
    sources = {module_name(path, root): path
               for inventory_root in inventory_roots
               for path in inventory_root.rglob('*.py')}
    inventory_profiles = {
        name: profile for name, profile in profiles.items()
        if any(name == package or name.startswith(package + '.')
               for package in INVENTORY_PACKAGES)
    }
    assert sources.keys() == inventory_profiles.keys(), (
        f'unclassified modules: {sorted(sources.keys() - inventory_profiles.keys())}; '
        f'stale profiles: {sorted(inventory_profiles.keys() - sources.keys())}')
    assert set(profiles.values()) <= VALID_PROFILES, 'invalid module profile'
    trees = {name: ast.parse(path.read_text(), filename=str(path)) for name, path in sources.items()}
    exports = {}
    for name, tree in trees.items():
        for node in tree.body:
            if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == '__all__'
                                                       for t in node.targets):
                try:
                    exports[name] = set(ast.literal_eval(node.value))
                except (ValueError, TypeError):
                    pass

    def base_name(source, node):
        if not node.level:
            return node.module or ''
        package = source if sources[source].name == '__init__.py' else source.rpartition('.')[0]
        parts = package.split('.')
        assert node.level <= len(parts), f'{source}: invalid relative import'
        return '.'.join(parts[:len(parts) - node.level + 1] +
                        ([node.module] if node.module else []))

    def imports(name):
        for node in ast.walk(trees[name]):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    yield alias.name, None
            elif isinstance(node, ast.ImportFrom):
                base = base_name(name, node)
                for alias in node.names:
                    yield base, alias.name

    def exported_names(package, seen=frozenset()):
        """Expand static star exports, including chained facades, without executing code."""
        if package not in sources or package in seen:
            return set()
        if package in exports:
            return exports[package]
        names = set()
        for node in trees[package].body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                names.add(node.name)
            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                names.update(child.id for target in targets for child in ast.walk(target)
                             if isinstance(child, ast.Name))
            elif isinstance(node, ast.Import):
                names.update(alias.asname or alias.name.split('.')[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    if alias.name == '*':
                        names |= exported_names(base_name(package, node), seen | {package})
                    else:
                        names.add(alias.asname or alias.name)
        return {name for name in names if not name.startswith('_')}

    def resolve_symbol(package, symbol, seen=frozenset()):
        """Follow named reexports, not arbitrary transitive module dependencies."""
        key = (package, symbol)
        if key in seen or package not in sources:
            return set()
        seen = seen | {key}
        targets = set()
        for node in trees[package].body:
            if isinstance(node, ast.Import):
                for alias in node.names:
                    bound = alias.asname or alias.name.split('.')[0]
                    target = alias.name if alias.asname else bound
                    if bound == symbol and target in sources:
                        targets.add(target)
                continue
            if not isinstance(node, ast.ImportFrom):
                continue
            base = base_name(package, node)
            for alias in node.names:
                if alias.name == '*':
                    if symbol in exported_names(base):
                        targets.add(base)
                        targets |= resolve_symbol(base, symbol, seen)
                    continue
                if (alias.asname or alias.name) != symbol:
                    continue
                target = f'{base}.{alias.name}'
                if target in sources:
                    targets.add(target)
                elif base in sources:
                    targets.add(base)
                    targets |= resolve_symbol(base, alias.name, seen)
        return targets

    edges = set()
    for source in sources:
        for base, symbol in imports(source):
            from_master = source == 'vs_master' or source.startswith('vs_master.')
            policy_packages = POLICY_PACKAGES if from_master else INVENTORY_PACKAGES
            if not any(base == package or base.startswith(package + '.')
                       for package in policy_packages):
                continue
            targets = {base} if base in profiles else set()
            if symbol is not None:
                candidate = f'{base}.{symbol}'
                if candidate in profiles:
                    targets.add(candidate)
                if base in sources:
                    if symbol == '*':
                        for exported in exported_names(base):
                            candidate = f'{base}.{exported}'
                            if candidate in profiles:
                                targets.add(candidate)
                            targets |= resolve_symbol(base, exported)
                    elif candidate not in profiles:
                        targets |= resolve_symbol(base, symbol)
            if (not targets and
                    any(base == package or base.startswith(package + '.')
                        for package in policy_packages)):
                raise AssertionError(f'{source}: unclassified import {base}')
            edges.update((source, target) for target in targets if source != target)

    for (source, target), reason in exceptions.items():
        assert source in sources and target in profiles, f'stale exception module: {source} -> {target}'
        assert isinstance(reason, str) and reason.strip(), f'blank exception reason: {source} -> {target}'
        assert profiles[source] != profiles[target], f'same-profile exception: {source} -> {target}'
        assert (source, target) in edges, f'stale exception edge: {source} -> {target}'
    for source, target in sorted(edges):
        cross_profile = profiles[source] != profiles[target]
        requires_exception = profiles[target] != 'core' or profiles[source] == 'master'
        if cross_profile and requires_exception:
            assert (source, target) in exceptions, f'cross-profile import: {source} -> {target}'
    return edges


def fixture_tree(tmp_path, files, profiles, exceptions=None):
    root = tmp_path / 'src'
    for name, content in files.items():
        path = root.joinpath(*name.split('.'))
        if content is None:
            path = path / '__init__.py'
            content = ''
        else:
            path = path.with_suffix('.py')
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    return inspect_boundary(root, profiles, exceptions or {})


def test_criterion_1_exact_inventory_and_missing_registration(tmp_path):
    files = {module_name(path, SOURCE)
             for package in INVENTORY_PACKAGES
             for path in (SOURCE / package).rglob('*.py')}
    inventory_profiles = {name for name in MODULE_PROFILES
                          if any(name == package or name.startswith(package + '.')
                                 for package in INVENTORY_PACKAGES)}
    assert files == inventory_profiles
    assert MODULE_PROFILES['vs_master'] == 'master'
    assert MODULE_PROFILES['vs_master.models'] == 'master'
    assert MODULE_PROFILES['vs_portal.models'] == 'panel'
    assert set(MODULE_PROFILES.values()) <= VALID_PROFILES
    for name in files:
        assert module_profile(name) == MODULE_PROFILES[name]
    with pytest.raises(KeyError):
        module_profile('vs_router.not_registered')
    with pytest.raises(AssertionError, match='unclassified modules'):
        fixture_tree(tmp_path, {'vs_router': None, 'vs_router.extra': ''},
                     {'vs_router': 'core'})


def test_criterion_2_real_boundary():
    inspect_boundary(SOURCE, MODULE_PROFILES, KNOWN_CROSS_PROFILE_EDGES)


def test_criterion_2_master_edges_and_router_import_forbidden(tmp_path):
    files = {
        'vs_master': None,
        'vs_master.models': ('from vs_portal.models import UTCDateTime\n'
                             'from vs_router.schema import EncryptedSecret\n'),
        'vs_router': None,
        'vs_router.schema': 'EncryptedSecret = str\n',
    }
    profiles = {
        'vs_master': 'master',
        'vs_master.models': 'master',
        'vs_portal.models': 'panel',
        'vs_router': 'core',
        'vs_router.schema': 'core',
    }
    exceptions = {
        ('vs_master.models', 'vs_portal.models'): 'portal helpers',
        ('vs_master.models', 'vs_router.schema'): 'shared secret type',
    }
    edges = fixture_tree(tmp_path / 'allowed', files, profiles, exceptions)
    assert ('vs_master.models', 'vs_portal.models') in edges
    assert ('vs_master.models', 'vs_router.schema') in edges

    forbidden_files = {**files, 'vs_router.consumer': 'import vs_master.models\n'}
    forbidden_profiles = {**profiles, 'vs_router.consumer': 'core'}
    with pytest.raises(AssertionError,
                       match=r'cross-profile import: vs_router\.consumer -> vs_master\.models'):
        fixture_tree(tmp_path / 'forbidden', forbidden_files, forbidden_profiles, exceptions)

    unclassified_files = {**files, 'vs_master.consumer': 'import vs_portal.missing\n'}
    unclassified_profiles = {**profiles, 'vs_master.consumer': 'master'}
    with pytest.raises(AssertionError, match='unclassified import vs_portal.missing'):
        fixture_tree(tmp_path / 'unclassified', unclassified_files,
                     unclassified_profiles, exceptions)


@pytest.mark.parametrize('form', [
    'import vs_router.feature.target',
    'import vs_router.feature.target as renamed',
    'from vs_router.feature import target',
    'from vs_router.feature.target import value',
    'from ..feature.target import value',
    'from ..feature import target as renamed',
    'def run():\n    from ..feature.target import value',
    'from vs_router.facade import value',
    'from vs_router.facade import renamed',
    'from vs_router.facade import *',
])
@pytest.mark.parametrize('owner,other', [('router', 'panel'), ('panel', 'router'),
                                         ('core', 'router'), ('core', 'panel')])
def test_criterion_2_import_forms(tmp_path, form, owner, other):
    files = {'vs_router': None, 'vs_router.feature': None,
             'vs_router.feature.target': 'value = 1',
             'vs_router.facade.__init__': 'from ..feature.target import value as renamed\n'
                                          'from ..feature.target import value\n'
                                          '__all__ = ["value", "renamed"]\n',
             'vs_router.owner': None, 'vs_router.owner.consumer': form}
    profiles = {'vs_router': 'core', 'vs_router.feature': other,
                'vs_router.feature.target': other, 'vs_router.facade': 'core',
                'vs_router.owner': owner, 'vs_router.owner.consumer': owner}
    with pytest.raises(AssertionError, match=r'cross-profile import: .* -> vs_router\.feature'):
        fixture_tree(tmp_path, files, profiles,
                     {('vs_router.facade', 'vs_router.feature.target'): 'synthetic facade'})


def test_criterion_2_chained_reexports_and_cycles(tmp_path):
    files = {'vs_router': None, 'vs_router.router': None,
             'vs_router.router.target': 'value = 1',
             'vs_router.facade': None,
             'vs_router.facade.first.__init__': 'from ...router.target import value as renamed\n'
                                                'from .. import second as cycle\n',
             'vs_router.facade.second.__init__': 'from ..first import renamed as value\n'
                                                 'from ..first import cycle\n',
             'vs_router.facade.consumer': 'from .second import value'}
    mapping = {name: ('router' if name.startswith('vs_router.router') else 'core')
               for name in files}
    mapping = {name.removesuffix('.__init__'): value for name, value in mapping.items()}
    exceptions = {('vs_router.facade.first', 'vs_router.router.target'): 'facade import'}
    with pytest.raises(AssertionError, match=r'vs_router\.facade\.consumer -> vs_router\.router\.target'):
        fixture_tree(tmp_path, files, mapping, exceptions)


@pytest.mark.parametrize('facade,consumer', [
    ('import vs_router.target as exposed', 'from .facade import exposed'),
    ('import vs_router.target as exposed', 'from .facade import *'),
    ('from ..target import *', 'from .facade import value'),
    ('from ..target import *', 'from .facade import *'),
    ('from ..target import *\n__all__ = ["value"]', 'from .facade import *'),
])
@pytest.mark.parametrize('package', [False, True])
def test_criterion_2_star_and_module_alias_reexports(tmp_path, facade, consumer, package):
    facade_name = 'vs_router.facade.__init__' if package else 'vs_router.facade'
    if not package:
        facade = facade.replace('from ..target', 'from .target')
    files = {'vs_router': None, 'vs_router.target': 'value = 1',
             facade_name: facade, 'vs_router.consumer': consumer}
    mapping = {'vs_router': 'core', 'vs_router.target': 'router',
               'vs_router.facade': 'core', 'vs_router.consumer': 'core'}
    with pytest.raises(AssertionError, match=r'vs_router\.consumer -> vs_router\.target'):
        fixture_tree(tmp_path, files, mapping,
                     {('vs_router.facade', 'vs_router.target'): 'existing facade coupling'})


def test_criterion_3_exceptions_are_exact_live_and_explained(tmp_path):
    edges = inspect_boundary(SOURCE, MODULE_PROFILES, KNOWN_CROSS_PROFILE_EDGES)
    for edge, reason in KNOWN_CROSS_PROFILE_EDGES.items():
        assert reason.strip() and edge in edges
        with pytest.raises(AssertionError, match='cross-profile import') as failure:
            inspect_boundary(SOURCE, MODULE_PROFILES,
                             {key: value for key, value in KNOWN_CROSS_PROFILE_EDGES.items() if key != edge})
        assert str(failure.value).startswith(f'cross-profile import: {edge[0]} -> {edge[1]}')
    with pytest.raises(AssertionError, match='stale exception edge'):
        inspect_boundary(SOURCE, MODULE_PROFILES,
                         {**KNOWN_CROSS_PROFILE_EDGES,
                          ('vs_router.schema', 'vs_router.generators.kea'): 'unrelated'})
    with pytest.raises(AssertionError, match='blank exception reason'):
        edge = next(iter(KNOWN_CROSS_PROFILE_EDGES))
        inspect_boundary(SOURCE, MODULE_PROFILES,
                         {**KNOWN_CROSS_PROFILE_EDGES, edge: '  '})
    with pytest.raises(AssertionError, match=r'vs_router\.second -> vs_router\.panel'):
        fixture_tree(tmp_path,
                     {'vs_router': None, 'vs_router.panel': 'value = 1',
                      'vs_router.first': 'from .panel import value',
                      'vs_router.second': 'from .panel import value'},
                     {'vs_router': 'core', 'vs_router.panel': 'panel',
                      'vs_router.first': 'router', 'vs_router.second': 'router'},
                     {('vs_router.first', 'vs_router.panel'): 'only first edge'})


def test_criterion_4_fixture_rejects_coupling_without_false_positives(tmp_path):
    files = {'vs_router': None, 'vs_router.consumer': 'from .panel import value',
             'vs_router.router': 'from .core import value',
             'vs_router.panel': 'value = 1',
             'vs_router.core': 'import requests\nfrom math import sqrt\nvalue = 1',
             'vs_router.ok': 'from .router import value'}
    mapping = {'vs_router': 'core', 'vs_router.consumer': 'core', 'vs_router.router': 'router',
               'vs_router.panel': 'panel', 'vs_router.core': 'core', 'vs_router.ok': 'router'}
    with pytest.raises(AssertionError, match=r'vs_router\.consumer -> vs_router\.panel'):
        fixture_tree(tmp_path, files, mapping)
    files['vs_router.consumer'] = 'from .core import value\nimport requests'
    edges = fixture_tree(tmp_path, files, mapping)
    assert ('vs_router.consumer', 'vs_router.core') in edges
    assert ('vs_router.router', 'vs_router.core') in edges
    assert ('vs_router.ok', 'vs_router.router') in edges
    assert all(target != 'requests' for _, target in edges)
    with pytest.raises(AssertionError, match='unclassified import vs_router'):
        fixture_tree(tmp_path, {**files, 'vs_router.consumer': 'import vs_router.missing'}, mapping)

    chain = {'vs_router': None, 'vs_router.router': 'from .panel import value',
             'vs_router.panel': 'value = 1', 'vs_router.core': 'from . import router\nvalue = 1',
             'vs_router.ok': 'from .core import value'}
    ownership = {'vs_router': 'core', 'vs_router.router': 'router',
                 'vs_router.panel': 'panel', 'vs_router.core': 'core', 'vs_router.ok': 'core'}
    observed = fixture_tree(tmp_path / 'chain', chain, ownership, {
        ('vs_router.router', 'vs_router.panel'): 'direct router import',
        ('vs_router.core', 'vs_router.router'): 'direct core import'})
    assert ('vs_router.ok', 'vs_router.router') not in observed
    assert ('vs_router.core', 'vs_router.panel') not in observed


@pytest.mark.parametrize('marker,dhcp,expected', [
    (None, False, 'confirmed'), (None, True, 'confirmed'),
    ('panel', False, 'confirmed'), ('panel', True, 'profile.capability_mismatch'),
    ('router', True, 'confirmed'), ('router', False, 'profile.capability_mismatch'),
])
def test_criterion_5_host_free_profile_apply_regression(monkeypatch, marker, dhcp, expected):
    monkeypatch.setattr(apply_mod, 'read_profile', lambda: marker)
    monkeypatch.setattr(apply_mod.shutil, 'which',
                        lambda name: '/usr/sbin/' + name if dhcp else None)
    files = host_files(which=apply_mod.shutil.which)
    assert set(files) == (set(FILES) if dhcp else set(FILES) - set(PHASE_TOOLS))
    fs, executor = FakeFS(), FakeExecutor()
    engine = ApplyEngine(filesystem=fs, executor=executor, files=files)
    document = dict(snapshot(), profile=marker or ('router' if dhcp else 'panel'))
    if expected == 'confirmed':
        result = engine.apply_version(document)
        assert result.status == expected
        assert set(result.phases) == set(files)
        assert (APPLIED_DIR / 'kea.json' in fs.files) is dhcp
    else:
        with pytest.raises(ApplyError) as failure:
            engine.apply_version(document)
        assert failure.value.code == expected
        assert fs.files == {} and executor.calls == []
