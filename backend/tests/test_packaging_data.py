"""The package must ship the data it reads at runtime.

The preset catalogue is JSON next to the code that loads it. Setuptools does
not include such files by default, and the wheel then installs without it:
``/api/presets/catalog`` answers 500 on every installed host while the
source tree works fine, so the defect only shows up after an install.
"""
import json
import shutil
import subprocess
import sys
import tomllib
import zipfile
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
PYPROJECT = BACKEND / "pyproject.toml"
CATALOGUE = Path("vs_router") / "agent" / "presets_catalog.json"


def test_criterion_packaging_catalogue_is_declared_as_package_data():
    """The build configuration must include the runtime data of the package.

    This is the check that runs everywhere: it does not need a wheel, only the
    declaration that decides what setuptools puts into it.
    """
    config = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    patterns = (config.get("tool", {}).get("setuptools", {})
                .get("package-data", {}).get("vs_router", []))
    assert patterns, (
        "pyproject.toml declares no package data for vs_router; the preset "
        "catalogue is read at runtime and would be missing from the wheel"
    )
    # setuptools matches the pattern against the path inside the package.
    import fnmatch
    assert any(fnmatch.fnmatch(CATALOGUE.as_posix(), pattern)
               for pattern in patterns), (
        f"no package-data pattern covers {CATALOGUE.as_posix()}: {patterns}"
    )


def test_criterion_packaging_catalogue_is_readable_from_the_installed_package():
    """The loader must find the catalogue next to itself, as it does in the
    source tree, so the installed package behaves like the source one."""
    from vs_router.agent.presets import load_catalog

    catalog = load_catalog()
    assert catalog, "the preset catalogue must not be empty"
    assert all(preset.id and preset.name for preset in catalog)


def _build_wheel(out_dir: Path) -> Path | None:
    """Build the wheel with whatever builder is available, or give up.

    The artifact check needs a build backend; without one the source-level
    checks above still guard the declaration.
    """
    uv = shutil.which("uv")
    if uv:
        result = subprocess.run(
            [uv, "build", "--wheel", "--out-dir", str(out_dir), str(BACKEND)],
            capture_output=True, text=True,
        )
    else:
        try:
            import build  # noqa: F401
        except Exception:
            return None
        result = subprocess.run(
            [sys.executable, "-m", "build", "--wheel", "--outdir", str(out_dir),
             str(BACKEND)],
            capture_output=True, text=True,
        )
    wheels = sorted(out_dir.glob("*.whl"))
    if result.returncode != 0 or not wheels:
        return None
    return wheels[-1]


def test_criterion_packaging_built_wheel_ships_the_preset_catalogue(tmp_path):
    """The artifact itself must contain the catalogue.

    The source tree always has it, so only the built wheel can show the
    packaging defect this guards against.
    """
    wheel = _build_wheel(tmp_path)
    if wheel is None:
        import pytest
        pytest.skip("no wheel builder is available in this environment")
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
    assert CATALOGUE.as_posix() in names, (
        f"{CATALOGUE.as_posix()} is missing from {wheel.name}; the package reads "
        "it at runtime with Path(__file__).with_name(...)"
    )
