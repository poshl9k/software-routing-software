"""Exercise the real master builder against pinned, dirty disposable git trees.

Only uv/npm are stand-ins: they turn their actual cwd's inputs into inspectable
wheel/UI payloads. Git, archive creation and checksum generation are real.
Upload tests redirect Git to a local bare repo and replace gh; no network release
or installer is executed, and no project dependencies are needed.
"""
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import zipfile

import pytest


MAKER = Path(__file__).resolve().parents[1] / "packaging/make-master-release.sh"
UPSTREAM = "https://github.com/poshl9k/software-routing-software.git"
UNITS = (
    "vs-master-web.service",
    "vs-master-worker.service",
    "vs-master-bot.service",
    "vs-master-backup.service",
    "vs-master-backup.timer",
    "install-master.sh",
    "caddy-master.conf",
)
# These exact committed inputs must reach the bundle, including build metadata.
INPUTS = (
    "backend/src/vs_master/__init__.py",
    "backend/src/vs_master/payload.py",
    "backend/requirements-runtime.txt",
    "backend/alembic-master/alembic.ini",
    "backend/alembic-master/env.py",
    "backend/alembic-master/versions/0001_initial.py",
    *(f"backend/packaging/{name}" for name in UNITS),
    "frontend-master/src/main.tsx",
    "frontend-master/index.html",
    "frontend-master/vite.config.ts",
    "frontend-master/package.json",
    "frontend-master/package-lock.json",
)
FAKE_TOOLS = r'''
import json, os, pathlib, sys, tomllib, zipfile
kind, *args = sys.argv[1:]
cwd = pathlib.Path.cwd()
with open(os.environ["TOOL_CALLS"], "a", encoding="utf-8") as log:
    log.write(json.dumps({"tool": kind, "args": args, "cwd": str(cwd)}) + "\n")
if kind == "uv":
    assert args[:2] == ["build", "--wheel"], args
    dest = pathlib.Path(args[args.index("--out-dir") + 1])
    dest.mkdir(parents=True, exist_ok=True)
    version = tomllib.loads((cwd / "pyproject.toml").read_text())["project"]["version"]
    with zipfile.ZipFile(dest / f"vs_router_backend-{version}-py3-none-any.whl", "w") as wheel:
        for source in sorted((cwd / "src").rglob("*.py")):
            wheel.write(source, source.relative_to(cwd / "src").as_posix())
    (cwd / ".build-touched").write_text("wheel build")
elif kind == "npm":
    if args == ["ci"]:
        assert (cwd / "package-lock.json").is_file()
        (cwd / "node_modules").mkdir()
        (cwd / "node_modules/installed").write_text("locked install")
    else:
        assert args == ["run", "build", "--silent"], args
        dest = pathlib.Path(os.environ["VS_MASTER_STATIC_DIR"])
        dest.mkdir(parents=True, exist_ok=True)
        inputs = {p.relative_to(cwd).as_posix(): p.read_text()
                  for p in sorted(cwd.rglob("*")) if p.is_file()
                  and "node_modules" not in p.parts and "dist" not in p.parts}
        (dest / "index.html").write_text(json.dumps(inputs, sort_keys=True))
        (dest / "assets").mkdir()
        (dest / "assets/app.js").write_bytes((cwd / "src/main.tsx").read_bytes())
        (cwd / ".build-touched").write_text("UI build")
else:
    sys.exit("network/upload tools must never be called")
'''


def run_git(repo, *args):
    return subprocess.check_output(
        ["git", "-C", str(repo), *args], text=True, stderr=subprocess.PIPE
    ).strip()


def bash_path(path):
    """Use MSYS paths for shell tools, not tar's remote-host C: syntax."""
    path = Path(path)
    if os.name == "nt":
        return "/" + path.drive[0].lower() + path.as_posix()[2:]
    return str(path)


def snapshot(repo):
    return {p.relative_to(repo).as_posix(): p.read_bytes()
            for p in repo.rglob("*") if p.is_file() and ".git" not in p.parts}


def make_test_upstream(repo, *, publish=False):
    """Redirect only the canonical Git URL to a disposable local bare repo."""
    remote = repo.parent / "upstream.git"
    subprocess.run(["git", "init", "--bare", str(remote)], check=True, capture_output=True)
    run_git(repo, "config", f"url.{remote.as_uri()}.insteadOf", UPSTREAM)
    if publish:
        run_git(repo, "push", str(remote), "HEAD:refs/heads/main")
    return remote


@pytest.fixture
def release_rig(tmp_path):
    for tool in ("bash", "git", "tar", "sha256sum"):
        if shutil.which(tool) is None:
            pytest.skip(f"{tool} is required for host-free builder tests")
    repo = tmp_path / "repo with spaces"
    repo.mkdir()
    run_git(repo, "init", "-q")
    run_git(repo, "config", "user.email", "release-test@example.invalid")
    run_git(repo, "config", "user.name", "Release test")
    run_git(repo, "config", "core.autocrlf", "false")
    run_git(repo, "config", "commit.gpgsign", "false")

    def write_version(marker, version):
        for name in INPUTS:
            path = repo / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f"{marker}: {name}\n", encoding="utf-8", newline="\n")
        (repo / "backend/pyproject.toml").write_text(
            f'[project]\nname = "vs-router-backend"\nversion = "{version}"\n',
            encoding="utf-8", newline="\n",
        )

    write_version("committed A", "1.2.3")
    builder = repo / "backend/packaging/make-master-release.sh"
    builder.write_text(MAKER.read_text(encoding="utf-8"), encoding="utf-8", newline="\n")
    run_git(repo, "add", ".")
    run_git(repo, "commit", "-qm", "version A")
    commit_a = run_git(repo, "rev-parse", "HEAD")
    expected = snapshot(repo)

    # The tools live outside the repo: git archive must not need untracked tools.
    bin_dir = tmp_path / "tools"
    bin_dir.mkdir()
    driver = bin_dir / "build_tools.py"
    driver.write_text(FAKE_TOOLS, encoding="utf-8", newline="\n")
    for kind in ("uv", "npm", "gh", "curl", "wget"):
        wrapper = bin_dir / kind
        wrapper.write_text(
            '#!/usr/bin/env bash\n'
            'if [[ ${OS:-} == Windows_NT && -n ${VS_MASTER_STATIC_DIR:-} ]]; then\n'
            '  export VS_MASTER_STATIC_DIR=$(cygpath -m "$VS_MASTER_STATIC_DIR")\n'
            'fi\nexec "$REAL_PYTHON" "$FAKE_TOOLS" '
            + kind + ' "$@"\n', encoding="utf-8", newline="\n",
        )
        wrapper.chmod(0o755)
    python_wrapper = bin_dir / "python3"
    python_wrapper.write_text(
        '#!/usr/bin/env bash\nexec "$REAL_PYTHON" "$@"\n',
        encoding="utf-8", newline="\n",
    )
    python_wrapper.chmod(0o755)
    calls = tmp_path / "calls.jsonl"
    gh_calls = tmp_path / "gh.calls"
    gh = bin_dir / "gh"
    gh.write_text(
        '#!/usr/bin/env bash\n'
        'printf "%s\\n" "$*" >> "$GH_CALLS"\n'
        'if [[ $1 == release && $2 == view ]]; then exit "${GH_VIEW_STATUS:-1}"; fi\n'
        'if [[ $1 == release && $2 == create ]]; then exit "${GH_CREATE_STATUS:-0}"; fi\n'
        'exit 99\n', encoding="utf-8", newline="\n",
    )
    gh.chmod(0o755)
    out = tmp_path / "artifacts"
    work = tmp_path / "scratch"
    work.mkdir()
    env = {**os.environ, "PATH": str(bin_dir) + os.pathsep + os.environ["PATH"],
           "TOOL_CALLS": calls.as_posix(), "REAL_PYTHON": Path(sys.executable).as_posix(),
           "FAKE_TOOLS": driver.as_posix(), "VS_MASTER_RELEASE_OUT": bash_path(out),
           "GH_CALLS": bash_path(gh_calls),
           "TMPDIR": bash_path(work), "TMP": work.as_posix(), "TEMP": work.as_posix()}
    # Permit Git Bash to translate staged POSIX paths for native git/Python.
    for key in ("BASH_ENV", "ENV", "PYTHONPATH", "MSYS_NO_PATHCONV", "MSYS2_ARG_CONV_EXCL"):
        env.pop(key, None)

    def dirty():
        write_version("dirty B", "9.9.9")
        for name in ("backend/src/vs_master/untracked.py",
                     "backend/alembic-master/versions/9999_untracked.py",
                     "frontend-master/src/untracked.tsx",
                     "frontend-master/dist/index.html"):
            path = repo / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("untracked B\n", encoding="utf-8")

    bash = shutil.which("bash")
    assert bash is not None

    def run(*args):
        return subprocess.run([bash, builder.as_posix(), *args], cwd=repo, env=env,
                              capture_output=True, text=True, timeout=60)

    def events():
        return [json.loads(line) for line in calls.read_text().splitlines()] if calls.exists() else []

    return repo, commit_a, expected, out, work, dirty, run, events, gh_calls, env


@pytest.mark.parametrize("selection", ["default", "explicit", "older-than-head"])
def test_master_release_uses_only_selected_commit(release_rig, selection):
    repo, commit_a, expected, out, work, dirty, run, events, _, _ = release_rig
    if selection == "older-than-head":
        dirty()
        run_git(repo, "add", ".")
        run_git(repo, "commit", "-qm", "different HEAD B")
        assert run_git(repo, "rev-parse", "HEAD") != commit_a
    dirty()
    before = snapshot(repo)
    result = run(*([] if selection == "default" else [commit_a]))
    assert result.returncode == 0, result.stdout + result.stderr

    archive = out / f"vs-master-{commit_a}.tar.gz"
    with tarfile.open(archive) as bundle:
        prefix = f"vs-master-{commit_a}/"
        contents = {}
        for member in bundle.getmembers():
            if member.isfile():
                stream = bundle.extractfile(member)
                assert stream is not None
                contents[member.name.removeprefix(prefix)] = stream.read()
    wheel_names = [name for name in contents if name.endswith(".whl")]
    assert wheel_names == ["vs_router_backend-1.2.3-py3-none-any.whl"]
    with zipfile.ZipFile(io.BytesIO(contents[wheel_names[0]])) as wheel:
        payload = {name: wheel.read(name) for name in wheel.namelist()}
    assert payload == {name.removeprefix("backend/src/"): content
                       for name, content in expected.items() if name.startswith("backend/src/")}
    for source, content in expected.items():
        if source.startswith("backend/alembic-master/"):
            assert contents[source.removeprefix("backend/")] == content
    assert not any("untracked" in name for name in contents)
    assert contents["requirements-runtime.txt"] == expected["backend/requirements-runtime.txt"]
    for name in UNITS:
        assert contents[name] == expected[f"backend/packaging/{name}"]
    ui = json.loads(contents["ui/index.html"])
    assert ui == {name.removeprefix("frontend-master/"): data.decode()
                  for name, data in expected.items() if name.startswith("frontend-master/")}
    assert contents["ui/assets/app.js"] == expected["frontend-master/src/main.tsx"]

    manifest = json.loads((out / "release-master.json").read_text())
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    assert manifest == {
        "commit": commit_a, "semver": "1.2.3", "kind": "vs-master",
        "source_url": "https://github.com/poshl9k/software-routing-software/releases/download/"
                      f"vs-master-1.2.3/vs-master-{commit_a}.tar.gz",
        "source_sha256": digest,
    }
    entry = (out / "get-master.sh").read_text()
    assert f"VSM_COMMIT='{commit_a}'" in entry
    assert f"VSM_SHA='{digest}'" in entry
    assert "releases/download/vs-master-1.2.3'" in entry
    assert snapshot(repo) == before, "build tools must never mutate the source checkout"
    assert not list(work.iterdir()), "staging must be cleaned on success"
    log = events()
    assert [(e["tool"], e["args"]) for e in log if e["tool"] == "npm"] == [
        ("npm", ["ci"]), ("npm", ["run", "build", "--silent"]),
    ]
    assert all(not Path(e["cwd"]).is_relative_to(repo) for e in log)
    assert {e["tool"] for e in log} == {"uv", "npm"}


def test_upload_requires_commit_published_on_canonical_main(release_rig):
    repo, commit_a, _, _, _, _, run, events, gh_calls, env = release_rig
    make_test_upstream(repo)
    result = run("--upload", commit_a)
    assert result.returncode != 0
    assert "canonical main" in result.stderr
    assert not gh_calls.exists()


def test_upload_rejects_semver_collision_before_gh_create(release_rig):
    repo, commit_a, _, _, _, _, run, events, gh_calls, env = release_rig
    make_test_upstream(repo, publish=True)
    run_git(repo, "tag", "vs-master-1.2.3", commit_a)
    remote = repo.parent / "upstream.git"
    run_git(repo, "push", str(remote), "refs/tags/vs-master-1.2.3")
    result = run("--upload", commit_a)
    assert result.returncode != 0
    calls = gh_calls.read_text().splitlines() if gh_calls.exists() else []
    assert not any(line.startswith("release create ") or line.startswith("release upload ") for line in calls)


def test_upload_creates_all_assets_atomically_with_explicit_target(release_rig):
    repo, commit_a, _, _, _, _, run, events, gh_calls, env = release_rig
    make_test_upstream(repo, publish=True)
    result = run("--upload", commit_a)
    assert result.returncode == 0, result.stdout + result.stderr
    creates = [line for line in gh_calls.read_text().splitlines() if line.startswith("release create ")]
    assert len(creates) == 1
    args = creates[0].split()
    assert "--target" in args and args[args.index("--target") + 1] == commit_a
    assert {"--clobber"}.isdisjoint(args)
    assert all(name in creates[0] for name in (f"vs-master-{commit_a}.tar.gz", "release-master.json", "get-master.sh"))


@pytest.mark.parametrize("failure", ["create-fails", "unpublished"])
def test_upload_never_uploads_after_preflight_or_create_failure(release_rig, failure):
    repo, commit_a, _, _, _, _, run, events, gh_calls, env = release_rig
    make_test_upstream(repo, publish=failure == "create-fails")
    if failure == "create-fails":
        env["GH_CREATE_STATUS"] = "17"
    result = run("--upload", commit_a)
    assert result.returncode != 0
    calls = gh_calls.read_text().splitlines() if gh_calls.exists() else []
    assert not any(line.startswith("release upload ") for line in calls)
    if failure == "unpublished":
        assert not any(line.startswith("release create ") for line in calls)


def test_upload_rejects_noncanonical_origin_even_if_it_contains_commit(release_rig):
    repo, commit_a, _, _, _, _, run, _, gh_calls, _ = release_rig
    make_test_upstream(repo)
    fork = repo.parent / "fork.git"
    subprocess.run(["git", "init", "--bare", str(fork)], check=True, capture_output=True)
    run_git(repo, "remote", "add", "origin", str(fork))
    run_git(repo, "push", "origin", "HEAD:refs/heads/main")
    result = run("--upload", commit_a)
    assert result.returncode != 0
    assert "canonical main" in result.stderr
    assert not gh_calls.exists()


def test_upload_fails_closed_when_tag_lookup_transport_fails(release_rig):
    repo, commit_a, _, _, _, _, run, _, gh_calls, env = release_rig
    make_test_upstream(repo, publish=True)
    fake_git = repo.parent / "tools/git"
    env["REAL_GIT"] = shutil.which("git")
    fake_git.write_text(
        '#!/usr/bin/env bash\n'
        'if [[ " $* " == *" ls-remote --tags "* ]]; then exit 128; fi\n'
        'exec "$REAL_GIT" "$@"\n', encoding="utf-8", newline="\n",
    )
    fake_git.chmod(0o755)
    result = run("--upload", commit_a)
    assert result.returncode != 0
    assert "remote tag" in result.stderr
    assert not gh_calls.exists()


@pytest.mark.parametrize("invalid", ["", "HEAD", "a" * 39, "g" * 40, "0" * 40,
                                     "blob", "tree", "tag-object", "multiple", "missing-head"])
def test_master_release_rejects_invalid_commit_before_build(release_rig, invalid):
    repo, commit_a, _, out, work, dirty, run, events, _, _ = release_rig
    dirty()
    if invalid == "blob":
        invalid = run_git(repo, "rev-parse", f"{commit_a}:backend/pyproject.toml")
    elif invalid == "tree":
        invalid = run_git(repo, "rev-parse", f"{commit_a}^{{tree}}")
    elif invalid == "tag-object":
        run_git(repo, "-c", "tag.gpgsign=false", "tag", "-am", "fixture tag", "fixture", commit_a)
        invalid = run_git(repo, "rev-parse", "refs/tags/fixture")
    if invalid == "missing-head":
        run_git(repo, "symbolic-ref", "HEAD", "refs/heads/unborn")
        args = []
    else:
        args = [commit_a, commit_a] if invalid == "multiple" else [invalid]
    before = snapshot(repo)
    result = run(*args)
    assert result.returncode != 0, result.stdout + result.stderr
    assert "commit" in result.stderr.lower(), result.stderr
    assert not events(), "invalid commit must be rejected before uv/npm/network tools"
    assert not out.exists(), "invalid commit must not publish any artifacts"
    assert not list(work.iterdir()), "invalid commit must not leave staging behind"
    assert snapshot(repo) == before
