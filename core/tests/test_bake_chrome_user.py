"""真机格 3：Chrome 非 root + setuid sandbox 运行契约。"""

import importlib.util
import os
import stat
import types
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
BAKE_PATH = REPO_ROOT / "image" / "entrypoint" / "persona_bake.py"


@pytest.fixture()
def bake():
    spec = importlib.util.spec_from_file_location("tishen_persona_bake_chrome_user", BAKE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_prepare_chrome_user_dry_run_is_read_only(bake, monkeypatch, tmp_path):
    bake._DRY_RUN = True
    profile = tmp_path / "profile"
    profile.mkdir()
    lock = profile / "SingletonLock"
    lock.write_text("must remain", encoding="utf-8")
    monkeypatch.setattr(bake, "CHROME_PROFILE", profile)
    monkeypatch.setattr(
        bake,
        "_chown_tree_once",
        lambda path: pytest.fail(f"dry-run 不应迁移目录：{path}"),
    )

    env = bake.prepare_chrome_user()

    assert env["HOME"] == "/home/ubuntu"
    assert env["USER"] == env["LOGNAME"] == "ubuntu"
    assert env["XDG_RUNTIME_DIR"] == "/run/user/1000"
    assert lock.read_text(encoding="utf-8") == "must remain"


def test_prepare_chrome_user_removes_only_stale_singleton_locks(bake, monkeypatch, tmp_path):
    bake._DRY_RUN = False
    profile = tmp_path / "profile"
    profile.mkdir()
    history = profile / "History"
    history.write_text("must survive", encoding="utf-8")
    locks = [profile / name for name in bake.CHROME_SINGLETON_FILES]
    for lock in locks:
        lock.write_text("stale", encoding="utf-8")
    monkeypatch.setattr(bake, "CHROME_PROFILE", profile)
    monkeypatch.setattr(bake, "_chown_tree_once", lambda path: None)
    monkeypatch.setattr(Path, "chmod", lambda path, mode: None)

    bake.prepare_chrome_user()

    assert all(not lock.exists() for lock in locks)
    assert history.read_text(encoding="utf-8") == "must survive"


def test_prepare_chrome_user_hands_off_only_chrome_write_paths(bake, monkeypatch):
    bake._DRY_RUN = False
    handed_off = []
    chmod_calls = []
    monkeypatch.setattr(bake, "_chown_tree_once", lambda path: handed_off.append(str(path)))
    monkeypatch.setattr(Path, "chmod", lambda path, mode: chmod_calls.append((str(path), mode)))

    env = bake.prepare_chrome_user()

    assert [path.replace("\\", "/") for path in handed_off] == [
        "/persona/profile",
        "/persona/logs/sslkeys",
        "/persona/logs/hook",
        "/run/user/1000",
    ]
    assert [(path.replace("\\", "/"), mode) for path, mode in chmod_calls] == [
        ("/run/user/1000", 0o700)
    ]
    assert env["HOME"] == bake.CHROME_HOME


def test_chown_tree_migrates_root_last_and_skips_after_handoff(bake, monkeypatch, tmp_path):
    root = tmp_path / "profile"
    child = root / "Default"
    child.mkdir(parents=True)
    cookie = child / "Cookies"
    cookie.write_text("fixture", encoding="utf-8")
    calls = []
    monkeypatch.setattr(bake, "CHROME_UID", 4242)
    monkeypatch.setattr(bake, "CHROME_GID", 4343)
    monkeypatch.setattr(
        bake.os,
        "chown",
        lambda path, uid, gid, **kwargs: calls.append((Path(path), uid, gid, kwargs)),
        raising=False,
    )

    bake._chown_tree_once(root)

    assert calls[-1][:3] == (root, 4242, 4343)
    assert {item[0] for item in calls[:-1]} == {child, cookie}
    assert all(item[3] == {"follow_symlinks": False} for item in calls)

    # 根目录已完成交接时不再遍历大型持久化 profile。
    calls.clear()
    monkeypatch.setattr(bake, "CHROME_UID", root.stat().st_uid)
    monkeypatch.setattr(bake, "CHROME_GID", root.stat().st_gid)
    bake._chown_tree_once(root)
    assert calls == []


def test_hook_socket_is_handed_to_chrome_user_and_stays_0600(bake, monkeypatch, tmp_path):
    socket_path = tmp_path / "hook.sock"
    socket_path.touch()
    ownership = []
    monkeypatch.setattr(bake, "HOOK_SOCKET", str(socket_path))
    monkeypatch.setattr(
        bake.os,
        "chown",
        lambda path, uid, gid: ownership.append((Path(path), uid, gid)),
        raising=False,
    )

    bake._handoff_hook_socket(timeout=0.1)

    assert ownership == [(socket_path, bake.CHROME_UID, bake.CHROME_GID)]
    if os.name != "nt":
        assert stat.S_IMODE(socket_path.stat().st_mode) == 0o600


def test_main_launches_chrome_as_ubuntu_without_forbidden_flags():
    source = BAKE_PATH.read_text(encoding="utf-8")
    assert "user=CHROME_UID" in source
    assert "group=CHROME_GID" in source
    assert "extra_groups=()" in source
    assert 'FORBIDDEN_FLAGS = ("--no-sandbox", "--remote-debugging-port")' in source
    launch_section = source[source.index('log(f"启动 Chrome') : source.index('_boot_mark("chrome_launch")')]
    assert "--no-sandbox" not in launch_section


def test_chrome_uses_explicit_persona_proxy_only_when_configured(bake):
    persona = types.SimpleNamespace(
        region=types.SimpleNamespace(locale="en-CA"),
        webrtc=types.SimpleNamespace(ip_handling_policy="disable_non_proxied_udp"),
        proxy="http://host.docker.internal:11089",
    )
    argv = bake.build_chrome_argv(persona, "mesa")
    assert "--proxy-server=http://host.docker.internal:11089" in argv

    persona.proxy = None
    argv = bake.build_chrome_argv(persona, "mesa")
    assert not any(arg.startswith("--proxy-server=") for arg in argv)


def test_hook_bus_removes_stale_volume_socket_before_spawn_and_handoff():
    source = BAKE_PATH.read_text(encoding="utf-8")
    hook_section = source[source.index("def step7_7_hook") : source.index("# ── 第 7.5 步")]
    unlink = 'Path(HOOK_SOCKET).unlink(missing_ok=True)'
    spawn = '_CHILDREN["hook_bus"] = subprocess.Popen(hook_argv)'
    handoff = "_handoff_hook_socket()"
    assert hook_section.index(unlink) < hook_section.index(spawn) < hook_section.index(handoff)
