# SPEC-E4 §件一 I3：native host argv 包装 + 扩展 id 派生 + manifest 渲染测试。
# 覆盖：包装脚本 argv 固化/0700/降级路径、_extension_id 金标准对拍（已知 RSA
# fixture → 已知 id）、manifest 渲染替换、既有 bake dry-run 契约零回归。
import hashlib
import importlib.util
import os
import shutil
import stat
import subprocess
import sys
import types
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
BAKE_PATH = REPO_ROOT / "image" / "entrypoint" / "persona_bake.py"
MANIFEST_TEMPLATE = REPO_ROOT / "image" / "hook" / "tishen_native_host.json"

# 已知 RSA fixture（openssl genrsa 2048，仅测试用途），chrome 算法金标准 id 见下
FIXTURE_KEY_PEM = """-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDlMD2vhypl/1k2
p9d1uWcTi2KRBAR/3NhCKFYThzCywXcfniRBXasa8lG9Tbnv/U3EVpn+z/V7KgmB
FQnKleiemGxV22neKuHM0fl48RW3rqMfHCWgO9vtJuaVUTV/otuOQAr6XLMtz7H8
c90rjbl7ZdCK8ukGX1VuKfvY/yEihP1tH0EDfk9h9glc7jlYSChIQVzZf//0/QDs
azn+frtHbZLCzc9SwiCH1rEJ4HFN4cVpuISwVmKy3NY9VjMidy+yQ+hBzpH0tEf2
iWuMWNq2QiCAGi8EE3s2LkWZec+ez+7JH2WTFHMSV3ETb16DP+r9Gqd+df6wV0Ao
voN0SyKTAgMBAAECggEARCugtYShXlxhB2pOIrSmjcAwbc0Bn5yrcKY50C4ulIUK
L0vlIdJAMlAwcvvbGiDAkG1n+cyWim97CzucQXdsjTvuQW11pIEhz8AHEeu3135p
A7hmEq6rYHNpM7HHlXL2Fm5DNav8GdzE5r/54doSeTtUF/hfyqbxrMZtJGLi0ram
tehYScp41OnO1/Yv0vKWDaSS15ChX+lsFOMEoAeqF0YUQ4Lae03reMJYdW8p548T
5sUYOoFE7vrCzqPUvknSpHtV4tJLxP9BqHiAnuapw7wh44azU39mPI6GfkOW5qJN
dUw95GGxTdg7dTPqPeQ7uTZcKFsXwP2U+KPYvo+FeQKBgQD/K41z24bNdfxG5+Kg
AlHCtaBnAj+jggYd+N05kTeKC0xlkHVHyM1a6eA2KypcsS76qnI0qYM6rUVqNhe9
9Q/y98gw9FW01D64X/lNnT/RmOi80nNwH6t/pqHqt7GC6cSYFuxWe7Ituo2iTl01
/jd6aqnvy3Mx2NSmBG95Sz36iQKBgQDl7w6J5VQkpH4+iXCXYkMoHae5So5MF4Zf
iu7DK1eX5KGr++c1X3DRlcU+OFOOMM0knYzcYTxyl4mzhE3COzENl3PP28Y/DyZv
XvUeUOsuVx075B4YtbyRCU9klUi25PMEEjWJ3BN1tbE+7ERMmO+LoDjLT1gv0H/g
qt4Z2uH9OwKBgBYcgQpsGHdPZQgD6ghxiwIzWO30LO2PQ9ZvDUSCx+xHZFxcsz0A
MoNRRuOKxAX6OJbyFClqEvwPrbcxbsdAKBymygsr8Q1VYwX5ExJdsP0JoglStzwd
EnBiUR+UwWYVubpwKhSobV03EDTjU4JtQAN0oLstxxKntm2Ybsx07675AoGAMHkN
H5TxACiNVLG0wrU8YyCdUzqcdP4gndO0MgDZHnRcgN1CCMZuCkEAq/VD6B3xoV51
a6A0FhRMO0QRAHlqBet/xroWOQUAnUnvcsysR8ClsRKOJbdqYUkNK68s/SGW+ay9
DKsQjygWjaVRYLR9C3pjfrjjZnEWBE8BM4IpUjECgYEAxvvmvNX273LhPgOjowpw
IBsgc5HnMPQRMp0ByCB4/ZfKSb6mxGT8oT9gymmfOHCnxQ1eRwbPcJYiWIir152E
gsii53+08Xm63pFzTL6Z4aKFpBGsrXLAHOmrEGwxhCwIaVhH+1GxRlWBkPEyrCtO
sKfCDRFGH5gajHxvaApxSlg=
-----END PRIVATE KEY-----
"""
# 金标准：openssl 3.0.20 从 fixture 提取 public key DER → sha256 前 16 字节
# 按 a–p 映射（每字节高低半字节各一字符），独立复算结果
GOLDEN_EXT_ID = "ihajhfphhmhdipiehjehlkjabpafjemi"

openssl_required = pytest.mark.skipif(
    shutil.which("openssl") is None, reason="openssl 不可用（镜像内恒定可用，开发机跳过）")


def _load_bake():
    """按路径加载 persona_bake（image/entrypoint 不在包内，避免与既有模块混淆）。"""
    spec = importlib.util.spec_from_file_location("tishen_persona_bake_e4", BAKE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture()
def bake():
    return _load_bake()


@pytest.fixture()
def persona():
    return types.SimpleNamespace(meta=types.SimpleNamespace(id="persona-test-01"))


@pytest.fixture()
def key_file(tmp_path):
    p = tmp_path / "ext-key.pem"
    p.write_text(FIXTURE_KEY_PEM, encoding="utf-8")
    return str(p)


def _isolate_hook_paths(bake, monkeypatch, tmp_path):
    """把 step7_7 的落盘路径全部重定向到 tmp，并令 hook 总线自检降级（不起子进程）。"""
    monkeypatch.setattr(bake, "HOOK_WRAPPER", str(tmp_path / "run" / "tishen" / "native-host-wrapper.sh"))
    monkeypatch.setattr(bake, "HOOK_NATIVE_MANIFEST_DIR", str(tmp_path / "NativeMessagingHosts"))
    monkeypatch.setattr(bake, "HOOK_NATIVE_MANIFEST_TEMPLATE", str(MANIFEST_TEMPLATE))
    monkeypatch.setattr(bake, "_hook_bus_available", lambda: False)


# ── 包装脚本生成 ────────────────────────────────────────────────────────────
def test_wrapper_argv_baked_and_mode0700(bake, persona, monkeypatch, tmp_path):
    wrapper = tmp_path / "run" / "tishen" / "native-host-wrapper.sh"
    monkeypatch.setattr(bake, "HOOK_WRAPPER", str(wrapper))
    result = bake._write_native_host_wrapper(persona, "sess-abc")
    assert result == str(wrapper)
    body = wrapper.read_text(encoding="utf-8")
    # argv 固化进脚本体，exec 转发 stdio
    assert body.startswith("#!/bin/sh\n")
    assert "exec /opt/tishen/hook/tishen_native_host.py" in body
    assert "--persona-id persona-test-01" in body
    assert "--session-id sess-abc" in body
    assert f"--socket {bake.HOOK_SOCKET}" in body
    assert f"--payload-log {bake.HOOK_PAYLOAD_LOG}" in body
    assert body.rstrip().endswith('"$@"')
    # 0700 权限
    assert stat.S_IMODE(wrapper.stat().st_mode) == 0o700


def test_wrapper_generation_failure_degrades(bake, persona, monkeypatch, tmp_path, capsys):
    blocker = tmp_path / "not-a-dir"
    blocker.write_text("x", encoding="utf-8")
    monkeypatch.setattr(bake, "HOOK_WRAPPER", str(blocker / "sub" / "wrapper.sh"))
    assert bake._write_native_host_wrapper(persona, "sess-abc") is None  # 无异常、无 fail()
    assert "降级" in capsys.readouterr().out


# ── _extension_id 金标准对拍 ────────────────────────────────────────────────
@openssl_required
def test_extension_id_golden(bake, key_file):
    assert bake._extension_id(key_file) == GOLDEN_EXT_ID


@openssl_required
def test_extension_id_matches_chrome_algorithm(bake, key_file):
    """独立复算（不经被测函数）：DER → sha256 前 16 字节 a–p 映射，双向对拍。"""
    der = subprocess.run(["openssl", "rsa", "-in", key_file, "-pubout", "-outform", "DER"],
                         capture_output=True, check=True).stdout
    digest = hashlib.sha256(der).digest()[:16]
    expected = "".join(chr(97 + (b >> 4)) + chr(97 + (b & 0xF)) for b in digest)
    assert expected == GOLDEN_EXT_ID  # 复算锚定金标准，防 fixture 被换
    assert bake._extension_id(key_file) == expected


def test_extension_id_missing_key_raises(bake, tmp_path):
    with pytest.raises((OSError, subprocess.CalledProcessError)):
        bake._extension_id(str(tmp_path / "absent.pem"))


# ── manifest 渲染替换 ───────────────────────────────────────────────────────
@openssl_required
def test_manifest_render_with_wrapper_and_ext_id(bake, persona, monkeypatch, tmp_path, key_file):
    _isolate_hook_paths(bake, monkeypatch, tmp_path)
    monkeypatch.setattr(bake, "HOOK_EXT_KEY", key_file)
    monkeypatch.setattr(bake, "_DRY_RUN", False)
    monkeypatch.delenv("TISHEN_SESSION_ID", raising=False)
    bake.step7_7_hook(persona)
    rendered = (tmp_path / "NativeMessagingHosts" / "tishen_native_host.json").read_text(encoding="utf-8")
    # HOST_PATH 指向包装脚本（非直连 host 路径），EXT_ID 已替换
    assert str(tmp_path / "run" / "tishen" / "native-host-wrapper.sh") in rendered
    assert f"chrome-extension://{GOLDEN_EXT_ID}/" in rendered
    assert "__HOST_PATH__" not in rendered and "__EXT_ID__" not in rendered


def test_manifest_render_degraded_keeps_placeholders(bake, persona, monkeypatch, tmp_path, capsys):
    _isolate_hook_paths(bake, monkeypatch, tmp_path)
    blocker = tmp_path / "not-a-dir"
    blocker.write_text("x", encoding="utf-8")
    monkeypatch.setattr(bake, "HOOK_WRAPPER", str(blocker / "sub" / "wrapper.sh"))
    monkeypatch.setattr(bake, "HOOK_EXT_KEY", str(tmp_path / "absent.pem"))
    monkeypatch.setattr(bake, "_DRY_RUN", False)
    monkeypatch.delenv("TISHEN_SESSION_ID", raising=False)
    bake.step7_7_hook(persona)  # 全程降级，无 fail()/异常
    rendered = (tmp_path / "NativeMessagingHosts" / "tishen_native_host.json").read_text(encoding="utf-8")
    # 包装失败 → 降级直连 host 路径；key 缺失 → 保留 __EXT_ID__ 占位
    assert bake.HOOK_NATIVE_HOST in rendered
    assert "__EXT_ID__" in rendered
    assert "降级" in capsys.readouterr().out


# ── 会话 id 与 dry-run 契约零回归 ───────────────────────────────────────────
def test_session_id_env_reuse_and_generate(bake, monkeypatch):
    monkeypatch.setenv("TISHEN_SESSION_ID", "sess-fixed")
    assert bake._session_id() == "sess-fixed"  # 环境注入优先
    monkeypatch.delenv("TISHEN_SESSION_ID")
    generated = bake._session_id()
    assert generated and generated != "sess-fixed"
    assert os.environ["TISHEN_SESSION_ID"] == generated  # 回写环境保证同次启动一致
    assert bake._session_id() == generated  # 幂等


def test_dry_run_contract_no_writes(bake, persona, monkeypatch, tmp_path, capsys):
    _isolate_hook_paths(bake, monkeypatch, tmp_path)
    monkeypatch.setattr(bake, "HOOK_EXT_KEY", str(tmp_path / "absent.pem"))
    monkeypatch.setattr(bake, "_DRY_RUN", True)
    monkeypatch.setenv("TISHEN_SESSION_ID", "sess-dry")
    bake.step7_7_hook(persona)
    out = capsys.readouterr().out
    assert "[dry-run]" in out
    assert bake.HOOK_WRAPPER in out  # 计划打印含包装脚本路径
    # dry-run 零落盘（契约：只打印计划不执行）
    assert not (tmp_path / "run").exists()
    assert not (tmp_path / "NativeMessagingHosts").exists()


def test_build_chrome_argv_load_extension_unchanged(bake, persona):
    argv = bake.build_chrome_argv(persona_display := types.SimpleNamespace(
        meta=types.SimpleNamespace(id="p"), region=types.SimpleNamespace(locale="zh-CN"),
        webrtc=types.SimpleNamespace(ip_handling_policy="default")), "mesa")
    assert f"--load-extension={bake.HOOK_EXT_DIR}" in argv
    assert "--no-sandbox" not in argv and "--remote-debugging-port" not in " ".join(argv)
