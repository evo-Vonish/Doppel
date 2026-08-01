"""INS-1 一体化安装器骨架测试（shell/install.sh + shell/uninstall.sh）。

执行方式：pytest 内嵌 bash 调用真实脚本。通过脚本预留的环境变量注入点
（DOPPEL_OS_RELEASE / DOPPEL_PREFIX / DOPPEL_DAEMON_JSON / DOPPEL_LOG_DIR）
与 fakebin（PATH 前置的假命令目录：sudo/docker/curl/usermod/sg/snap）
实现零触网、零系统改动的全链路验证。
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
INSTALL_SH = REPO_ROOT / "shell" / "install.sh"
UNINSTALL_SH = REPO_ROOT / "shell" / "uninstall.sh"

APP_NAME = "doppel-shell.AppImage"
FAKE_APP_CONTENT = b"FAKE-APPIMAGE-V1\n"

# 四档发行版 fixture（经 DOPPEL_OS_RELEASE 注入，顶替 /etc/os-release）
OS_RELEASE_FIXTURES = {
    "ubuntu": 'PRETTY_NAME="Ubuntu 24.04 LTS"\nID=ubuntu\nVERSION_ID="24.04"\n',
    "debian": 'PRETTY_NAME="Debian GNU/Linux 12"\nID=debian\nVERSION_ID="12"\n',
    "fedora": 'PRETTY_NAME="Fedora Linux 40"\nID=fedora\nVERSION_ID="40"\n',
    "unknown": 'PRETTY_NAME="Arch Linux"\nID=arch\nVERSION_ID="20240101"\n',
}

# ---------- fakebin 假命令（全部不触网、不改系统） ----------
FAKE_SUDO = '#!/bin/sh\nexec "$@"\n'  # 假 sudo：直接以当前用户执行参数命令
FAKE_USERMOD = "#!/bin/sh\nexit 0\n"
FAKE_SG = "#!/bin/sh\nexit 0\n"
FAKE_DOCKER = (
    "#!/bin/sh\n"
    'case "$1" in --version|version) echo "Docker version 26.0.0-fake";; esac\n'
    "exit 0\n"
)
FAKE_SNAP_WITH_DOCKER = (
    "#!/bin/sh\n"
    'if [ "$1" = "list" ] && [ "$2" = "docker" ]; then\n'
    '  echo "docker 1.0 20 latest/stable canonical** installed"\n'
    "  exit 0\n"
    "fi\n"
    "exit 1\n"
)


def run_sh(script: Path, args: list[str], env_extra: dict) -> subprocess.CompletedProcess:
    """内嵌 bash 执行脚本；脱离控制终端（/dev/tty 读取必失败），保证非交互确定性。"""
    env = dict(os.environ)
    env.update(env_extra)
    return subprocess.run(
        ["bash", str(script), *args],
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        stdin=subprocess.DEVNULL,
        start_new_session=True,
    )


def write_fake(bin_dir: Path, name: str, body: str) -> None:
    path = bin_dir / name
    path.write_text(body)
    path.chmod(0o755)


def make_curl_fake(bin_dir: Path, sha_line: str) -> None:
    """假 curl：按 URL 落盘假 AppImage 与指定的校验和行，全程不触网。"""
    body = (
        "#!/bin/bash\n"
        'OUT=""; URL=""\n'
        "while [ $# -gt 0 ]; do\n"
        '  case "$1" in\n'
        '    -o) OUT="$2"; shift 2;;\n'
        "    -*) shift;;\n"
        '    *) URL="$1"; shift;;\n'
        "  esac\n"
        "done\n"
        'case "$URL" in\n'
        f'  *.sha256) printf "%s\\n" "{sha_line}" > "$OUT";;\n'
        '  *) printf "FAKE-APPIMAGE-V1\\n" > "$OUT";;\n'
        "esac\n"
    )
    write_fake(bin_dir, "curl", body)


def make_full_fakebin(tmp_path: Path, sha_line: str) -> Path:
    """真实跑通安装全流程所需的完整假命令目录。"""
    bin_dir = tmp_path / "fakebin"
    bin_dir.mkdir(exist_ok=True)
    write_fake(bin_dir, "sudo", FAKE_SUDO)
    write_fake(bin_dir, "docker", FAKE_DOCKER)
    write_fake(bin_dir, "usermod", FAKE_USERMOD)
    write_fake(bin_dir, "sg", FAKE_SG)
    make_curl_fake(bin_dir, sha_line)
    return bin_dir


def snapshot_tree(root: Path) -> list[str]:
    """目录树快照（dry-run 零落盘断言用）。"""
    return sorted(str(p.relative_to(root)) for p in root.rglob("*"))


@pytest.fixture
def injected(tmp_path: Path) -> dict:
    """安装器注入环境：伪造 os-release + 临时 HOME/前缀/日志/daemon.json。"""
    os_release = tmp_path / "os-release"
    os_release.write_text(OS_RELEASE_FIXTURES["ubuntu"])
    home = tmp_path / "home"
    home.mkdir()
    return {
        "HOME": str(home),
        "DOPPEL_OS_RELEASE": str(os_release),
        "DOPPEL_PREFIX": str(tmp_path / "prefix"),
        "DOPPEL_DAEMON_JSON": str(tmp_path / "daemon.json"),
        "DOPPEL_LOG_DIR": str(tmp_path / "logs"),
    }


# ---------- 1~3：dry-run 三族发行版矩阵输出断言 ----------
@pytest.mark.parametrize(
    "distro,pkg_cmd",
    [("ubuntu", "apt-get install -y docker.io"),
     ("debian", "apt-get install -y docker.io"),
     ("fedora", "dnf install -y docker")],
)
def test_dry_run_supported_distros(distro: str, pkg_cmd: str, injected: dict) -> None:
    Path(injected["DOPPEL_OS_RELEASE"]).write_text(OS_RELEASE_FIXTURES[distro])
    result = run_sh(INSTALL_SH, ["--dry-run"], injected)
    assert result.returncode == 0, result.stderr
    out = result.stdout
    for i in range(1, 7):
        assert f"[{i}/6]" in out  # 六步中文回显齐全
    assert distro in out
    assert pkg_cmd in out  # 对应发行版的代装命令
    assert "dry-run" in out
    assert "newgrp docker" in out  # docker 组生效话术
    assert "max-download-attempts" in out  # daemon.json 调优段


# ---------- 4：未知发行版降级指引模式，退出码 2（不硬失败） ----------
def test_unknown_distro_guidance_mode(injected: dict) -> None:
    Path(injected["DOPPEL_OS_RELEASE"]).write_text(OS_RELEASE_FIXTURES["unknown"])
    result = run_sh(INSTALL_SH, ["--dry-run"], injected)
    assert result.returncode == 2
    assert "指引模式" in result.stdout
    assert "docs.docker.com" in result.stdout  # 手动安装指引


# ---------- 5：dry-run 零落盘（临时 HOME/前缀/日志目录前后对比一致） ----------
def test_dry_run_zero_disk_writes(injected: dict, tmp_path: Path) -> None:
    before = snapshot_tree(tmp_path)
    result = run_sh(INSTALL_SH, ["--dry-run"], injected)
    assert result.returncode == 0
    assert snapshot_tree(tmp_path) == before  # 任何文件/目录都未新增
    assert not Path(injected["DOPPEL_PREFIX"]).exists()
    assert not Path(injected["DOPPEL_LOG_DIR"]).exists()  # dry-run 连日志文件都不写


# ---------- 6：snap 版 Docker 黑名单，检出即拒，退出码 3 ----------
def test_snap_docker_rejected(injected: dict, tmp_path: Path) -> None:
    bin_dir = tmp_path / "fakebin"
    bin_dir.mkdir()
    write_fake(bin_dir, "snap", FAKE_SNAP_WITH_DOCKER)
    env = dict(injected)
    env["PATH"] = f"{bin_dir}:{os.environ['PATH']}"
    result = run_sh(INSTALL_SH, ["--dry-run"], env)
    assert result.returncode == 3
    assert "snap" in result.stdout
    assert "snap remove docker" in result.stdout  # 卸载指引


# ---------- 7：SHA256 校验失败即删除下载文件，退出码 4 ----------
def test_checksum_failure_exit4(injected: dict, tmp_path: Path) -> None:
    bin_dir = make_full_fakebin(tmp_path, f"{'0' * 64}  {APP_NAME}")
    env = dict(injected)
    env["PATH"] = f"{bin_dir}:{os.environ['PATH']}"
    result = run_sh(INSTALL_SH, ["--unattended"], env)
    assert result.returncode == 4
    assert "校验失败" in result.stdout
    assert not (Path(injected["DOPPEL_PREFIX"]) / APP_NAME).exists()  # 失败即删


# ---------- 8：真实跑通（假命令全链路）+ daemon.json 合并不覆盖 + 幂等重跑 ----------
def test_real_run_success_daemon_merge_and_rerun(injected: dict, tmp_path: Path) -> None:
    good_sha = hashlib.sha256(FAKE_APP_CONTENT).hexdigest()
    bin_dir = make_full_fakebin(tmp_path, f"{good_sha}  {APP_NAME}")
    env = dict(injected)
    env["PATH"] = f"{bin_dir}:{os.environ['PATH']}"
    daemon = Path(injected["DOPPEL_DAEMON_JSON"])
    daemon.write_text(json.dumps({"registry-mirrors": ["https://mirror.example"]}))

    result = run_sh(INSTALL_SH, ["--unattended"], env)
    assert result.returncode == 0, result.stdout + result.stderr
    app = Path(injected["DOPPEL_PREFIX"]) / APP_NAME
    assert app.exists() and os.access(app, os.X_OK)  # 外壳落盘且可执行
    merged = json.loads(daemon.read_text())
    assert merged["max-download-attempts"] == 5  # 调优键写入
    assert merged["registry-mirrors"] == ["https://mirror.example"]  # 既有键保留（合并不覆盖）
    logs = list(Path(injected["DOPPEL_LOG_DIR"]).glob("doppel-install-*.log"))
    assert len(logs) >= 1  # 全程 tee 日志落盘

    rerun = run_sh(INSTALL_SH, ["--unattended"], env)  # 幂等重跑
    assert rerun.returncode == 0
    assert "跳过代装" in rerun.stdout  # 已装 Docker 直接跳过


# ---------- 9：dry-run 连跑两次输出完全一致（幂等稳定） ----------
def test_dry_run_idempotent_output(injected: dict) -> None:
    first = run_sh(INSTALL_SH, ["--dry-run"], injected)
    second = run_sh(INSTALL_SH, ["--dry-run"], injected)
    assert first.returncode == second.returncode == 0
    assert first.stdout == second.stdout


# ---------- 10：shellcheck 门禁（error 严重级别零命中） ----------
def test_shellcheck_error_level_clean() -> None:
    shellcheck = shutil.which("shellcheck")
    if shellcheck is None:
        pytest.skip("环境无 shellcheck，跳过静态门禁")
    for script in (INSTALL_SH, UNINSTALL_SH):
        result = subprocess.run(
            [shellcheck, "-S", "error", str(script)],
            capture_output=True, text=True,
        )
        assert result.returncode == 0, f"{script.name} shellcheck error:\n{result.stdout}"


# ---------- 11：uninstall.sh dry-run 预演（零落盘 + 关键步骤话术） ----------
def test_uninstall_dry_run(injected: dict, tmp_path: Path) -> None:
    before = snapshot_tree(tmp_path)
    result = run_sh(UNINSTALL_SH, ["--dry-run"], injected)
    assert result.returncode == 0, result.stderr
    out = result.stdout
    assert "doppel-image" in out  # 镜像清理段
    assert "ts_" in out  # 数据卷清理段
    assert "max-download-attempts" in out  # daemon.json 配置段回滚
    assert snapshot_tree(tmp_path) == before  # dry-run 零落盘


# ---------- 12：数据卷删除需 --force 二次确认；--force 下全量清除 ----------
def test_uninstall_volume_force_gate(injected: dict, tmp_path: Path) -> None:
    bin_dir = tmp_path / "fakebin"
    bin_dir.mkdir()
    calls = tmp_path / "calls.log"
    write_fake(bin_dir, "sudo", FAKE_SUDO)
    write_fake(
        bin_dir, "docker",
        "#!/bin/sh\n"
        f'echo "$@" >> "{calls}"\n'
        'case "$1" in\n'
        '  images) echo "doppel-image:latest";;\n'
        '  volume) if [ "$2" = "ls" ]; then echo "ts_persona"; echo "ts_cache"; fi;;\n'
        "esac\n"
        "exit 0\n",
    )
    env = dict(injected)
    env["PATH"] = f"{bin_dir}:{os.environ['PATH']}"

    # 未给 --force（非交互下二次确认不可得）：数据卷必须被保护性跳过
    result = run_sh(UNINSTALL_SH, ["--unattended"], env)
    assert result.returncode == 0
    assert "销毁" in result.stdout  # 数据销毁话术
    recorded = calls.read_text() if calls.exists() else ""
    assert "volume rm" not in recorded  # 卷一个都不许删

    # --force：执行全量清除（资产目录 + 镜像 + 卷 + daemon.json 回滚）
    prefix = Path(injected["DOPPEL_PREFIX"])
    prefix.mkdir()
    (prefix / APP_NAME).write_text("x")
    daemon = Path(injected["DOPPEL_DAEMON_JSON"])
    daemon.write_text(json.dumps({"max-download-attempts": 5, "registry-mirrors": ["m"]}))

    forced = run_sh(UNINSTALL_SH, ["--force", "--unattended"], env)
    assert forced.returncode == 0, forced.stdout + forced.stderr
    recorded = calls.read_text()
    assert "volume rm ts_persona" in recorded and "volume rm ts_cache" in recorded
    assert "rmi doppel-image:latest" in recorded
    assert not prefix.exists()  # 资产目录已清除
    rolled_back = json.loads(daemon.read_text())
    assert "max-download-attempts" not in rolled_back  # 配置段已回滚
    assert rolled_back["registry-mirrors"] == ["m"]  # 其余配置保留
