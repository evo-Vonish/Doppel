"""docker 命令封装（SPEC §7.4）。

纪律：
- 所有 subprocess 调用返回 (rc, stdout, stderr)；
- 不捕获异常吃掉错误——docker 不存在等 OSError 直接向上抛，
  由 CLI 层决定如何向用户报告；
- docker run 组装严格对应 M1 方案 §6 的运行时基线：
  --shm-size=2g、--device /dev/dri、--cap-add NET_RAW/NET_ADMIN、
  profile/log 卷挂载、persona.yaml 只读挂载、容器名 ts_<id>。
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from .persona import Persona

# shm-size 基线：Docker 默认 64MB 必崩 Chrome（M1 方案 §11 坑位 1）
SHM_SIZE = "2g"
SHM_SIZE_BYTES = 2 * 1024 ** 3

# 镜像默认标签（M1 方案 §3 标签策略）；CLI 可用 TISHEN_IMAGE 覆盖
DEFAULT_IMAGE_TAG = "tishen/platform:latest-stable"


def container_name(persona_id: str) -> str:
    """容器命名约定：ts_<persona_id>。"""
    return f"ts_{persona_id}"


def _run(args: list[str]) -> tuple[int, str, str]:
    """执行命令并返回 (rc, stdout, stderr)。不吞异常：docker 缺失时
    FileNotFoundError 直接抛给调用方。"""
    proc = subprocess.run(args, capture_output=True, text=True, check=False)
    return proc.returncode, proc.stdout, proc.stderr


def build_run_command(persona: Persona, image_tag: str,
                      personas_dir: str | Path) -> list[str]:
    """组装 docker run 命令（M1 方案 §6 基线，A4：固化进编排层）。"""
    pid = persona.meta.id
    yaml_path = Path(personas_dir).expanduser().resolve() / f"{pid}.yaml"
    return [
        "docker", "run", "-d",
        "--name", container_name(pid),
        f"--shm-size={SHM_SIZE}",
        "--device", "/dev/dri",                       # GPU 透传（R2）
        "--cap-add", "NET_RAW", "--cap-add", "NET_ADMIN",  # 观测抓包所需
        "--security-opt", "seccomp=default",          # 安全基线：不加 --no-sandbox
        "-v", f"{persona.storage.profile_volume}:/persona/profile",
        "-v", f"{persona.storage.log_volume}:/persona/logs",
        "-v", f"{yaml_path}:/persona/persona.yaml:ro",     # persona 只读挂载
        image_tag,
    ]


def run_persona_container(persona: Persona, image_tag: str,
                          personas_dir: str | Path) -> tuple[int, str, str]:
    """docker run 启动替身容器。"""
    return _run(build_run_command(persona, image_tag, personas_dir))


def start_container(persona_id: str) -> tuple[int, str, str]:
    """启动已存在的容器。"""
    return _run(["docker", "start", container_name(persona_id)])


def stop_container(persona_id: str) -> tuple[int, str, str]:
    """停止容器（发 SIGTERM，persona-bake 负责优雅退出）。"""
    return _run(["docker", "stop", container_name(persona_id)])


def pause_container(persona_id: str) -> tuple[int, str, str]:
    """suspend = docker pause。"""
    return _run(["docker", "pause", container_name(persona_id)])


def unpause_container(persona_id: str) -> tuple[int, str, str]:
    """resume = docker unpause。"""
    return _run(["docker", "unpause", container_name(persona_id)])


def rm_container(persona_id: str, force: bool = True) -> tuple[int, str, str]:
    """删除容器。force=True 等价 docker rm -f（先停后删）。"""
    args = ["docker", "rm"]
    if force:
        args.append("-f")
    args.append(container_name(persona_id))
    return _run(args)


def container_exists(persona_id: str) -> bool:
    """容器是否存在（docker inspect 返回码为 0）。"""
    rc, _, _ = _run(["docker", "inspect", container_name(persona_id)])
    return rc == 0


def container_shm_size(persona_id: str) -> int | None:
    """读容器 HostConfig.ShmSize（doctor §7.5 用）；读不到返回 None。"""
    rc, out, _ = _run(["docker", "inspect", "--format",
                       "{{.HostConfig.ShmSize}}", container_name(persona_id)])
    if rc != 0:
        return None
    try:
        return int(out.strip())
    except ValueError:
        return None


def volume_create(name: str) -> tuple[int, str, str]:
    """创建 docker 卷。"""
    return _run(["docker", "volume", "create", name])


def volume_rm(name: str, force: bool = True) -> tuple[int, str, str]:
    """删除 docker 卷。"""
    args = ["docker", "volume", "rm"]
    if force:
        args.append("-f")
    args.append(name)
    return _run(args)


def volume_exists(name: str) -> bool:
    """卷是否存在。"""
    rc, _, _ = _run(["docker", "volume", "inspect", name])
    return rc == 0


def docker_available() -> tuple[bool, str]:
    """docker 可用性探测；返回 (是否可用, docker version 摘要或错误)。

    docker 二进制不存在时 FileNotFoundError 向上抛（不吞错纪律），
    调用方（doctor/CLI）自行捕获并给出中文提示。
    """
    rc, out, err = _run(["docker", "version", "--format", "{{.Server.Version}}"])
    if rc == 0:
        return True, out.strip()
    return False, (err or out).strip()
