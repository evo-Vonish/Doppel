"""docker 命令封装（SPEC §7.4）。

纪律：
- 所有 subprocess 调用返回 (rc, stdout, stderr)；
- 不捕获异常吃掉错误——docker 不存在等 OSError 直接向上抛，
  由 CLI 层决定如何向用户报告；
- docker run 组装严格对应 M1 方案 §6 的运行时基线：
  --shm-size=2g、宿主 GPU 设备、--cap-add NET_RAW/NET_ADMIN、
  profile/log 卷挂载、persona.yaml 只读挂载、容器名 ts_<id>；
- M2 流层追加（SPEC-M2M3 §1.3）：-p 127.0.0.1:0:8080（neko 只发布到宿主 loopback
  的随机空闲端口）、-e NEKO_PASSWORD=<创建时生成的随机口令>；
  start 后 docker port 解析宿主端口供外壳拼接 embed_url。
"""

from __future__ import annotations

import secrets
import subprocess
from pathlib import Path

from .persona import Persona

# shm-size 基线：Docker 默认 64MB 必崩 Chrome（M1 方案 §11 坑位 1）
SHM_SIZE = "2g"
SHM_SIZE_BYTES = 2 * 1024 ** 3

# 镜像默认标签（M1 方案 §3 标签策略）；CLI 可用 TISHEN_IMAGE 覆盖
DEFAULT_IMAGE_TAG = "tishen/platform:latest-stable"

# neko 流服务容器内监听端口（与镜像 ENV NEKO_BIND=:8080 对应）
NEKO_CONTAINER_PORT = 8080

# Windows 11 / WSL2 的 GPU 透传不是 Linux DRI 设备。三件套必须同时存在：
# dxg 字符设备、Windows GPU 用户态库、WSLg 共享运行目录。
WSL_GPU_DEVICE = Path("/dev/dxg")
WSL_GPU_LIB_DIR = Path("/usr/lib/wsl")
WSL_GPU_RUNTIME_DIR = Path("/mnt/wslg")


def container_name(persona_id: str) -> str:
    """容器命名约定：ts_<persona_id>。"""
    return f"ts_{persona_id}"


def _run(args: list[str]) -> tuple[int, str, str]:
    """执行命令并返回 (rc, stdout, stderr)。不吞异常：docker 缺失时
    FileNotFoundError 直接抛给调用方。"""
    proc = subprocess.run(args, capture_output=True, text=True, check=False)
    return proc.returncode, proc.stdout, proc.stderr


def generate_neko_password() -> str:
    """生成 neko 流服务登录口令（每替身创建时随机生成，M2 方案 §二.3）。

    口令只经 -e 注入容器与记入状态库（供外壳拼接 embed_url），不落 persona.yaml。
    """
    return secrets.token_hex(16)


def detect_gpu_backend() -> str:
    """探测宿主 GPU 透传后端：wsl、dri 或 missing。"""
    if (WSL_GPU_DEVICE.exists()
            and WSL_GPU_LIB_DIR.is_dir()
            and WSL_GPU_RUNTIME_DIR.is_dir()):
        return "wsl"
    if Path("/dev/dri").exists():
        return "dri"
    return "missing"


def gpu_passthrough_args(backend: str | None = None) -> list[str]:
    """返回 Docker GPU 参数；missing 保留既有 DRI 失败路径供 doctor 提示。"""
    selected = backend or detect_gpu_backend()
    if selected == "wsl":
        return [
            "--device", "/dev/dxg",
            "--mount", "type=bind,source=/usr/lib/wsl,target=/usr/lib/wsl,readonly",
            "--mount", "type=bind,source=/mnt/wslg,target=/mnt/wslg,readonly",
            "--env", "LD_LIBRARY_PATH=/usr/lib/wsl/lib",
        ]
    if selected in {"dri", "missing"}:
        return ["--device", "/dev/dri"]
    raise ValueError(f"未知 GPU 后端：{selected}")


def build_run_command(persona: Persona, image_tag: str,
                      personas_dir: str | Path,
                      neko_password: str | None = None) -> list[str]:
    """组装 docker run 命令（M1 方案 §6 基线 + M2 流层追加，A4：固化进编排层）。"""
    pid = persona.meta.id
    yaml_path = Path(personas_dir).expanduser().resolve() / f"{pid}.yaml"
    args = [
        "docker", "run", "-d",
        "--name", container_name(pid),
        f"--shm-size={SHM_SIZE}",
        *gpu_passthrough_args(),                        # GPU 透传（R2；Linux/WSL2）
        "--cap-add", "NET_RAW", "--cap-add", "NET_ADMIN",  # 观测抓包所需
        "--security-opt", "seccomp=default",          # 安全基线：不加 --no-sandbox
        "-v", f"{persona.storage.profile_volume}:/persona/profile",
        "-v", f"{persona.storage.log_volume}:/persona/logs",
        "-v", f"{yaml_path}:/persona/persona.yaml:ro",     # persona 只读挂载
    ]
    if neko_password is not None:
        # M2 流层：neko 只发布到宿主 loopback 的随机空闲端口（0 = docker 分配），
        # 口令经环境变量注入容器（persona-bake 第 7.5 步读取，缺失会拒绝启动）
        args += [
            "-p", f"127.0.0.1:0:{NEKO_CONTAINER_PORT}",
            "-e", f"NEKO_PASSWORD={neko_password}",
        ]
    args.append(image_tag)
    return args


def run_persona_container(persona: Persona, image_tag: str,
                          personas_dir: str | Path,
                          neko_password: str | None = None) -> tuple[int, str, str]:
    """docker run 启动替身容器。"""
    return _run(build_run_command(persona, image_tag, personas_dir, neko_password))


def container_host_port(persona_id: str) -> int | None:
    """解析 neko 端口在宿主的映射（docker port ts_<id> 8080）；读不到返回 None。

    输出形如「127.0.0.1:49153」（可能多行多绑定，取第一个解析成功的端口）。
    """
    rc, out, _ = _run(["docker", "port", container_name(persona_id),
                       str(NEKO_CONTAINER_PORT)])
    if rc != 0:
        return None
    for line in out.splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        try:
            return int(line.rsplit(":", 1)[1])
        except ValueError:
            continue
    return None


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


def image_exists(tag: str) -> bool:
    """镜像是否已存在于本地（M2 外壳首启引导用）。"""
    rc, _, _ = _run(["docker", "image", "inspect", tag])
    return rc == 0


def pull_image(tag: str) -> tuple[int, str, str]:
    """拉取替身平台镜像（M2 首启引导第 3 步；网络动作由使用者在真实环境触发）。"""
    return _run(["docker", "pull", tag])


def docker_available() -> tuple[bool, str]:
    """docker 可用性探测；返回 (是否可用, docker version 摘要或错误)。

    docker 二进制不存在时 FileNotFoundError 向上抛（不吞错纪律），
    调用方（doctor/CLI）自行捕获并给出中文提示。
    """
    rc, out, err = _run(["docker", "version", "--format", "{{.Server.Version}}"])
    if rc == 0:
        return True, out.strip()
    return False, (err or out).strip()
