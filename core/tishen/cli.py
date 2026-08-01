"""tishen 命令行（SPEC §7 + M2 JSON 输出与事件查询，SPEC-M2M3 §1.3，argparse）。

子命令：
    tishen create [--region auto|CN|HK|TW|JP|US|GB|DE] [--name 名] [--seed N]
    tishen start|stop|suspend|resume|reset|destroy <id>
    tishen list [--json]
    tishen events <id> [--type T] [--limit N] [--json]   # M2 新增；数据由 M3 观测模块提供
    tishen lint <persona.yaml>
    tishen doctor [<id>] [--json]
    tishen pull [--json]                                 # M2 新增：拉取平台镜像（幂等）
    tishen evolve <id> --pack <drift_pack.json>          # EVO-2：演化门禁检查（预览，不执行演化）
    tishen evolve <id> --pack <drift_pack.json> --execute
        # EVO-3：执行演化门禁序列（§四 0–8 骨架；真机步骤 stub 未接入则记 skipped）

M2 全局 --json（可放子命令前或后）：list --json 输出替身数组；
start <id> --json 输出 {"id","state","host_port","embed_url","password"} 供外壳消费；
doctor/pull/events 亦支持 --json（外壳契约：一切 docker 操作经 CLI --json）。
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import date
from pathlib import Path

from . import docker_ctl
from .linter import LintContext, lint_persona
from .persona import load as load_persona, dump as dump_persona, validate_structure
from .regions import REGION_PROFILES
from .sampler import create_persona
from .state import StateDB, tishen_home

# 当前 stable 基线：真实环境由流水线（§8）注入环境变量 TISHEN_STABLE_CHROME；
# 未注入时使用脚手架默认值（随 M1 出厂版本，后续由流水线维护更新）。
DEFAULT_STABLE_CHROME = "138.0.7204.0"

REGION_CHOICES = ["auto"] + sorted(REGION_PROFILES)


def _current_stable_chrome() -> str:
    """当前 stable 版本：环境变量优先，否则脚手架默认值。"""
    return os.environ.get("TISHEN_STABLE_CHROME", DEFAULT_STABLE_CHROME)


def _image_tag() -> str:
    """替身镜像标签：环境变量 TISHEN_IMAGE 优先，否则 latest-stable。"""
    return os.environ.get("TISHEN_IMAGE", docker_ctl.DEFAULT_IMAGE_TAG)


def _personas_dir() -> Path:
    d = tishen_home() / "personas"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _load_persona_or_exit(persona_id: str):
    """从 $TISHEN_HOME/personas/<id>.yaml 加载 persona；失败打印中文并退出。"""
    path = _personas_dir() / f"{persona_id}.yaml"
    if not path.exists():
        print(f"错误：找不到替身 {persona_id} 的 persona 文件：{path}", file=sys.stderr)
        print("提示：用 `tishen list` 查看已登记的替身。", file=sys.stderr)
        sys.exit(2)
    try:
        return load_persona(path)
    except ValueError as e:
        print(f"错误：persona 文件损坏：{e}", file=sys.stderr)
        sys.exit(2)


def _get_record_or_exit(db: StateDB, persona_id: str) -> dict:
    rec = db.get(persona_id)
    if rec is None:
        print(f"错误：状态库中不存在替身 {persona_id}。", file=sys.stderr)
        print("提示：用 `tishen list` 查看已登记的替身。", file=sys.stderr)
        sys.exit(2)
    return rec


def _report_docker_result(action: str, rc: int, out: str, err: str) -> bool:
    """统一报告 docker 调用结果；返回是否成功。"""
    if rc == 0:
        print(f"{action}：成功。")
        return True
    print(f"{action}：失败（退出码 {rc}）。", file=sys.stderr)
    detail = (err or out).strip()
    if detail:
        print(f"docker 输出：{detail}", file=sys.stderr)
    return False


def _embed_url(host_port: int | None, password: str | None) -> str | None:
    """拼接外壳 webview 嵌入地址（M2 方案 §二.3：?embed=1 免登录嵌入）。

    端口或口令缺失（如 M1 遗留替身）时返回 None——不编造不可用的 URL。
    """
    if host_port is None or not password:
        return None
    return f"http://127.0.0.1:{host_port}/?embed=1&usr=admin&pwd={password}"


def _json_mode(args) -> bool:
    """是否 --json 输出模式（全局开关，子命令经 parents 继承）。"""
    return bool(getattr(args, "json", False))


# ---------------------------------------------------------------------------
# create（§7.1）
# ---------------------------------------------------------------------------

def cmd_create(args) -> int:
    name = args.name or "默认替身"
    json_mode = _json_mode(args)

    def info(msg: str) -> None:
        # --json 模式人类可读信息走 stderr，stdout 只留最终 JSON（外壳按契约解析）
        print(msg, file=sys.stderr if json_mode else sys.stdout)

    try:
        persona = create_persona(
            name=name,
            region=args.region,
            stable_chrome=_current_stable_chrome(),
            ip_region=None,  # 网络探测属使用者环境动作，CLI 不主动联网（SPEC §0）
            seed=args.seed,
        )
    except (ValueError, RuntimeError) as e:
        print(f"错误：创建替身失败：{e}", file=sys.stderr)
        return 1

    # 落盘 persona.yaml
    yaml_path = _personas_dir() / f"{persona.meta.id}.yaml"
    dump_persona(persona, yaml_path)
    info(f"已生成 persona：{yaml_path}")
    if persona.meta.note:
        info(f"注意：{persona.meta.note}")

    # 创建两个卷（docker 不可用时给出警告但不阻断登记，使用者可在真实环境补建）
    volumes_ok = True
    for vol in (persona.storage.profile_volume, persona.storage.log_volume):
        try:
            rc, _, err = docker_ctl.volume_create(vol)
        except FileNotFoundError:
            print("警告：本机未找到 docker，跳过卷创建；请在目标环境手动执行："
                  f"docker volume create {vol}", file=sys.stderr)
            volumes_ok = False
            continue
        if rc != 0:
            print(f"警告：卷 {vol} 创建失败：{(err or '').strip()}", file=sys.stderr)
            volumes_ok = False
    if volumes_ok:
        info(f"已创建卷：{persona.storage.profile_volume}、{persona.storage.log_volume}")

    # 状态库登记 creating
    with StateDB() as db:
        db.add(persona_id=persona.meta.id, name=persona.meta.name,
               region=persona.region.detected_ip_region,
               state="creating",
               chrome_baseline=persona.evolution.baseline_chrome)
    if json_mode:
        # M2：外壳创建替身后需拿 id 走后续 start --json，结构化输出（属 --json 契约的合理扩展）
        print(json.dumps({"id": persona.meta.id, "name": persona.meta.name,
                          "region": persona.region.detected_ip_region,
                          "state": "creating"}, ensure_ascii=False))
        return 0
    info(f"替身 {persona.meta.id}（{persona.meta.name}）已登记，状态 creating。")
    info(f"下一步：tishen start {persona.meta.id}")
    return 0


# ---------------------------------------------------------------------------
# 生命周期命令（§7.2）
# ---------------------------------------------------------------------------

def cmd_start(args) -> int:
    # --json 模式下人类可读信息一律走 stderr，stdout 只留最终 JSON（外壳按行解析契约）
    json_mode = _json_mode(args)

    def info(msg: str) -> None:
        print(msg, file=sys.stderr if json_mode else sys.stdout)

    with StateDB() as db:
        rec = _get_record_or_exit(db, args.id)
        if rec["state"] == "destroyed":
            print(f"错误：替身 {args.id} 已销毁，不可启动。", file=sys.stderr)
            return 1
        persona = _load_persona_or_exit(args.id)
        try:
            exists = docker_ctl.container_exists(args.id)
        except FileNotFoundError:
            print("错误：本机未找到 docker，无法启动替身容器。", file=sys.stderr)
            return 1
        new_password = None
        if exists:
            rc, out, err = docker_ctl.start_container(args.id)
        else:
            # M2：创建容器时生成随机 neko 口令，经 -e 注入（persona-bake 第 7.5 步强制校验）
            new_password = docker_ctl.generate_neko_password()
            rc, out, err = docker_ctl.run_persona_container(
                persona, _image_tag(), _personas_dir(), new_password)
        if rc != 0:
            print(f"启动替身 {args.id}：失败（退出码 {rc}）。", file=sys.stderr)
            detail = (err or out).strip()
            if detail:
                print(f"docker 输出：{detail}", file=sys.stderr)
            return 1
        db.update_state(args.id, "active")

        # M2 连接信息：docker port 解析宿主 loopback 映射端口；口令记入状态库
        host_port = docker_ctl.container_host_port(args.id)
        db.update_connection(args.id, host_port=host_port,
                             neko_password=new_password)
        password = new_password if new_password is not None \
            else db.get(args.id).get("neko_password")
        embed_url = _embed_url(host_port, password)

        if json_mode:
            # 输出契约（SPEC-M2M3 §1.3）：{"id","state","host_port","embed_url","password"}
            payload = {"id": args.id, "state": "active", "host_port": host_port,
                       "embed_url": embed_url, "password": password}
            print(json.dumps(payload, ensure_ascii=False))
            return 0

        info(f"启动替身 {args.id}：成功。")
        info(f"替身 {args.id} 已上线（状态 active）。")
        if embed_url is not None:
            info(f"连接信息：neko 流服务 http://127.0.0.1:{host_port}（仅本机回环）")
            info(f"嵌入地址：{embed_url}")
        else:
            info("提示：未获取到 neko 连接信息（镜像可能不含 L5 流层，或该替身是 M1 遗留无口令记录）。")
        return 0


def cmd_stop(args) -> int:
    with StateDB() as db:
        _get_record_or_exit(db, args.id)
        try:
            rc, out, err = docker_ctl.stop_container(args.id)
        except FileNotFoundError:
            print("错误：本机未找到 docker。", file=sys.stderr)
            return 1
        if not _report_docker_result(f"停止替身 {args.id}", rc, out, err):
            return 1
        # M1 四态枚举无 stopped，停止后归并到 suspended（可 start 恢复）
        db.update_state(args.id, "suspended")
        print(f"替身 {args.id} 已停止（状态 suspended，可用 start 恢复）。")
        return 0


def cmd_suspend(args) -> int:
    with StateDB() as db:
        _get_record_or_exit(db, args.id)
        try:
            rc, out, err = docker_ctl.pause_container(args.id)
        except FileNotFoundError:
            print("错误：本机未找到 docker。", file=sys.stderr)
            return 1
        if not _report_docker_result(f"挂起替身 {args.id}", rc, out, err):
            return 1
        db.update_state(args.id, "suspended")
        print(f"替身 {args.id} 已挂起（状态 suspended）。")
        return 0


def cmd_resume(args) -> int:
    with StateDB() as db:
        _get_record_or_exit(db, args.id)
        try:
            rc, out, err = docker_ctl.unpause_container(args.id)
        except FileNotFoundError:
            print("错误：本机未找到 docker。", file=sys.stderr)
            return 1
        if not _report_docker_result(f"恢复替身 {args.id}", rc, out, err):
            return 1
        db.update_state(args.id, "active")
        print(f"替身 {args.id} 已恢复（状态 active）。")
        return 0


def cmd_reset(args) -> int:
    """reset = 信誉清零：交互式二次确认（须输入替身名），然后删容器+重建 profile 卷。"""
    with StateDB() as db:
        rec = _get_record_or_exit(db, args.id)
        persona = _load_persona_or_exit(args.id)

        print("=" * 60)
        print("信誉清零警告")
        print(f"即将重置替身 {args.id}（{persona.meta.name}）。")
        print("此操作将删除 profile 卷——登录态、Cookie、浏览历史等全部信誉资产")
        print("将永久清零，替身将以全新身份重新出发。此操作不可撤销。")
        print(f"如确认继续，请输入替身名「{persona.meta.name}」：")
        try:
            typed = input("> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n已取消重置。")
            return 1
        if typed != persona.meta.name:
            print("替身名不匹配，已取消重置。")
            return 1

        try:
            docker_ctl.rm_container(args.id, force=True)
            rc, out, err = docker_ctl.volume_rm(persona.storage.profile_volume)
            if rc != 0:
                print(f"警告：删除 profile 卷失败：{(err or out).strip()}", file=sys.stderr)
            rc, out, err = docker_ctl.volume_create(persona.storage.profile_volume)
        except FileNotFoundError:
            print("错误：本机未找到 docker，无法执行重置。", file=sys.stderr)
            return 1
        if not _report_docker_result(f"重建 profile 卷 {persona.storage.profile_volume}",
                                     rc, out, err):
            return 1
        db.update_state(args.id, "creating")
        print(f"替身 {args.id} 信誉已清零，状态 creating。")
        print(f"下一步：tishen start {args.id}（将以全新 profile 上线）")
        return 0


def cmd_destroy(args) -> int:
    """destroy：删容器 + 两个卷 + 状态置 destroyed。"""
    with StateDB() as db:
        rec = _get_record_or_exit(db, args.id)
        persona = _load_persona_or_exit(args.id)
        try:
            rc, out, err = docker_ctl.rm_container(args.id, force=True)
            if rc != 0 and "No such container" not in (err or ""):
                if not _report_docker_result("删除容器", rc, out, err):
                    return 1
            for vol in (persona.storage.profile_volume, persona.storage.log_volume):
                rc, out, err = docker_ctl.volume_rm(vol)
                if rc != 0:
                    print(f"警告：删除卷 {vol} 失败：{(err or out).strip()}",
                          file=sys.stderr)
        except FileNotFoundError:
            print("错误：本机未找到 docker，无法销毁容器与卷。", file=sys.stderr)
            return 1
        db.update_state(args.id, "destroyed")
        print(f"替身 {args.id} 已销毁（容器与两卷已删除，状态 destroyed）。")
        return 0


# ---------------------------------------------------------------------------
# list（§7）
# ---------------------------------------------------------------------------

def cmd_list(args) -> int:
    with StateDB() as db:
        rows = db.list_all(include_destroyed=args.all)
    if _json_mode(args):
        # M2 契约（SPEC-M2M3 §1.3）：输出替身数组（含 M2 连接信息列），供外壳消费
        print(json.dumps(rows, ensure_ascii=False))
        return 0
    if not rows:
        print("暂无替身。用 `tishen create` 创建第一个替身。")
        return 0
    header = f"{'ID':<22} {'名称':<12} {'属地':<5} {'状态':<10} {'Chrome 基线':<16} 更新时间"
    print(header)
    print("-" * len(header))
    for r in rows:
        print(f"{r['id']:<22} {r['name']:<12} {r['region']:<5} {r['state']:<10} "
              f"{r['chrome_baseline']:<16} {r['updated_at']}")
    return 0


# ---------------------------------------------------------------------------
# events（M2 新增，SPEC-M2M3 §1.3）：查询替身事件流（数据由 M3 观测模块落库）
# ---------------------------------------------------------------------------

def cmd_events(args) -> int:
    """tishen events <id> [--type T] [--limit N] [--json]。

    观测模块（tishen.observ）由 M3 提供（Coder D）；未安装时给出中文友好提示，
    不以 traceback 上屏（原则：观测缺失不阻塞主链路）。
    """
    try:
        from tishen.observ.query import query_events
    except ImportError:
        print("错误：观测模块未安装（M3）。事件查询由 M3 观测链路（tishen.observ）提供；"
              "该模块就绪后本子命令自动可用，替身本体运行不受影响。", file=sys.stderr)
        return 1
    with StateDB() as db:
        _get_record_or_exit(db, args.id)
    # 事件库权威路径：M3 daemon 在容器内写 /persona/logs/events/events.db（即替身 log 卷）。
    # 宿主侧经 docker 卷目录直读；卷路径不存在时回退 $TISHEN_HOME/events/<id>.db 开发约定。
    # （主代理合并 m2/m3 时对齐：Coder C 原约定仅宿主侧路径，与 daemon 容器内产出路径不一致。）
    events_db = None
    persona_yaml = tishen_home() / "personas" / f"{args.id}.yaml"
    if persona_yaml.exists():
        try:
            log_volume = load_persona(persona_yaml).storage.log_volume
            candidate = Path("/var/lib/docker/volumes") / log_volume / "_data" / "events" / "events.db"
            if candidate.exists():
                events_db = str(candidate)
        except Exception:
            events_db = None
    if events_db is None:
        events_db = str(tishen_home() / "events" / f"{args.id}.db")
    events = query_events(events_db, event_type=args.type, limit=args.limit)
    if _json_mode(args):
        print(json.dumps(events, ensure_ascii=False))
        return 0
    if not events:
        print(f"替身 {args.id} 暂无事件记录。")
        return 0
    print(f"替身 {args.id} 最近 {len(events)} 条事件：")
    for e in events:
        # 事件字段以 M3 契约为准（Coder D 实现），这里逐条 JSON 打印避免对字段假设
        print("  " + json.dumps(e, ensure_ascii=False))
    return 0


# ---------------------------------------------------------------------------
# lint（§7）
# ---------------------------------------------------------------------------

def cmd_lint(args) -> int:
    path = Path(args.persona_yaml)
    if not path.exists():
        print(f"错误：文件不存在：{path}", file=sys.stderr)
        return 2
    try:
        persona = load_persona(path)
    except ValueError as e:
        print(f"错误：persona 文件损坏：{e}", file=sys.stderr)
        return 2

    has_error = False
    struct_errors = validate_structure(persona)
    if struct_errors:
        has_error = True
        print("结构错误（类型/枚举/格式）：")
        for msg in struct_errors:
            print(f"  [STRUCT] {msg}")

    # 属地锚取 persona 自报的 detected_ip_region；current stable 走环境变量/默认值
    ctx = LintContext(current_stable_chrome=_current_stable_chrome(),
                      detected_ip_region=persona.region.detected_ip_region)
    lint_errors = lint_persona(persona, ctx)
    if lint_errors:
        has_error = True
        print("门禁错误（V1–V10）：")
        print(f"  {'规则':<10} {'字段':<38} 说明")
        print("  " + "-" * 78)
        for e in lint_errors:
            print(f"  {e.code:<10} {e.field:<38} {e.message}")

    if not has_error:
        print(f"{path}：通过全部结构校验与门禁规则（V1–V10）。")
        return 0
    return 1


# ---------------------------------------------------------------------------
# doctor（§7.5）
# ---------------------------------------------------------------------------

class _Doctor:
    """逐项 [OK]/[FAIL] 输出，FAIL 附修复建议；failed 计数供退出码使用。

    M2：检查项同步记入 items，--json 模式输出结构化结果供外壳首启引导消费
    （外壳契约：一切 docker 操作经 CLI --json，严禁直接调 docker）。
    """

    def __init__(self, json_mode: bool = False) -> None:
        self.failed = 0
        self.items: list[dict] = []
        self._json_mode = json_mode

    def check(self, ok: bool, item: str, detail: str = "", fix: str = "") -> None:
        self.items.append({"item": item, "ok": ok, "detail": detail, "fix": fix})
        if not ok:
            self.failed += 1
        if self._json_mode:
            return  # JSON 模式只收集，最终统一输出
        if ok:
            print(f"[OK]   {item}" + (f"（{detail}）" if detail else ""))
        else:
            print(f"[FAIL] {item}" + (f"（{detail}）" if detail else ""))
            if fix:
                print(f"       修复建议：{fix}")


def _doctor_header(doc: _Doctor, title: str) -> None:
    """段落标题；--json 模式走 stderr 避免污染 stdout 的结构化输出。"""
    print(title, file=sys.stderr if doc._json_mode else sys.stdout)


def _doctor_global(doc: _Doctor) -> None:
    """全局检查：docker 可用性、GPU 透传后端、TISHEN_HOME 结构。"""
    _doctor_header(doc, "── 全局环境检查 ──")
    try:
        ok, info = docker_ctl.docker_available()
    except FileNotFoundError:
        ok, info = False, "未找到 docker 命令"
    doc.check(ok, "docker 守护进程可用", detail=info,
              fix="安装并启动 docker（如 apt install docker.io 并 systemctl start docker）；"
                  "确认当前用户在 docker 组内")
    gpu_backend = docker_ctl.detect_gpu_backend()
    gpu_detail = {
        "wsl": "WSL2 /dev/dxg + /usr/lib/wsl + /mnt/wslg",
        "dri": "Linux /dev/dri",
        "missing": "未找到 /dev/dri 或完整 WSL2 GPU 三件套",
    }[gpu_backend]
    doc.check(gpu_backend != "missing", "GPU 透传设备可用", detail=gpu_detail,
              fix="Linux 请确认 /dev/dri；Windows WSL2 请确认 /dev/dxg、"
                  "/usr/lib/wsl、/mnt/wslg 三者同时存在")
    home = tishen_home()
    doc.check(home.is_dir(), f"TISHEN_HOME 目录存在", detail=str(home),
              fix=f"执行 mkdir -p {home}/personas，或先运行一次 `tishen create`")
    doc.check((home / "personas").is_dir(), "personas 目录存在",
              detail=str(home / "personas"),
              fix=f"执行 mkdir -p {home}/personas，或运行 `tishen create`")
    doc.check((home / "state.db").exists(), "状态库 state.db 存在",
              detail=str(home / "state.db"),
              fix="运行任意 tishen 命令（如 `tishen list`）会自动初始化状态库")


def _doctor_persona(doc: _Doctor, persona_id: str) -> None:
    """替身级检查：登记在否、yaml 过 linter、容器在否、卷在否、shm-size。"""
    _doctor_header(doc, f"── 替身 {persona_id} 检查 ──")
    with StateDB() as db:
        rec = db.get(persona_id)
    doc.check(rec is not None, "替身已登记到状态库",
              fix="该替身未登记；若为手工放置的 yaml，请用 `tishen create` 重新创建")

    yaml_path = _personas_dir() / f"{persona_id}.yaml"
    persona = None
    if yaml_path.exists():
        try:
            persona = load_persona(yaml_path)
        except ValueError as e:
            doc.check(False, "persona.yaml 可解析", detail=str(e),
                      fix=f"修复 YAML 结构后重试，或用 `tishen lint {yaml_path}` 查看详情")
    doc.check(persona is not None, "persona.yaml 存在且可解析", detail=str(yaml_path),
              fix=f"从备份恢复或用 `tishen create` 重建；缺失时容器无法烘焙启动")

    if persona is not None:
        struct_errors = validate_structure(persona)
        ctx = LintContext(current_stable_chrome=_current_stable_chrome(),
                          detected_ip_region=persona.region.detected_ip_region)
        lint_errors = lint_persona(persona, ctx)
        doc.check(not struct_errors and not lint_errors,
                  "persona.yaml 通过出场门禁（结构 + V1–V10）",
                  detail=f"结构错误 {len(struct_errors)} 条，门禁错误 {len(lint_errors)} 条",
                  fix=f"运行 `tishen lint {yaml_path}` 查看逐条错误并按提示修正")

    try:
        exists = docker_ctl.container_exists(persona_id)
    except FileNotFoundError:
        doc.check(False, "docker 可用", fix="安装并启动 docker 后重试")
        return
    doc.check(exists, f"容器 {docker_ctl.container_name(persona_id)} 存在",
              fix=f"运行 `tishen start {persona_id}` 创建并启动容器")
    if persona is not None:
        for vol, label in ((persona.storage.profile_volume, "profile 卷"),
                           (persona.storage.log_volume, "log 卷")):
            doc.check(docker_ctl.volume_exists(vol), f"{label} {vol} 存在",
                      fix=f"执行 docker volume create {vol} 补建；"
                          f"profile 卷缺失意味着信誉资产已丢失" if "profile" in label
                          else f"执行 docker volume create {vol} 补建")
    if exists:
        shm = docker_ctl.container_shm_size(persona_id)
        doc.check(shm is not None and shm >= docker_ctl.SHM_SIZE_BYTES,
                  "容器 shm-size ≥ 2GB（Chrome 不崩的基线）",
                  detail=f"实测 {shm} 字节" if shm is not None else "读取失败",
                  fix=f"销毁后用 `tishen start {persona_id}` 重建容器"
                      f"（编排层已固化 --shm-size={docker_ctl.SHM_SIZE}）")


def cmd_doctor(args) -> int:
    json_mode = _json_mode(args)
    doc = _Doctor(json_mode=json_mode)
    if args.id:
        _doctor_persona(doc, args.id)
    else:
        _doctor_global(doc)
    if json_mode:
        print(json.dumps({"failed": doc.failed, "checks": doc.items},
                         ensure_ascii=False))
        return 1 if doc.failed else 0
    print()
    if doc.failed:
        print(f"自检完成：{doc.failed} 项未通过，请按上方修复建议处理。")
        return 1
    print("自检完成：全部通过。")
    return 0


# ---------------------------------------------------------------------------
# pull（M2 新增）：外壳首启引导第 3 步拉取平台镜像（一切 docker 操作经 CLI）
# ---------------------------------------------------------------------------

def cmd_pull(args) -> int:
    """tishen pull [--json]：拉取替身平台镜像；已存在则跳过（幂等）。"""
    tag = _image_tag()
    json_mode = _json_mode(args)

    def info(msg: str) -> None:
        print(msg, file=sys.stderr if json_mode else sys.stdout)

    try:
        if docker_ctl.image_exists(tag):
            info(f"镜像 {tag} 已存在，跳过拉取。")
            if json_mode:
                print(json.dumps({"image": tag, "pulled": False,
                                  "present": True}, ensure_ascii=False))
            return 0
        info(f"正在拉取镜像 {tag}（体积较大，请耐心等待）……")
        rc, out, err = docker_ctl.pull_image(tag)
    except FileNotFoundError:
        print("错误：本机未找到 docker，无法拉取镜像。", file=sys.stderr)
        return 1
    if rc != 0:
        print(f"错误：镜像拉取失败（退出码 {rc}）：{(err or out).strip()}",
              file=sys.stderr)
        print("提示：检查网络后重试；若磁盘不足请清理后重试。", file=sys.stderr)
        return 1
    info(f"镜像 {tag} 拉取完成。")
    if json_mode:
        print(json.dumps({"image": tag, "pulled": True, "present": True},
                         ensure_ascii=False))
    return 0


# ---------------------------------------------------------------------------
# evolve（EVO-2，演化方案 §四）：演化状态查看 + 时机门禁检查（预览）
# ---------------------------------------------------------------------------

def cmd_evolve(args) -> int:
    """tishen evolve <id> --pack <drift_pack.json> [--execute]。

    默认（预览）：只打印该 persona 当前演化状态（current/schedule/history 计数）
    并对指定 drift pack 跑时机门禁纯函数 check_evolve_gate（§四步骤 0/2）——
    不执行真实演化，不写任何状态。
    --execute（EVO-3）：调 run_evolve_sequence 执行门禁序列骨架（§四 0–8），
    打印逐步结果；真机步骤 stub 未接入时记「skipped（真机接入后激活）」并
    合法滞留；仅 outcome=evolved 时把 current_chrome/history 写回 persona.yaml。
    """
    from .evolution import check_evolve_gate, validate_drift_pack
    from .persona import count_rollbacks

    persona = _load_persona_or_exit(args.id)
    ev = persona.evolution

    print(f"替身 {args.id} 当前演化状态（演化方案 §二）：")
    print(f"  基线版本 baseline_chrome : {ev.baseline_chrome}")
    print(f"  当前版本 current_chrome  : {ev.current_chrome}")
    print(f"  发布通道 channel         : {ev.channel}")
    sch = ev.schedule
    print(f"  时机画像 delay_model     : {sch.delay_model}")
    print(f"  时机闸门 not_before      : {sch.next_upgrade_not_before or '（未设置）'}")
    print(f"  演化履历 history         : {len(ev.history)} 条")
    rollbacks = count_rollbacks(ev)
    if rollbacks:
        print(f"  警告：history 含 {rollbacks} 条 rollback=true 回滚记录"
              "（方案 §七.3：回滚违反单调增，仅允许 24h 内且诚实留痕，请人工复核）")

    # drift pack 加载与结构校验（§三）
    pack_path = Path(args.pack)
    if not pack_path.exists():
        print(f"错误：drift pack 文件不存在：{pack_path}", file=sys.stderr)
        return 2
    try:
        pack = json.loads(pack_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        print(f"错误：drift pack 不是合法 JSON：{e}", file=sys.stderr)
        return 2
    pack_errors = validate_drift_pack(pack)
    if pack_errors:
        print(f"drift pack 结构校验未通过（{len(pack_errors)} 条）：")
        for msg in pack_errors:
            print(f"  [PACK] {msg}")
        return 1

    # --execute（EVO-3）：执行演化门禁序列（§四 0–8 骨架）；预览为默认路径（不变）
    if getattr(args, "execute", False):
        return _evolve_execute(persona, pack)

    # 时机门禁（预览）：纯函数，今日日期取自本机时钟
    print(f"演化门禁检查（预览）——drift pack {pack['from']} → {pack['to']}：")
    ok, reasons = check_evolve_gate(persona, pack, today=date.today())
    if ok:
        print("  [放行] 四条时机断言全部通过（时机闸门 / 单调增 / 不超前发布日 / OS×版本组合）。")
        print("  说明：本命令只做门禁预览，不执行真实演化；门禁序列编排（§四步骤 1–8）属 EVO-3。")
        return 0
    print(f"  [拒绝] {len(reasons)} 条断言未通过：")
    for r in reasons:
        print(f"    - {r}")
    print("  说明：门禁拒绝=合法滞留当前版本（§四步骤 7），本命令不执行真实演化。")
    return 1


def _evolve_execute(persona, pack: dict) -> int:
    """tishen evolve --execute：跑 EVO-3 门禁序列骨架并打印逐步结果。

    真机步骤（R-Gate 实跑/镜像升级/外部抽样/采集）全部以 EvolveHooks 默认值
    None 注入 → 首个真机依赖步骤记「skipped（真机接入后激活）」且序列合法
    滞留（held，§四-7：绝不带病推进）。outcome=evolved 时把推进后的
    current_chrome 与 history 落账条目 dump 回 persona.yaml（§四-8）。
    """
    from .evolve_seq import EvolveHooks, run_evolve_sequence

    print(f"演化门禁序列执行（§四 0–8）——drift pack {pack['from']} → {pack['to']}：")
    result = run_evolve_sequence(persona, pack, hooks=EvolveHooks(), today=date.today())
    for s in result["steps"]:
        if s["skipped"]:
            mark = "skipped（真机接入后激活）"
        elif s["ok"]:
            mark = "OK"
        else:
            mark = "拒绝"
        print(f"  [{mark}] {s['step']}：{s['detail']}")

    outcome = result["outcome"]
    if outcome == "evolved":
        dump_persona(persona, _personas_dir() / f"{persona.meta.id}.yaml")
        print(f"  [结果] evolved：演化完成，current_chrome 推进至 {pack['to']}，"
              "履历已落 history（§四-8）。")
        return 0
    if outcome == "held":
        print("  [结果] held：合法滞留当前版本（§四-7：任一门禁失败→合法滞留+告警，"
              "不许带病演化）。")
    else:
        print("  [结果] rejected：演化结果未过硬断言（§四-4/5），拒绝落账，"
              "履历不写 history。")
    return 1


# ---------------------------------------------------------------------------
# 入口
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    # M2 全局 --json：经 parents 挂到需要的子命令上（list/start/events），
    # 顶层也注册一份，使 `tishen --json list` 与 `tishen list --json` 两种写法都成立。
    # 注意：parents 里的默认值必须 SUPPRESS，否则子命令解析时会把顶层已置位的 True 覆盖回 False。
    json_parent = argparse.ArgumentParser(add_help=False)
    json_parent.add_argument("--json", action="store_true", default=argparse.SUPPRESS,
                             help="以 JSON 输出（供外壳等程序消费）")

    parser = argparse.ArgumentParser(
        prog="tishen", description="替身（Tishen）编排命令行：创建/生命周期/门禁/自检")
    parser.add_argument("--json", action="store_true",
                        help="以 JSON 输出（仅 list/start/events 支持，可放子命令后）")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("create", parents=[json_parent],
                       help="创建替身（采样→过滤→门禁→落盘→建卷→登记）")
    p.add_argument("--region", choices=REGION_CHOICES, default="auto",
                   help="属地偏好，默认 auto（跟随实测 IP 属地）")
    p.add_argument("--name", default=None, help="替身名（1–32 字符）")
    p.add_argument("--seed", type=int, default=None, help="采样随机种子（仅测试复现用）")
    p.set_defaults(func=cmd_create)

    for name, help_text in (
            ("start", "启动替身（容器不存在则 docker run 创建；--json 输出连接信息）"),
            ("stop", "停止替身容器"),
            ("suspend", "挂起替身（docker pause）"),
            ("resume", "恢复替身（docker unpause）"),
            ("reset", "信誉清零：二次确认后重建 profile 卷"),
            ("destroy", "销毁替身：删容器 + 两卷 + 状态置 destroyed")):
        # start 支持 --json（SPEC-M2M3 §1.3 输出契约）
        p = sub.add_parser(name, help=help_text,
                           parents=[json_parent] if name == "start" else [])
        p.add_argument("id", help="替身 ID（p_ 开头）")
        p.set_defaults(func={"start": cmd_start, "stop": cmd_stop,
                             "suspend": cmd_suspend, "resume": cmd_resume,
                             "reset": cmd_reset, "destroy": cmd_destroy}[name])

    p = sub.add_parser("list", help="列出替身", parents=[json_parent])
    p.add_argument("--all", action="store_true", help="包含已销毁的替身")
    p.set_defaults(func=cmd_list)

    p = sub.add_parser("events", parents=[json_parent],
                       help="查询替身事件流（M3 观测模块提供数据；未安装时给出提示）")
    p.add_argument("id", help="替身 ID（p_ 开头）")
    p.add_argument("--type", default=None, help="按事件类型过滤（枚举见 M3 方案 §3.2）")
    p.add_argument("--limit", type=int, default=50, help="最多返回条数（默认 50）")
    p.set_defaults(func=cmd_events)

    p = sub.add_parser("lint", help="对任意 persona.yaml 跑结构校验 + 门禁 V1–V10")
    p.add_argument("persona_yaml", help="persona.yaml 路径")
    p.set_defaults(func=cmd_lint)

    p = sub.add_parser("doctor", parents=[json_parent],
                       help="自检：无 id 查全局，有 id 查指定替身（--json 供外壳消费）")
    p.add_argument("id", nargs="?", default=None, help="替身 ID（可选）")
    p.set_defaults(func=cmd_doctor)

    p = sub.add_parser("pull", parents=[json_parent],
                       help="拉取替身平台镜像（已存在则跳过；M2 首启引导用）")
    p.set_defaults(func=cmd_pull)

    p = sub.add_parser("evolve",
                       help="演化门禁检查（预览）：打印演化状态 + 对 drift pack 跑时机门禁，不执行演化")
    p.add_argument("id", help="替身 ID（p_ 开头）")
    p.add_argument("--pack", required=True,
                   help="drift pack JSON 路径（演化方案 §三数据件）")
    p.add_argument("--execute", action="store_true",
                   help="执行演化门禁序列（EVO-3 §四 0–8 骨架；真机步骤 stub 未接入则记 skipped 并合法滞留）")
    p.set_defaults(func=cmd_evolve)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
