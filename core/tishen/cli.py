"""tishen 命令行（SPEC §7，argparse）。

子命令：
    tishen create [--region auto|CN|HK|TW|JP|US|GB|DE] [--name 名] [--seed N]
    tishen start|stop|suspend|resume|reset|destroy <id>
    tishen list
    tishen lint <persona.yaml>
    tishen doctor [<id>]
"""

from __future__ import annotations

import argparse
import os
import sys
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


# ---------------------------------------------------------------------------
# create（§7.1）
# ---------------------------------------------------------------------------

def cmd_create(args) -> int:
    name = args.name or "默认替身"
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
    print(f"已生成 persona：{yaml_path}")
    if persona.meta.note:
        print(f"注意：{persona.meta.note}")

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
        print(f"已创建卷：{persona.storage.profile_volume}、{persona.storage.log_volume}")

    # 状态库登记 creating
    with StateDB() as db:
        db.add(persona_id=persona.meta.id, name=persona.meta.name,
               region=persona.region.detected_ip_region,
               state="creating",
               chrome_baseline=persona.evolution.baseline_chrome)
    print(f"替身 {persona.meta.id}（{persona.meta.name}）已登记，状态 creating。")
    print(f"下一步：tishen start {persona.meta.id}")
    return 0


# ---------------------------------------------------------------------------
# 生命周期命令（§7.2）
# ---------------------------------------------------------------------------

def cmd_start(args) -> int:
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
        if exists:
            rc, out, err = docker_ctl.start_container(args.id)
        else:
            rc, out, err = docker_ctl.run_persona_container(
                persona, _image_tag(), _personas_dir())
        if not _report_docker_result(f"启动替身 {args.id}", rc, out, err):
            return 1
        db.update_state(args.id, "active")
        print(f"替身 {args.id} 已上线（状态 active）。")
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
    """逐项 [OK]/[FAIL] 输出，FAIL 附修复建议；failed 计数供退出码使用。"""

    def __init__(self) -> None:
        self.failed = 0

    def check(self, ok: bool, item: str, detail: str = "", fix: str = "") -> None:
        if ok:
            print(f"[OK]   {item}" + (f"（{detail}）" if detail else ""))
        else:
            self.failed += 1
            print(f"[FAIL] {item}" + (f"（{detail}）" if detail else ""))
            if fix:
                print(f"       修复建议：{fix}")


def _doctor_global(doc: _Doctor) -> None:
    """全局检查：docker 可用性、/dev/dri、TISHEN_HOME 结构。"""
    print("── 全局环境检查 ──")
    try:
        ok, info = docker_ctl.docker_available()
    except FileNotFoundError:
        ok, info = False, "未找到 docker 命令"
    doc.check(ok, "docker 守护进程可用", detail=info,
              fix="安装并启动 docker（如 apt install docker.io 并 systemctl start docker）；"
                  "确认当前用户在 docker 组内")
    doc.check(Path("/dev/dri").exists(), "/dev/dri 存在（GPU 透传设备）",
              fix="确认宿主机 GPU 驱动已安装且暴露 DRI 设备；无 GPU 环境无法运行替身容器")
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
    print(f"── 替身 {persona_id} 检查 ──")
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
    doc = _Doctor()
    if args.id:
        _doctor_persona(doc, args.id)
    else:
        _doctor_global(doc)
    print()
    if doc.failed:
        print(f"自检完成：{doc.failed} 项未通过，请按上方修复建议处理。")
        return 1
    print("自检完成：全部通过。")
    return 0


# ---------------------------------------------------------------------------
# 入口
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tishen", description="替身（Tishen）编排命令行：创建/生命周期/门禁/自检")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("create", help="创建替身（采样→过滤→门禁→落盘→建卷→登记）")
    p.add_argument("--region", choices=REGION_CHOICES, default="auto",
                   help="属地偏好，默认 auto（跟随实测 IP 属地）")
    p.add_argument("--name", default=None, help="替身名（1–32 字符）")
    p.add_argument("--seed", type=int, default=None, help="采样随机种子（仅测试复现用）")
    p.set_defaults(func=cmd_create)

    for name, help_text in (
            ("start", "启动替身（容器不存在则 docker run 创建）"),
            ("stop", "停止替身容器"),
            ("suspend", "挂起替身（docker pause）"),
            ("resume", "恢复替身（docker unpause）"),
            ("reset", "信誉清零：二次确认后重建 profile 卷"),
            ("destroy", "销毁替身：删容器 + 两卷 + 状态置 destroyed")):
        p = sub.add_parser(name, help=help_text)
        p.add_argument("id", help="替身 ID（p_ 开头）")
        p.set_defaults(func={"start": cmd_start, "stop": cmd_stop,
                             "suspend": cmd_suspend, "resume": cmd_resume,
                             "reset": cmd_reset, "destroy": cmd_destroy}[name])

    p = sub.add_parser("list", help="列出替身")
    p.add_argument("--all", action="store_true", help="包含已销毁的替身")
    p.set_defaults(func=cmd_list)

    p = sub.add_parser("lint", help="对任意 persona.yaml 跑结构校验 + 门禁 V1–V10")
    p.add_argument("persona_yaml", help="persona.yaml 路径")
    p.set_defaults(func=cmd_lint)

    p = sub.add_parser("doctor", help="自检：无 id 查全局，有 id 查指定替身")
    p.add_argument("id", nargs="?", default=None, help="替身 ID（可选）")
    p.set_defaults(func=cmd_doctor)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
