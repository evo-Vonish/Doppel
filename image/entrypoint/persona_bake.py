#!/usr/bin/env python3
"""替身容器 persona 烘焙器（SPEC §6 十步契约 + M2 流层编排，SPEC-M2M3 §1.2）。

容器启动时按序执行，把 /persona/persona.yaml 声明的环境真实烘焙进运行时：
门禁复验 → 时区 → locale → 字体激活 → 显示 → 输入法 → 观测 → 7.5 neko 流服务 → Chrome 启动行 → 禁项自检 → SIGTERM 收尾。

M2 进程启动顺序固定（M2 方案 §二.2，persona-bake 统一收口编排）：
    Xorg(dummy) → xrandr 按 persona 设分辨率 → PulseAudio → fcitx5 → neko server → Chrome
neko 只负责抓屏推流与输入回注，不接管 Chrome 生命周期（避免两套进程管理权打架）。

输入：/persona/persona.yaml（只读挂载）
环境变量：GPU_VENDOR（mesa|nvidia，默认 mesa）、MONITOR_PCAP（0|1，默认 1）、
          NEKO_PASSWORD（neko 流服务登录口令，缺失则拒绝启动——口令只经环境变量注入，不落盘）
参数：--dry-run 冒烟模式——跑完第 1–7.5 步后打印将要执行的 neko/Chrome 启动计划并退出 0
"""

import argparse
import os
import re
import shlex
import signal
import subprocess
import sys
import time
from pathlib import Path

# tishen core 包由镜像层 pip 安装（与 Coder B 的接口点，签名按 SPEC §3.1/§2 固定）
try:
    from tishen.persona import load, validate_structure
    from tishen.linter import lint_persona, LintContext
except ImportError as exc:  # 镜像构建异常时给出中文可读错误而非 traceback
    print(f"[persona_bake] 错误：tishen core 包未安装或接口缺失（{exc}），请检查镜像 tishen 层", file=sys.stderr)
    sys.exit(3)

# ── 路径与环境常量（镜像内固化布局，SPEC §5/§6）───────────────────────────
PERSONA_PATH = "/persona/persona.yaml"          # 只读挂载的 persona 声明
CHROME_VERSION_FILE = "/etc/tishen/chrome_version"  # 镜像构建期落档的精确 Chrome 版本
FONTCONFIG_TEMPLATE = "/opt/tishen/config/fontconfig-pack.conf.template"
OBSERVABILITY_DAEMON = "/opt/tishen/scripts/observability-daemon.sh"
XORG_CONFIG = "/opt/tishen/config/xorg-dummy.conf"
NEKO_BIN = "/opt/neko/neko"                     # L5 流层安装的 neko v2 server 二进制
DISPLAY_ID = ":0"                               # 虚拟显示器编号
X_READY_TIMEOUT = 15                            # 等待 X 就绪秒数

# 后台子进程登记表：名称 → Popen，供第 10 步 SIGTERM 收尾按序终止
_CHILDREN: dict[str, subprocess.Popen] = {}
# 本进程是否为 dry-run（供 run_cmd 打计划而非执行）
_DRY_RUN = False
# M5 启动计时基准（SPEC-M5 §5）：脚本入口 time.monotonic()，main() 开头赋值
_BOOT_T0: float | None = None


def log(msg: str) -> None:
    """中文运行日志（stdout）。"""
    print(f"[persona_bake] {msg}", flush=True)


def _boot_mark(seg: str) -> None:
    """M5 BOOT_MARK 打点（SPEC-M5 §5）：十步各段完成处向 stderr 打累计毫秒。

    走 stderr 避免污染 --dry-run 的 stdout 契约；段名枚举与顺序：
    entry → lint_recheck → timezone → locale → fonts → xrandr → fcitx5 → observ → neko → chrome_launch。
    """
    if _BOOT_T0 is None:
        return
    ms = int((time.monotonic() - _BOOT_T0) * 1000)
    print(f"[BOOT_MARK] segment={seg} elapsed_ms={ms}", file=sys.stderr, flush=True)


def fail(msg: str, code: int = 1) -> "None":
    """每步失败即非零退出并输出中文错误（契约总纪律）。"""
    print(f"[persona_bake] 错误：{msg}", file=sys.stderr)
    sys.exit(code)


def run_cmd(argv: list[str], desc: str, check: bool = True) -> subprocess.CompletedProcess:
    """执行外部命令；dry-run 下只打印计划不执行（冒烟环境无 X/无 capability）。"""
    line = " ".join(shlex.quote(a) for a in argv)
    if _DRY_RUN:
        log(f"[dry-run] 将执行：{line}（{desc}）")
        return subprocess.CompletedProcess(argv, 0, "", "")
    proc = subprocess.run(argv, capture_output=True, text=True)
    if check and proc.returncode != 0:
        fail(f"{desc}失败（rc={proc.returncode}）：{proc.stderr.strip() or proc.stdout.strip()}")
    return proc


def spawn(name: str, argv: list[str], desc: str) -> None:
    """后台拉起长驻进程并登记；dry-run 下只打印计划。"""
    line = " ".join(shlex.quote(a) for a in argv)
    if _DRY_RUN:
        log(f"[dry-run] 将后台启动：{line}（{desc}）")
        return
    try:
        _CHILDREN[name] = subprocess.Popen(argv)
    except OSError as exc:
        fail(f"{desc}启动失败：{exc}")
    log(f"{desc}已启动（pid={_CHILDREN[name].pid}）")


# ── 字体包激活块（模板占位符 @FONT_PACK@ 的注入内容）──────────────────────
# 与 image/config/fontconfig-pack.conf.template 头部注释保持同步；
# 包集合白名单见 SPEC §3.3 V7（os.family=linux 仅这两包）。
PACK_SNIPPETS = {
    # linux-noto-standard：Noto 系为西文主族，Noto CJK + 文泉驿微米黑作中文兜底
    "linux-noto-standard": """  <!-- 激活包 linux-noto-standard：Noto Sans/Serif/Mono 主族，CJK 由 Noto Sans CJK SC 与文泉驿微米黑兜底 -->
  <alias><family>sans-serif</family><prefer><family>Noto Sans</family><family>Noto Sans CJK SC</family><family>WenQuanYi Micro Hei</family><family>DejaVu Sans</family></prefer></alias>
  <alias><family>serif</family><prefer><family>Noto Serif</family><family>Noto Serif CJK SC</family><family>DejaVu Serif</family></prefer></alias>
  <alias><family>monospace</family><prefer><family>Noto Sans Mono</family><family>Noto Sans Mono CJK SC</family><family>DejaVu Sans Mono</family></prefer></alias>""",
    # linux-liberation-dejavu：Liberation 三族（度量兼容 Arial/Times/Courier）+ DejaVu 兜底
    "linux-liberation-dejavu": """  <!-- 激活包 linux-liberation-dejavu：Liberation Sans/Serif/Mono 主族，DejaVu 三族兜底 -->
  <alias><family>sans-serif</family><prefer><family>Liberation Sans</family><family>DejaVu Sans</family></prefer></alias>
  <alias><family>serif</family><prefer><family>Liberation Serif</family><family>DejaVu Serif</family></prefer></alias>
  <alias><family>monospace</family><prefer><family>Liberation Mono</family><family>DejaVu Sans Mono</family></prefer></alias>""",
}

# extras 附加激活块（模板占位符 @EXTRAS@ 的注入内容；元素白名单见 SPEC §2 fonts.extras）
EXTRAS_SNIPPETS = {
    "cjk": """  <!-- extras=cjk：为三大通用族显式追加 CJK 兜底族，保证中文页面不缺字形 -->
  <alias><family>sans-serif</family><prefer><family>Noto Sans CJK SC</family><family>WenQuanYi Micro Hei</family></prefer></alias>
  <alias><family>serif</family><prefer><family>Noto Serif CJK SC</family></prefer></alias>""",
}


# ── 第 1 步：容器内门禁复验 ────────────────────────────────────────────────
def step1_gate():
    """加载 persona.yaml，先 validate_structure 再 lint_persona；不过则拒绝启动。"""
    if not Path(PERSONA_PATH).is_file():
        fail(f"persona 声明文件不存在：{PERSONA_PATH}（应以只读卷挂载）", 2)
    try:
        persona = load(PERSONA_PATH)
    except Exception as exc:
        fail(f"persona.yaml 解析失败：{exc}", 2)

    struct_errors = validate_structure(persona)
    if struct_errors:
        for e in struct_errors:
            print(f"[persona_bake] 结构校验错误：{e}", file=sys.stderr)
        fail("persona.yaml 未通过 schema 结构校验，拒绝启动", 2)

    # 当前 stable 版本读镜像落档文件（linter V6 的版本锚）
    try:
        current_stable = Path(CHROME_VERSION_FILE).read_text(encoding="utf-8").strip()
    except OSError as exc:
        fail(f"读取 Chrome 版本落档失败：{CHROME_VERSION_FILE}（{exc}）", 2)
    if not current_stable:
        fail(f"Chrome 版本落档为空：{CHROME_VERSION_FILE}", 2)

    # 容器门禁必须以 persona 声明的创建时属地为锚——None 会把 V1 属地族检查整个跳过，
    # 让"属地 CN 却配纽约时区"这类矛盾替身直接漏进运行时（主代理集成测试发现并修复）。
    ctx = LintContext(current_stable_chrome=current_stable,
                      detected_ip_region=persona.region.detected_ip_region)
    lint_errors = lint_persona(persona, ctx)
    if lint_errors:
        for e in lint_errors:
            print(f"[persona_bake] 门禁拦截 [{e.code}] {e.field}：{e.message}", file=sys.stderr)
        fail(f"persona 未通过出场门禁复验（{len(lint_errors)} 条矛盾），拒绝启动", 2)

    log(f"门禁复验通过（镜像 Chrome stable={current_stable}）")
    return persona


# ── 第 2 步：时区 ─────────────────────────────────────────────────────────
def step2_timezone(persona) -> None:
    tz = persona.region.timezone
    zoneinfo = Path("/usr/share/zoneinfo") / tz
    if not zoneinfo.is_file():
        fail(f"时区数据库中不存在 {tz}（{zoneinfo}）")
    if _DRY_RUN:
        log(f"[dry-run] 将执行：ln -sf {zoneinfo} /etc/localtime；写 /etc/timezone={tz}")
    else:
        try:
            # ln -sf 语义：先删旧链接再建，避免 symlink 指向已存在时报错
            localtime = Path("/etc/localtime")
            if localtime.exists() or localtime.is_symlink():
                localtime.unlink()
            localtime.symlink_to(zoneinfo)
            Path("/etc/timezone").write_text(tz + "\n", encoding="utf-8")
        except OSError as exc:
            fail(f"设置时区失败：{exc}")
    os.environ["TZ"] = tz
    log(f"时区已烘焙：{tz}")


# ── 第 3 步：locale ───────────────────────────────────────────────────────
def step3_locale(persona) -> None:
    locale = persona.region.locale
    languages = persona.region.languages
    os.environ["LANG"] = f"{locale}.UTF-8"
    os.environ["LC_ALL"] = f"{locale}.UTF-8"
    # LANGUAGE 依 languages 列表拼冒号串（Accept-Language 顺序即指纹，保持同序）
    os.environ["LANGUAGE"] = ":".join(languages)
    log(f"locale 已烘焙：LANG={os.environ['LANG']}，LANGUAGE={os.environ['LANGUAGE']}")


# ── 第 4 步：字体激活 ─────────────────────────────────────────────────────
def step4_fonts(persona) -> None:
    pack = persona.fonts.pack
    extras = persona.fonts.extras or []
    if pack not in PACK_SNIPPETS:
        fail(f"未知字体包 {pack}（内置包：{sorted(PACK_SNIPPETS)}）")
    blocks = [PACK_SNIPPETS[pack]]
    extras_blocks = []
    for item in extras:
        if item not in EXTRAS_SNIPPETS:
            fail(f"未知字体附加项 {item}（可选：{sorted(EXTRAS_SNIPPETS)}）")
        extras_blocks.append(EXTRAS_SNIPPETS[item])

    try:
        template = Path(FONTCONFIG_TEMPLATE).read_text(encoding="utf-8")
    except OSError as exc:
        fail(f"读取字体模板失败：{FONTCONFIG_TEMPLATE}（{exc}）")
    # 只替换「独占一行」的占位符，避免误替换模板头部注释中对占位符的文字引用
    rendered = template.replace("\n@FONT_PACK@\n", "\n" + "\n".join(blocks) + "\n").replace(
        "\n@EXTRAS@\n", "\n" + "\n".join(extras_blocks) + "\n"
    )
    if "\n@FONT_PACK@\n" in rendered or "\n@EXTRAS@\n" in rendered:
        # 防御：独占一行的占位符未被消费说明模板被破坏（镜像资产缺失/改动），按失败处理
        fail(f"字体模板占位符渲染不完整，请检查 {FONTCONFIG_TEMPLATE}")

    fonts_conf = Path(os.path.expanduser("~/.config/fontconfig/fonts.conf"))
    if _DRY_RUN:
        log(f"[dry-run] 将渲染字体模板 → {fonts_conf}（pack={pack}，extras={extras}），并执行 fc-cache -f")
        return
    try:
        fonts_conf.parent.mkdir(parents=True, exist_ok=True)
        fonts_conf.write_text(rendered, encoding="utf-8")
    except OSError as exc:
        fail(f"写入字体激活配置失败：{exc}")
    run_cmd(["fc-cache", "-f"], "刷新字体缓存")
    log(f"字体集已激活：pack={pack}，extras={extras}")


# ── 第 5 步：显示（虚拟屏就绪 + 分辨率/DPR）───────────────────────────────
def _x_ready() -> bool:
    """探测 X 服务是否可用。"""
    proc = subprocess.run(["xrandr", "--query"], capture_output=True)
    return proc.returncode == 0


def _ensure_x_server() -> None:
    """虚拟显示器未起时用 dummy 配置拉起 Xorg（坑位 5：dummy 默认分辨率不可信）。"""
    if _x_ready():
        return
    log(f"未检测到可用 X 服务，使用虚拟显示器配置拉起：Xorg {DISPLAY_ID} -config {XORG_CONFIG}")
    try:
        _CHILDREN["xorg"] = subprocess.Popen(
            ["Xorg", DISPLAY_ID, "-config", XORG_CONFIG, "-noreset"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
    except OSError as exc:
        fail(f"启动 Xorg 虚拟显示器失败：{exc}")
    deadline = time.monotonic() + X_READY_TIMEOUT
    while time.monotonic() < deadline:
        if _x_ready():
            return
        if _CHILDREN["xorg"].poll() is not None:
            fail(f"Xorg 虚拟显示器意外退出（rc={_CHILDREN['xorg'].returncode}）")
        time.sleep(0.5)
    fail(f"等待 X 服务就绪超时（{X_READY_TIMEOUT}s）")


def _first_output() -> str | None:
    """取 xrandr 第一个已连接输出名（dummy 驱动下通常为 DUMMY0）。"""
    proc = subprocess.run(["xrandr"], capture_output=True, text=True)
    for line in proc.stdout.splitlines():
        m = re.match(r"^(\S+)\s+connected", line)
        if m:
            return m.group(1)
    return None


def _set_output_mode(output: str, w: int, h: int) -> None:
    """设置输出分辨率；模式缺失时用 cvt 生成 Modeline 动态增补。"""
    mode = f"{w}x{h}"
    if subprocess.run(["xrandr", "--output", output, "--mode", mode],
                      capture_output=True).returncode == 0:
        return
    cvt = run_cmd(["cvt", str(w), str(h), "60"], "生成分辨率 Modeline")
    modeline = None
    for line in cvt.stdout.splitlines():
        m = re.match(r'^Modeline\s+"(\S+)"\s+(.*)$', line.strip())
        if m:
            modeline = (m.group(1), m.group(2))
            break
    if modeline is None:
        fail(f"cvt 未产出可用 Modeline（{w}x{h}）")
    name, params = modeline
    run_cmd(["xrandr", "--newmode", name] + params.split(), "注册新分辨率模式", check=False)
    run_cmd(["xrandr", "--addmode", output, name], "为输出挂载新模式")
    run_cmd(["xrandr", "--output", output, "--mode", name], "应用输出分辨率")


def step5_display(persona) -> None:
    w, h, dpr = persona.display.width, persona.display.height, persona.display.dpr
    os.environ.setdefault("DISPLAY", DISPLAY_ID)
    if _DRY_RUN:
        log(f"[dry-run] 将确保虚拟屏就绪并执行：xrandr --fb {w}x{h} + 输出模式设置（dpr={dpr}）")
    else:
        _ensure_x_server()
        run_cmd(["xrandr", "--fb", f"{w}x{h}"], "设置帧缓冲分辨率")
        output = _first_output()
        if output is None:
            log("警告：未发现已连接输出，跳过输出模式设置（仅帧缓冲生效）")
        else:
            _set_output_mode(output, w, h)
    if dpr > 1:
        # Qt 支持小数缩放；GTK(GDK_SCALE) 仅认整数，非整数 dpr 时取整仅供 GTK 应用参考
        os.environ["QT_SCALE_FACTOR"] = str(dpr)
        os.environ["GDK_SCALE"] = str(int(round(dpr)))
        log(f"显示已烘焙：{w}x{h}，dpr={dpr}（QT_SCALE_FACTOR={dpr}，GDK_SCALE={os.environ['GDK_SCALE']}）")
    else:
        log(f"显示已烘焙：{w}x{h}，dpr={dpr}")


# ── 第 6 步：输入法（坑位 4：三环境变量缺一不可，且在 Chrome 启动前 export）──
def step6_input_method() -> None:
    os.environ["GTK_IM_MODULE"] = "fcitx"
    os.environ["QT_IM_MODULE"] = "fcitx"
    os.environ["XMODIFIERS"] = "@im=fcitx"
    spawn("fcitx5", ["fcitx5", "-d"], "fcitx5 输入法守护")


# ── 第 7 步：观测脚手架（M1 只保证数据在产生、落得了盘，解密属 M3）─────────
def step7_observability(monitor_pcap: str) -> None:
    for sub in ("sslkeys", "pcap", "events"):
        try:
            Path(f"/persona/logs/{sub}").mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            fail(f"创建观测目录 /persona/logs/{sub} 失败：{exc}")
    if monitor_pcap == "1":
        spawn("observability", ["bash", OBSERVABILITY_DAEMON], "观测守护（环形抓包）")
    else:
        log("MONITOR_PCAP=0：跳过抓包守护（keylog 仍随 Chrome 启动注入）")


# ── 第 7.6 步：判别引擎守护（SPEC-E §8，观测守护之后的纯增量加挂）──────────
# 不改既有十段 BOOT_MARK 打点：本段只挂后台进程，不新增段名。
ENGINE_EVENTS_DB = "/persona/logs/events/events.db"  # 观测守护落库路径（M3 契约）


def _engine_available() -> bool:
    """引擎可用性自检：tishen.engine.daemon 可导入且接口齐全才允许启动。"""
    try:
        from tishen.engine import daemon as engine_daemon
    except ImportError:
        return False
    return all(hasattr(engine_daemon, attr)
               for attr in ("EngineConfig", "EngineDaemon", "main"))


def step7_6_engine(persona) -> None:
    """加挂 engine daemon（后台进程组同观测守护）。

    自检失败时降级跳过（日志注明，不阻塞 bake）——判别引擎是增强层，
    观测与流链路不得被其缺失拖死（SPEC-E §8）。
    """
    if not _engine_available():
        log("判别引擎自检失败（tishen.engine.daemon 不可用），降级跳过引擎守护，bake 继续")
        return
    spawn("engine",
          [sys.executable, "-m", "tishen.engine.daemon",
           "--persona-id", persona.meta.id,
           "--events-db", ENGINE_EVENTS_DB],
          "判别引擎守护（E1/E2 标注 + E3 评级回写）")


# ── 第 7.7 步：JS hook 层（SPEC-E3 §2.3，引擎守护之后的纯增量加挂）──────────
# 不改既有十段 BOOT_MARK 打点：本段只挂后台进程与落配置文件，不新增段名。
HOOK_SOCKET = "/persona/logs/hook.sock"          # 总线收流 socket（SPEC-E3 §0）
HOOK_PAYLOAD_LOG = "/persona/logs/hook/samples.jsonl"  # payload_sample JSONL 落盘
HOOK_EXT_DIR = "/opt/tishen/hook-ext"            # MV3 hook 扩展目录（镜像内固化）
HOOK_NATIVE_HOST = "/opt/tishen/hook/tishen_native_host.py"   # 镜像内绝对路径
HOOK_NATIVE_MANIFEST_TEMPLATE = "/opt/tishen/hook/tishen_native_host.json"
HOOK_NATIVE_MANIFEST_DIR = "~/.config/chromium/NativeMessagingHosts"


def _hook_bus_available() -> bool:
    """hook 总线自检：tishen.observ.hook_bus 可导入且接口齐全才允许启动。"""
    try:
        from tishen.observ import hook_bus
    except ImportError:
        return False
    return all(hasattr(hook_bus, attr)
               for attr in ("BusConfig", "HookBus", "main"))


def step7_7_hook(persona) -> None:
    """加挂 JS hook 事件总线 + Chrome 扩展/native manifest（SPEC-E3 §2.3）。

    降级纪律同引擎守护：hook 层是观测增强，任何缺失/失败只记日志跳过，
    绝不阻塞 bake（观测与流链路不得被其缺失拖死）。
    """
    hook_argv = [sys.executable, "-m", "tishen.observ.hook_bus",
                 "--socket", HOOK_SOCKET, "--events-db", ENGINE_EVENTS_DB]
    hook_line = " ".join(shlex.quote(a) for a in hook_argv)
    if _DRY_RUN:
        log(f"[dry-run] 将后台启动：{hook_line}（JS hook 事件总线；失败降级跳过）")
    elif not _hook_bus_available():
        log("hook 总线自检失败（tishen.observ.hook_bus 不可用），降级跳过，bake 继续")
    else:
        try:
            Path("/persona/logs/hook").mkdir(parents=True, exist_ok=True)
            _CHILDREN["hook_bus"] = subprocess.Popen(hook_argv)
            log(f"JS hook 事件总线已启动（pid={_CHILDREN['hook_bus'].pid}，socket={HOOK_SOCKET}）")
        except OSError as exc:
            log(f"hook 总线启动失败（{exc}），降级跳过，bake 继续")

    # native messaging manifest 落位（SPEC-E3 §2.2/§2.3，HOST_PATH 用镜像内绝对路径）
    manifest_dir = Path(os.path.expanduser(HOOK_NATIVE_MANIFEST_DIR))
    manifest_path = manifest_dir / "tishen_native_host.json"
    if _DRY_RUN:
        log(f"[dry-run] 将安装 native manifest → {manifest_path}（HOST_PATH={HOOK_NATIVE_HOST}）")
        return
    try:
        template = Path(HOOK_NATIVE_MANIFEST_TEMPLATE).read_text(encoding="utf-8")
        rendered = template.replace("__HOST_PATH__", HOOK_NATIVE_HOST)
        manifest_dir.mkdir(parents=True, exist_ok=True)
        manifest_path.write_text(rendered, encoding="utf-8")
        log(f"native messaging manifest 已落位：{manifest_path}")
        if "__EXT_ID__" in rendered:
            log("提示：manifest 仍含 __EXT_ID__ 占位符，扩展 id 由 hook 扩展 key 确定后更新（H 侧契约）")
    except OSError as exc:
        log(f"native manifest 落位失败（{exc}），降级跳过，bake 继续")


# ── 第 7.5 步：neko 流服务（M2，SPEC-M2M3 §1.2）─────────────────────────────
# 在 fcitx5 之后、Chrome 之前受监督启动 neko server：neko 抓虚拟屏推 WebRTC 流并回注输入，
# 不接管 Chrome 生命周期（M2 方案 §二.2）。
# 口令纪律：NEKO_PASSWORD 只经环境变量注入（docker run -e，创建替身时随机生成），
# 缺失则拒绝启动（无人值守的流服务不允许以默认/空口令裸奔）。
def build_neko_argv() -> list[str]:
    """组装 neko 启动行；NEKO_BIND/ICELITE/NAT1TO1/EPR 走镜像 ENV 默认值。"""
    return [NEKO_BIN, "serve"]


def step7_5_neko() -> None:
    neko_password = os.environ.get("NEKO_PASSWORD", "")
    argv = build_neko_argv()
    line = " ".join(shlex.quote(a) for a in argv)
    if _DRY_RUN:
        # dry-run 只打印计划不真启动；口令永不明文上屏（含计划打印）
        pwd_note = "已注入（不明文打印）" if neko_password else "未设置（真实启动将拒绝）"
        log(f"[dry-run] 将后台启动：{line}（neko 流服务；NEKO_PASSWORD {pwd_note}；"
            f"NEKO_BIND={os.environ.get('NEKO_BIND', ':8080')}）")
        return
    if not neko_password:
        fail("NEKO_PASSWORD 环境变量缺失：neko 流服务拒绝以无口令状态启动。"
             "请在 docker run 时经 -e NEKO_PASSWORD=... 注入（由 tishen CLI 创建替身时随机生成）", 2)
    if not Path(NEKO_BIN).is_file():
        fail(f"neko server 二进制不存在：{NEKO_BIN}（镜像未含 L5 流层，请用 stream 阶段的镜像构建）", 2)
    spawn("neko", argv, "neko 流服务（WebRTC 推流/输入回注）")


# ── 第 8 步：组装 Chrome 启动行 ───────────────────────────────────────────
def build_chrome_argv(persona, gpu_vendor: str) -> list[str]:
    argv = [
        "google-chrome",
        "--user-data-dir=/persona/profile",
        "--ssl-key-log-file=/persona/logs/sslkeys/sslkeys.log",
        f"--lang={persona.region.locale}",
        f"--force-webrtc-ip-handling-policy={persona.webrtc.ip_handling_policy}",
        "--ignore-gpu-blocklist",
    ]
    # Mesa 透传走 ANGLE/gl；NVIDIA 变体走 EGL（坑位 3：NVIDIA 与 EGL 版本敏感，单列变体）
    if gpu_vendor == "nvidia":
        argv.append("--use-gl=egl")
    else:
        argv += ["--use-gl=angle", "--use-angle=gl"]
    argv += ["--no-first-run", "--no-default-browser-check", "--ozone-platform=x11"]
    # SPEC-E3 §2.3：加载 MV3 hook 扩展（镜像内固化目录；缺失时 Chrome 仅告警不拒启）
    argv.append(f"--load-extension={HOOK_EXT_DIR}")
    return argv


# ── 第 9 步：禁项自检（双保险，防未来改动引入）─────────────────────────────
FORBIDDEN_FLAGS = ("--no-sandbox", "--remote-debugging-port")


def step9_forbidden_check(chrome_argv: list[str]) -> None:
    line = " ".join(chrome_argv)
    for flag in FORBIDDEN_FLAGS:
        if flag in line:
            fail(f"启动行含禁项 {flag}（安全基线：不加 no-sandbox、用户会话不开 CDP 调试端口），拒绝启动", 4)
    log("禁项自检通过（无 --no-sandbox / --remote-debugging-port）")


# ── 第 10 步：SIGTERM 收尾 ────────────────────────────────────────────────
def _terminate(name: str, timeout: int = 10) -> None:
    proc = _CHILDREN.get(name)
    if proc is None or proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
    log(f"{name} 已停止")


def _shutdown(signum, _frame) -> None:
    """SIGTERM 监督收尾顺序（SPEC-M2M3 §1.2）：Chrome → neko → fcitx5 → 观测守护（含虚拟屏），退出码 0。"""
    log(f"收到信号 {signum}，按序收尾")
    _terminate("chrome")
    _terminate("neko")
    _terminate("engine")
    _terminate("hook_bus")
    _terminate("fcitx5")
    _terminate("observability")
    _terminate("xorg")
    sys.exit(0)


def main() -> None:
    global _DRY_RUN, _BOOT_T0
    # M5 启动计时基准（SPEC-M5 §5）：脚本入口即打点，entry 段 elapsed=0
    _BOOT_T0 = time.monotonic()
    _boot_mark("entry")
    parser = argparse.ArgumentParser(description="替身容器 persona 烘焙器（SPEC §6）")
    parser.add_argument("--dry-run", action="store_true",
                        help="冒烟模式：跑完第 1–7.5 步后打印将要执行的 neko/Chrome 启动计划并退出 0")
    args = parser.parse_args()
    _DRY_RUN = args.dry_run

    gpu_vendor = os.environ.get("GPU_VENDOR", "mesa")
    if gpu_vendor not in ("mesa", "nvidia"):
        fail(f"GPU_VENDOR={gpu_vendor} 非法（可选 mesa|nvidia）", 2)
    monitor_pcap = os.environ.get("MONITOR_PCAP", "1")
    if monitor_pcap not in ("0", "1"):
        fail(f"MONITOR_PCAP={monitor_pcap} 非法（可选 0|1）", 2)

    # 第 1–7.5 步：门禁 → 时区 → locale → 字体 → 显示 → 输入法 → 观测 → neko 流服务
    # 各段完成处打 BOOT_MARK（SPEC-M5 §5，段名枚举与顺序固定，stderr）
    persona = step1_gate()
    _boot_mark("lint_recheck")
    step2_timezone(persona)
    _boot_mark("timezone")
    step3_locale(persona)
    _boot_mark("locale")
    step4_fonts(persona)
    _boot_mark("fonts")
    step5_display(persona)
    _boot_mark("xrandr")
    step6_input_method()
    _boot_mark("fcitx5")
    step7_observability(monitor_pcap)
    _boot_mark("observ")
    step7_6_engine(persona)  # SPEC-E §8：观测守护之后加挂引擎守护（失败降级跳过）
    step7_7_hook(persona)  # SPEC-E3 §2.3：引擎守护之后加挂 JS hook 层（失败降级跳过）
    step7_5_neko()
    _boot_mark("neko")

    # 第 8/9 步：组装启动行 + 禁项自检
    chrome_argv = build_chrome_argv(persona, gpu_vendor)
    step9_forbidden_check(chrome_argv)

    launch_line = " ".join(shlex.quote(a) for a in chrome_argv)
    if _DRY_RUN:
        log("dry-run 完成（第 1–7.5 步已执行/预演），将要执行的 Chrome 启动行：")
        print(launch_line)
        _boot_mark("chrome_launch")  # dry-run 预演至启动行组装完成
        sys.exit(0)

    # 第 8 步执行：启动 Chrome 为会话主进程。
    # 说明：契约原文为 exec；但第 10 步要求本进程在 SIGTERM 时先停 Chrome 再停 fcitx5/观测守护，
    # exec 后 python 消失将无人收尾，故 Chrome 作为受监督子进程运行（仍是用户会话唯一主进程）。
    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)
    log(f"启动 Chrome：{launch_line}")
    try:
        _CHILDREN["chrome"] = subprocess.Popen(chrome_argv)
    except OSError as exc:
        fail(f"启动 Chrome 失败：{exc}")
    _boot_mark("chrome_launch")  # Chrome 已拉起（SPEC-M5 §5 末段）
    rc = _CHILDREN["chrome"].wait()
    log(f"Chrome 退出（rc={rc}），按序收尾后台进程（neko → 引擎守护 → fcitx5 → 观测守护）")
    _terminate("neko")
    _terminate("engine")
    _terminate("hook_bus")
    _terminate("fcitx5")
    _terminate("observability")
    _terminate("xorg")
    sys.exit(rc)


if __name__ == "__main__":
    main()
