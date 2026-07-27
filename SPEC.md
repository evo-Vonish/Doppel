# SPEC.md — 替身（Tishen）M1 工程脚手架规格

> 单一事实源。任何实现与本文档冲突时，以本文档为准。上游设计依据：`/mnt/agents/output/替身计划-M1实施方案.md`（必读背景）、`/mnt/agents/output/替身计划-项目计划文档.md`（v0.3 原则与风险）。

## 0. 全局纪律

- 代码标识符英文，注释与用户消息中文；
- 依赖白名单：`PyYAML`（必需）、`browserforge`（可选，try-import 缺失时走离线兜底）；其余一律不准引入；
- 禁止在构建会话中真实执行网络下载（Chrome deb、pip 包等）——网络动作只写成脚本，由使用者在真实环境执行；
- 所有脚本兼容 bash 5+；Python 兼容 3.11+。

## 1. 仓库结构

```
project/
├── README.md                      # 主代理负责
├── image/                         # 分支 image（Coder A）
│   ├── Dockerfile                 # 四层多阶段，见 §5
│   ├── entrypoint/persona-bake    # bash 入口（薄壳，exec python3 烘焙器）
│   ├── entrypoint/persona_bake.py # 烘焙器本体，见 §6
│   ├── config/xorg-dummy.conf     # 虚拟显示器 X 配置（支持运行时 xrandr）
│   ├── config/fontconfig-pack.conf.template  # 字体激活模板（占位符 @FONT_PACK@）
│   └── scripts/observability-daemon.sh       # 观测守护（keylog 目录/抓包开关）
├── core/                          # 分支 core（Coder B）
│   ├── pyproject.toml             # 包名 tishen，console_scripts: tishen=tishen.cli:main
│   ├── tishen/
│   │   ├── __init__.py            # __version__ = "0.1.0"
│   │   ├── persona.py             # §2 schema 的 dataclass + YAML 读写 + 结构校验
│   │   ├── regions.py             # 地域一致性数据表（§3.2）
│   │   ├── linter.py              # §3 规则 V1–V10
│   │   ├── sampler.py             # §4 采样 + 约束过滤 + create_persona
│   │   ├── state.py               # SQLite 状态库（§7.3）
│   │   ├── docker_ctl.py          # docker 命令封装（§7.4）
│   │   └── cli.py                 # §7 命令行
│   └── tests/
│       ├── fixtures/valid_cn.yaml         # 完全合法的中国属地 persona
│       ├── fixtures/invalid_v1.yaml       # 时区与属地矛盾
│       ├── fixtures/invalid_v2.yaml       # os.family=windows
│       ├── fixtures/invalid_v4.yaml       # 奇葩分辨率 1873×941
│       ├── fixtures/invalid_v5.yaml       # 2 核配 16GB
│       ├── fixtures/invalid_v9.yaml       # webrtc 策略 default
│       ├── test_persona.py        # schema 往返 + 结构校验
│       ├── test_linter.py         # V1–V10 每条 ≥1 正例 + ≥1 负例
│       └── test_sampler.py        # 固定 seed 可复现 + 离线兜底路径
└── pipeline/
    └── check_chrome_stable.sh     # §8 更新流水线骨架（分支 core）
```

## 2. persona.yaml Schema 契约（v1）

顶层字段（全部必填，除标注可选外）：

| 字段 | 类型 | 约束 |
|---|---|---|
| version | int | 恒为 1 |
| meta.id | str | `^p_[a-z0-9_]{4,32}$` |
| meta.name | str | 1–32 字符 |
| meta.created_at | str | ISO8601 |
| region.follow_ip | bool | 本期恒 true |
| region.detected_ip_region | str | ISO 3166-1 alpha-2，如 CN |
| region.locale | str | 如 zh-CN |
| region.timezone | str | IANA 时区名 |
| region.languages | list[str] | 非空，首项与 locale 一致 |
| os.family | str | 本期恒 linux |
| os.distro | str | 如 ubuntu-24.04 |
| os.chrome_channel | str | 恒 stable |
| hardware.gpu.mode | str | 恒 host_passthrough |
| hardware.gpu.renderer_string_source | str | 恒 real |
| hardware.hardwareConcurrency | int | {2,4,6,8,12,16} |
| hardware.deviceMemory | int | {2,4,8,16} |
| display.width/height | int | §3.4 常见分辨率集 |
| display.dpr | float | {1.0, 1.25, 1.5, 2.0} |
| fonts.pack | str | §3.7 字体包集 |
| fonts.extras | list[str] | 可空，元素 ∈ {cjk} |
| webrtc.ip_handling_policy | str | 恒 disable_non_proxied_udp |
| farbling.seed | str | 32 位十六进制（128-bit） |
| farbling.scope | list[str] | 子集 of {canvas_readback, webgl_readback, audio} |
| evolution.strategy | str | 恒 anchor_chrome_version |
| evolution.baseline_chrome | str | 形如 138.0.7204.0 |
| evolution.drift_policy | str | 恒 follow_stable_diff |
| proxy | null 或 str | 本期恒 null |
| storage.profile_volume / storage.log_volume | str | docker 卷名 |
| storage.retain_days | int | ≥1 |
| monitoring.keylog | bool | 恒 true |
| monitoring.log_encryption | str | 恒 age |
| lifecycle.state | str | ∈ {creating, active, suspended, destroyed} |

`persona.py` 提供：`Persona` dataclass、`load(path)->Persona`、`dump(persona,path)`、`validate_structure(persona)->list[str]`（仅类型/枚举/格式校验，不做跨字段一致性——那是 linter 的事）。

## 3. linter 契约

### 3.1 接口

```python
@dataclass
class LintContext:
    current_stable_chrome: str          # 当前 stable 版本，如 "138.0.7204.50"
    detected_ip_region: str | None      # 创建时实测属地（校验期可 None=跳过 V1 属地锚）

def lint_persona(p: Persona, ctx: LintContext) -> list[LintError]
# LintError: code（LINT_V1..LINT_V10）、field、message（中文，说明为何矛盾）
```

### 3.2 regions.py 数据表（内置最小真实数据，可后续扩充）

```python
REGION_PROFILES = {
  "CN": {"timezones": {"Asia/Shanghai", "Asia/Urumqi"}, "locales": {"zh-CN"},
         "lang_prefixes": ("zh",), "cjk": True},
  "HK": {"timezones": {"Asia/Hong_Kong"}, "locales": {"zh-HK","zh-TW","en-HK"}, "lang_prefixes": ("zh","en"), "cjk": True},
  "TW": {"timezones": {"Asia/Taipei"}, "locales": {"zh-TW"}, "lang_prefixes": ("zh",), "cjk": True},
  "JP": {"timezones": {"Asia/Tokyo"}, "locales": {"ja-JP"}, "lang_prefixes": ("ja",), "cjk": True},
  "US": {"timezones": {"America/New_York","America/Chicago","America/Denver","America/Los_Angeles","America/Phoenix","America/Anchorage"},
         "locales": {"en-US"}, "lang_prefixes": ("en",), "cjk": False},
  "GB": {"timezones": {"Europe/London"}, "locales": {"en-GB"}, "lang_prefixes": ("en",), "cjk": False},
  "DE": {"timezones": {"Europe/Berlin"}, "locales": {"de-DE"}, "lang_prefixes": ("de",), "cjk": False},
}
```

### 3.3 规则 V1–V10（错误码、判定逻辑）

- **V1 属地族一致**：`region.timezone ∈ REGION_PROFILES[detected_ip_region].timezones` 且 `locale ∈ locales` 且 `languages[0]` 以该族 `lang_prefixes` 之一开头。负例：属地 CN 配 America/New_York。
- **V2 OS 锁定**：`os.family == "linux"`。
- **V3 GPU 禁撒谎**：`gpu.mode == "host_passthrough"` 且 `renderer_string_source == "real"`。
- **V4 分辨率真实**：`(width,height) ∈ COMMON_RESOLUTIONS` 且 `dpr ∈ {1.0,1.25,1.5,2.0}`。COMMON_RESOLUTIONS = {(1920,1080),(1536,864),(1366,768),(1440,900),(2560,1440),(1600,900),(1280,720),(3840,2160)}。
- **V5 硬件搭配合理**：合法对表 `{(2,{2,4}),(4,{2,4,8}),(6,{4,8}),(8,{4,8,16}),(12,{8,16}),(16,{16})}`（HC→允许的 DM 集）。
- **V6 版本新鲜**：`major(baseline_chrome) ≥ major(ctx.current_stable_chrome) - 1`。
- **V7 字体包匹配**：`fonts.pack ∈ FONT_PACKS_BY_OS[os.family]`；`cjk ∈ extras` 仅当属地 profile `cjk==True` 或任一 language 以 zh/ja/ko 开头。FONT_PACKS_BY_OS = {"linux": {"linux-noto-standard","linux-liberation-dejavu"}}。
- **V8 种子合法**：`farbling.seed` 匹配 `^[0-9a-f]{32}$`。
- **V9 WebRTC 禁泄露**：`ip_handling_policy == "disable_non_proxied_udp"`。
- **V10 代理边界**：`proxy is None` 或匹配 `^(socks5|http)://[^\s]+:\d{1,5}$`。

## 4. sampler 契约

```python
def generate_candidates(n: int, region: str, rng: random.Random) -> list[dict]
    # 优先 browserforge（try-import）；缺失时走 BUNDLED_DISTRIBUTION（离线兜底静态表：
    # 分辨率/HC/DM/字体包的加权分布，注释注明"近似分布，后续以真实数据替换"）
def create_persona(name: str, region: str, stable_chrome: str,
                   ip_region: str | None = None, seed: int | None = None) -> Persona
    # region="auto" 时用 ip_region（仍 None 则默认 "CN" 并在 meta 注释）
    # 流程：采样 → V1 同族约束过滤 → 填充 schema 全字段 → lint_persona 复验（须零错误）
    # farbling.seed = secrets.token_hex(16)（seed 参数仅用于测试复现）
```

## 5. Dockerfile 契约（image/Dockerfile）

- 四阶段：`runtime` → `i18n` → `chrome` → `tishen`，层职责严格按 M1 方案 §3；
- `ARG UBUNTU=ubuntu:24.04`、`ARG CHROME_VERSION=stable`；
- chrome 层：从 `https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb` 安装；安装后 `google-chrome --version | awk '{print $3}' > /etc/tishen/chrome_version`；
- 透传准备：`/etc/ld.so.conf.d/nvidia.conf`、`/usr/share/glvnd/egl_vendor.d/10_nvidia.json`、mesa 驱动包；
- i18n 层：fonts-noto-cjk、fonts-wqy-microhei、fonts-liberation、fonts-dejavu、fcitx5、fcitx5-chinese-addons、im-config；
- tishen 层：拷贝 entrypoint/ config/ scripts/ 至 `/opt/tishen/`，安装 python3+yaml（烘焙器运行需要）、tcpdump、age（观测加密）；
- `ENTRYPOINT ["/opt/tishen/entrypoint/persona-bake"]`；
- 打 LABEL：`tishen.chrome.version`、`org.opencontainers.image.title="tishen-persona-image"`；
- 层尾清理 apt 缓存；不写死任何 persona 具体值（镜像=平台）。

## 6. persona_bake.py 契约（容器内烘焙器）

输入：`/persona/persona.yaml`（只读挂载）、环境变量 `GPU_VENDOR`（mesa|nvidia，默认 mesa）、`MONITOR_PCAP`（0|1）。

按序执行（每步失败即非零退出并输出中文错误）：

1. 加载并 `validate_structure` persona.yaml，再跑 `lint_persona`（当前 stable 读 `/etc/tishen/chrome_version`）——**门禁在容器内再执行一次**，不过则拒绝启动；
2. 时区：`ln -sf /usr/share/zoneinfo/<tz> /etc/localtime` 并写 `/etc/timezone`；export `TZ`；
3. locale：export `LANG/LC_ALL=<locale>.UTF-8`、`LANGUAGE` 依 languages 列表拼冒号串；
4. 字体：按 `fonts.pack`/`extras` 渲染 `fontconfig-pack.conf.template` → `~/.config/fontconfig/fonts.conf`，`fc-cache -f`；
5. 显示：`xrandr --fb <w>x<h>` + 输出分辨率设置，dpr>1 时写 `GDK_SCALE`/`QT_SCALE_FACTOR`；
6. 输入法：export `GTK_IM_MODULE=fcitx QT_IM_MODULE=fcitx XMODIFIERS=@im=fcitx`，后台启动 `fcitx5 -d`；
7. 观测：`mkdir -p /persona/logs/{sslkeys,pcap,events}`；`MONITOR_PCAP=1` 时后台启动 observability-daemon.sh；
8. 启动 Chrome（exec，保持为 PID 主进程）：
   ```
   google-chrome --user-data-dir=/persona/profile \
     --ssl-key-log-file=/persona/logs/sslkeys/sslkeys.log \
     --lang=<locale> \
     --force-webrtc-ip-handling-policy=disable_non_proxied_udp \
     --ignore-gpu-blocklist \
     $([ "$GPU_VENDOR" = nvidia ] && echo --use-gl=egl || echo --use-gl=angle --use-angle=gl) \
     --no-first-run --no-default-browser-check --ozone-platform=x11
   ```
9. **禁项自检**：启动行 grep 到 `--no-sandbox` 或 `--remote-debugging-port` 立即拒绝（双保险，防未来改动引入）；
10. 处理 SIGTERM：先停 Chrome 再停 fcitx5/观测守护，退出码 0。

`entrypoint/persona-bake`（bash 薄壳）：`#!/usr/bin/env bash`，`set -euo pipefail`，exec `python3 /opt/tishen/entrypoint/persona_bake.py "$@"`。

`scripts/observability-daemon.sh`：后台循环 `tcpdump -i any -w /persona/logs/pcap/ring.pcap -C 64 -W 8`（环形 8×64MB），权限失败时降级写 events 日志说明，不 crash。

## 7. CLI 契约（core/tishen/cli.py，argparse）

```
tishen create [--region auto|CN|HK|TW|JP|US|GB|DE] [--name 名] [--seed N]   # §4 全流程
tishen start <id> | stop <id> | suspend <id> | resume <id> | reset <id> | destroy <id>
tishen list
tishen lint <persona.yaml>            # 对任意 yaml 跑 linter，打印错误表
tishen doctor [<id>]                  # §7.5
```

### 7.1 create：调 `create_persona`，写 `$TISHEN_HOME/personas/<id>.yaml`，docker volume create 两个卷，状态库记 `creating`——随后提示用户 `tishen start`。
### 7.2 生命周期命令：调 docker_ctl；`reset` 必须交互式二次确认（输出"信誉清零"中文警告，输入替身名确认）；`destroy` 删容器+两卷+状态置 destroyed。
### 7.3 state.py：SQLite 存 `$TISHEN_HOME/state.db`，表 `personas(id, name, region, state, chrome_baseline, created_at, updated_at)`；`TISHEN_HOME` 默认 `~/.tishen`。
### 7.4 docker_ctl.py：`run_persona_container(persona, image_tag)` 组 M1 方案 §6 的 docker run 命令（--shm-size=2g、--device /dev/dri、cap、卷、只读挂载 yaml、容器名 ts_<id>）；`start/stop/pause/unpause/rm` 封装 subprocess，返回 (rc, stdout, stderr)；**不捕获异常吃掉错误**。
### 7.5 doctor：无 id 时查全局（docker 可用性、/dev/dri 存在、TISHEN_HOME 结构）；有 id 时查该替身（容器在否、卷在否、persona.yaml 过 linter、shm-size 检查 = 读容器 HostConfig）。逐项 [OK]/[FAIL] 中文输出，FAIL 项附修复建议。

## 8. pipeline/check_chrome_stable.sh 契约（骨架）

流程注释化实现：取最新 stable 版本（dl.google.com 的版本接口，curl 写成可选步骤）→ 与本地标签比对 → `docker build --build-arg CHROME_VERSION=...` → 冒烟段（启动临时容器跑 persona_bake --dry-run + 断言 `/etc/tishen/chrome_version`）→ 打双标签 → 输出"各 persona 演化补丁待生成"提示（演化逻辑属后续里程碑，本脚本只留 TODO 钩子）。脚本可完整运行在无 docker 环境时不报错退出（检测依赖缺失则提示后 `exit 0` 骨架模式）。

## 9. 验收（主代理执行）

1. `pytest core/tests` 全绿；
2. `python -m compileall core/` 无错；
3. `shellcheck image/entrypoint/* image/scripts/* pipeline/*.sh` 无 error（warning 需注释说明可接受项）；
4. Dockerfile 人工静态审查：四阶段、ARG、LABEL、ENTRYPOINT 齐全；
5. fixtures 中 invalid_v*.yaml 各自触发且仅触发对应规则（±附带 V3/V9/V10 等恒真规则豁免设计需注释说明）。
