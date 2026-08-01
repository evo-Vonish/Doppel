#!/usr/bin/env bash
# 替身 Tishen（Doppel）一体化安装器 —— install.sh（INS-1 骨架）
# 依据：替身计划-安装包实施方案.md §二（安装器六要素）、§三（镜像三层 fallback）
# 用法：bash install.sh [--dry-run] [--unattended]
#   --dry-run 全量预演：零落盘、不触网；--unattended 跳过全部交互确认
# 退出码：0 成功；1 一般错误/取消；2 未知发行版（指引模式，非硬失败）；
#         3 检出 snap 版 Docker（黑名单）；4 外壳 SHA256 校验失败
# 测试注入点：DOPPEL_OS_RELEASE / DOPPEL_PREFIX / DOPPEL_DAEMON_JSON /
#   DOPPEL_LOG_DIR 分别覆盖检测源、资产目录、daemon.json 路径、日志目录
set -euo pipefail

# 发布常量：URL 均为占位，由发布流水线（INS-4）替换为正式地址
readonly INSTALL_APP_URL="https://doppel.example/releases/latest/doppel-shell.AppImage"
readonly INSTALL_APP_SHA256_URL="${INSTALL_APP_URL}.sha256"
readonly APP_FILENAME="doppel-shell.AppImage"
# §三：docker 分层断点续传的重试调优键值（合并写入 daemon.json，不覆盖既有配置）
readonly DAEMON_JSON_KEY="max-download-attempts"
readonly DAEMON_JSON_VAL=5

# 参数解析
DRY_RUN=0; UNATTENDED=0
for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=1 ;;
    --unattended) UNATTENDED=1 ;;
    -h|--help) sed -n '2,9p' "$0"; exit 0 ;;
    *) echo "未知参数：$arg（仅支持 --dry-run / --unattended）" >&2; exit 1 ;;
  esac
done

# docker 可用性统一判定点（DOPPEL_FORCE_NO_DOCKER=1 强制视为未安装——
# 测试注入点：CI runner 预装 docker 会掩盖"代装"分支，断言须显式环境）。
docker_available() {
  [ -z "${DOPPEL_FORCE_NO_DOCKER:-}" ] && command -v docker >/dev/null 2>&1
}

# 日志（要素 6）：正式安装全程 tee；dry-run 零落盘故不写日志文件
LOG_FILE=""
if [ "$DRY_RUN" -eq 0 ]; then
  LOG_DIR="${DOPPEL_LOG_DIR:-/tmp}"; mkdir -p "$LOG_DIR"
  LOG_FILE="${LOG_DIR}/doppel-install-$(date +%Y%m%d-%H%M%S).log"
  exec > >(tee -a "$LOG_FILE") 2>&1
fi

# 中文回显助手
say()  { echo "$*"; }
ok()   { echo "  [成功] $*"; }
warn() { echo "  [警告] $*" >&2; }
die()  { echo "  [失败] $1" >&2; exit "${2:-1}"; }
step() { echo ""; echo "[$1/6] $2"; }

# 权限判定：root 或 sudo 可用则落系统目录，否则降级用户目录
SUDO=""
ROOT_OK=1
if [ "$(id -u)" -ne 0 ]; then
  if command -v sudo >/dev/null 2>&1; then SUDO="sudo"; else ROOT_OK=0; fi
fi
TARGET_USER="${SUDO_USER:-${USER:-$(id -un)}}"

# 路径解析（测试注入点优先于默认值）
PREFIX="${DOPPEL_PREFIX:-}"
if [ -z "$PREFIX" ]; then
  if [ "$ROOT_OK" -eq 1 ]; then PREFIX="/opt/doppel"; else PREFIX="${HOME}/.local/share/doppel"; fi
fi
DAEMON_JSON="${DOPPEL_DAEMON_JSON:-/etc/docker/daemon.json}"
OS_RELEASE="${DOPPEL_OS_RELEASE:-/etc/os-release}"

# 命令执行包装：dry-run 只打印（零落盘、不触网）；run_root 为需管理员权限的变体
run() {
  if [ "$DRY_RUN" -eq 1 ]; then echo "    + $*"; return 0; fi
  echo "    执行：$*"; "$@"
}
run_root() {
  if [ "$DRY_RUN" -eq 1 ]; then echo "    + ${SUDO:+$SUDO }$*"; return 0; fi
  echo "    执行：${SUDO:+$SUDO }$*"
  if [ -n "$SUDO" ]; then sudo "$@"; else "$@"; fi
}

# 指引模式：未知发行版不硬失败，打印手动步骤后退出码 2
guidance_mode() {
  say ""
  say "【指引模式】未识别的发行版，请按以下手动步骤安装（或转开发者档自助）："
  say "  1) 安装 Docker： https://docs.docker.com/engine/install/"
  say "  2) 加入 docker 组：sudo usermod -aG docker $TARGET_USER，随后注销重登或 newgrp docker"
  say "  3) 下载外壳： $INSTALL_APP_URL"
  say "     校验和： $INSTALL_APP_SHA256_URL （sha256sum 复算比对一致后方可执行）"
  say "  4) 首启拉取镜像：GHCR 主源 / 国内公益源 fallback / 离线 tar 包三层兜底"
  exit 2
}

# [1/6] 发行版检测（要素 1：三族支持矩阵）
detect_distro() {
  step 1 "检测操作系统发行版"
  if [ ! -r "$OS_RELEASE" ]; then warn "未找到 $OS_RELEASE，无法识别发行版"; guidance_mode; fi
  # 不 source，纯文本解析，避免执行发行版文件中的任意内容
  DISTRO_ID="$(sed -n 's/^ID=//p' "$OS_RELEASE" | head -n1 | tr -d "\"'")"
  DISTRO_VER="$(sed -n 's/^VERSION_ID=//p' "$OS_RELEASE" | head -n1 | tr -d "\"'")"
  say "  检测结果：ID=${DISTRO_ID:-未知} VERSION_ID=${DISTRO_VER:-未知}"
  case "$DISTRO_ID" in
    ubuntu) case "$DISTRO_VER" in
              22.04|24.04) ok "Ubuntu $DISTRO_VER 在支持矩阵内"; return 0 ;;
            esac ;;
    debian) if [ "${DISTRO_VER%%.*}" -ge 12 ] 2>/dev/null; then ok "Debian $DISTRO_VER 在支持矩阵内"; return 0; fi ;;
    fedora) if [ "${DISTRO_VER%%.*}" -ge 40 ] 2>/dev/null; then ok "Fedora $DISTRO_VER 在支持矩阵内"; return 0; fi ;;
  esac
  warn "发行版不在支持矩阵（Ubuntu 22.04/24.04、Debian 12+、Fedora 40+）"
  guidance_mode
}

# sudo 话术（要素 2）：先列命令清单与理由，再请求确认
sudo_plan_and_confirm() {
  say ""
  say "本安装器将以管理员权限执行以下操作（逐条说明理由，全程可审计）："
  say "  a) 包管理器安装 Docker（apt-get/dnf）——替身运行依赖容器运行时"
  say "  b) systemctl enable --now docker ——保证 Docker 开机自启、常驻可用"
  say "  c) usermod -aG docker $TARGET_USER ——当前用户免 sudo 使用 Docker"
  say "  d) 合并写入 $DAEMON_JSON ——镜像下载重试调优（§三 fallback 配套）"
  say "  e) 创建资产目录 $PREFIX 并下载外壳 AppImage——资产收敛单目录便于卸载"
  if [ "$DRY_RUN" -eq 1 ]; then say "（dry-run：以上仅预演打印，不会真正执行）"; return 0; fi
  if [ "$UNATTENDED" -eq 1 ]; then say "（--unattended：跳过交互确认）"; return 0; fi
  printf "确认继续安装？[y/N] "
  local ans=""
  read -r ans < /dev/tty 2>/dev/null || ans=""
  case "$ans" in y|Y|yes|YES) return 0 ;; *) die "用户取消安装（未确认 sudo 操作清单）" ;; esac
}

# [2/6] Docker 代装（要素 3）+ snap 黑名单拒绝（要素 4）
install_docker() {
  step 2 "检查 Docker 运行环境"
  # snap 版 Docker 黑名单：socket/挂载/权限兼容性实证翻车，检出即拒绝并给卸载指引
  if command -v snap >/dev/null 2>&1 && snap list docker >/dev/null 2>&1; then
    say "  检测到 snap 版 Docker——与替身的容器编排不兼容，必须先卸载："
    say "    sudo snap remove docker"
    say "  卸载后重跑本脚本，将由发行版官方源代装 Docker。"
    exit 3
  fi
  if docker_available; then
    ok "已安装 Docker（$(docker --version 2>/dev/null | head -n1)），跳过代装（幂等可重跑）"
    return 0
  fi
  if [ "$ROOT_OK" -eq 0 ]; then warn "无 root/sudo 权限，无法代装 Docker"; guidance_mode; fi
  say "  未检测到 Docker，将由发行版官方源代装："
  case "$DISTRO_ID" in
    ubuntu|debian) run_root apt-get update; run_root apt-get install -y docker.io ;;
    fedora) run_root dnf install -y docker ;;
  esac
  run_root systemctl enable --now docker
  ok "Docker 代装完成"
}

# [3/6] daemon.json 配置段（§三：max-download-attempts 调优，合并不覆盖）
merge_daemon_json() {
  step 3 "合并 Docker daemon.json 调优配置（${DAEMON_JSON_KEY}=${DAEMON_JSON_VAL}）"
  if [ "$ROOT_OK" -eq 0 ]; then warn "无 root/sudo 权限，跳过 daemon.json 配置"; return 0; fi
  if [ "$DRY_RUN" -eq 1 ]; then
    echo "    + ${SUDO:+$SUDO }mkdir -p $(dirname "$DAEMON_JSON")"
    echo "    + 合并写入 $DAEMON_JSON：保留既有键，新增 \"$DAEMON_JSON_KEY\": $DAEMON_JSON_VAL"
    return 0
  fi
  local tmp
  tmp="$(mktemp)"
  if [ -s "$DAEMON_JSON" ]; then
    # 合并而非覆盖：优先 jq，python3 兜底，两者皆无则给手动指引（不冒险解析既有文件）
    if command -v jq >/dev/null 2>&1; then
      jq --arg k "$DAEMON_JSON_KEY" --argjson v "$DAEMON_JSON_VAL" '. + {($k): $v}' "$DAEMON_JSON" > "$tmp" \
        || { rm -f "$tmp"; die "daemon.json 解析失败，请手动检查 $DAEMON_JSON"; }
    elif command -v python3 >/dev/null 2>&1; then
      python3 - "$DAEMON_JSON" "$DAEMON_JSON_KEY" "$DAEMON_JSON_VAL" > "$tmp" <<'PYEOF'
import json, sys
p, k, v = sys.argv[1], sys.argv[2], int(sys.argv[3])
try: d = json.load(open(p, encoding="utf-8"))
except Exception: d = {}
d[k] = v
print(json.dumps(d, indent=2, ensure_ascii=False))
PYEOF
    else
      warn "缺少 jq/python3，无法安全合并既有 daemon.json"
      say "  请手动在 $DAEMON_JSON 中加入：\"$DAEMON_JSON_KEY\": $DAEMON_JSON_VAL"
      rm -f "$tmp"; return 0
    fi
  else
    printf '{\n  "%s": %s\n}\n' "$DAEMON_JSON_KEY" "$DAEMON_JSON_VAL" > "$tmp"
  fi
  if [ -n "$SUDO" ]; then sudo mkdir -p "$(dirname "$DAEMON_JSON")"; sudo cp "$tmp" "$DAEMON_JSON"
  else mkdir -p "$(dirname "$DAEMON_JSON")"; cp "$tmp" "$DAEMON_JSON"; fi
  rm -f "$tmp"
  ok "daemon.json 已合并（既有配置全部保留）"
}

# [4/6] 资产收敛：下载外壳 AppImage + SHA256 校验（要素 5/6）
download_shell() {
  step 4 "下载外壳 AppImage 至 $PREFIX"
  if [ "$DRY_RUN" -eq 1 ]; then
    printf '    + %s\n' "mkdir -p $PREFIX" \
      "curl -fsSL $INSTALL_APP_URL -o $PREFIX/$APP_FILENAME" \
      "curl -fsSL $INSTALL_APP_SHA256_URL -o $PREFIX/$APP_FILENAME.sha256" \
      "sha256sum 复算比对（不一致即删除下载文件并退出码 4）"
    return 0
  fi
  local target="$PREFIX/$APP_FILENAME"
  # 系统目录：root 建目录后交还属主，下载仍以普通用户身份进行
  if [ "$PREFIX" = "/opt/doppel" ] && [ "$ROOT_OK" -eq 1 ]; then
    run_root mkdir -p "$PREFIX"; run_root chown -R "$TARGET_USER" "$PREFIX"
  else
    run mkdir -p "$PREFIX"
  fi
  run curl -fsSL "$INSTALL_APP_URL" -o "$target"
  run curl -fsSL "$INSTALL_APP_SHA256_URL" -o "$target.sha256"
  # 校验（要素 6）：发布页公示 SHA256，本地复算比对，失败即删
  local expect actual
  expect="$(awk '{print $1}' "$target.sha256" | head -n1)"
  actual="$(sha256sum "$target" | awk '{print $1}')"
  if [ -z "$expect" ] || [ "$expect" != "$actual" ]; then
    rm -f "$target" "$target.sha256"
    die "SHA256 校验失败（期望：${expect:-空}，实际：$actual），已删除下载文件" 4
  fi
  chmod +x "$target"; rm -f "$target.sha256"
  ok "外壳 AppImage 下载并校验通过：$target"
}

# [5/6] docker 用户组 + sg 兜底验证（要素 3：最高频翻车点防护）
setup_docker_group() {
  step 5 "配置 docker 用户组（免 sudo 使用 Docker）"
  if [ "$ROOT_OK" -eq 0 ]; then warn "无 root/sudo 权限，跳过用户组配置"; return 0; fi
  if [ "$DRY_RUN" -eq 0 ] && ! docker_available; then warn "Docker 不在 PATH，跳过用户组配置"; return 0; fi
  if id -nG "$TARGET_USER" 2>/dev/null | tr ' ' '\n' | grep -qx docker; then ok "用户 $TARGET_USER 已在 docker 组，无需调整"; return 0; fi
  run_root usermod -aG docker "$TARGET_USER"
  say "  重要提示：docker 组需【注销重登】或执行【newgrp docker】后方生效！"
  # 兜底：sg 以新组身份在当前会话续跑验证，避免用户误以为组已生效
  if [ "$DRY_RUN" -eq 1 ]; then
    echo "    + sg docker -c 'docker version'   # 组切换兜底验证"
  elif command -v sg >/dev/null 2>&1 && sg docker -c 'docker version >/dev/null 2>&1'; then
    ok "sg docker 兜底验证通过，当前会话已可使用 Docker"
  else
    warn "sg docker 验证未通过或不可用——请注销重登后再使用替身"
  fi
}

# [6/6] 完成摘要
summary() {
  step 6 "安装完成摘要"
  say "  外壳位置：$PREFIX/$APP_FILENAME"
  if [ -n "$LOG_FILE" ]; then say "  安装日志：$LOG_FILE"; fi
  say "  首次启动：运行外壳进入首启引导，自动拉取镜像（GHCR 主源 / 国内源 fallback / 离线包）"
  say "  卸载方法：bash uninstall.sh（与 install.sh 同目录；--keep-data 可保留数据卷）"
  if [ "$DRY_RUN" -eq 1 ]; then say "（本次为 dry-run 全量预演：零落盘、未触网、未做任何改动）"
  else ok "安装完成，欢迎使用替身 Tishen！"; fi
}

# 主流程
say "=================================================="
say "  替身 Tishen（Doppel）一体化安装器 v0.1（INS-1）"
say "=================================================="
if [ "$DRY_RUN" -eq 1 ]; then
  say "模式：dry-run 全量预演（零落盘、不触网，日志文件亦不创建）"
else
  say "模式：正式安装（全程日志 tee 至 $LOG_FILE）"
fi
detect_distro          # [1/6] 发行版检测
sudo_plan_and_confirm  # 要素 2：sudo 话术与确认
install_docker         # [2/6] Docker 代装 / snap 拒绝
merge_daemon_json      # [3/6] daemon.json 调优合并
download_shell         # [4/6] 外壳下载与校验
setup_docker_group     # [5/6] docker 组与兜底验证
summary                # [6/6] 摘要
