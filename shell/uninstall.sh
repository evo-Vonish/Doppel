#!/usr/bin/env bash
# ============================================================================
# 替身 Tishen（Doppel）卸载器 —— uninstall.sh（INS-1 骨架，全量清除是信任特性）
# 用法：bash uninstall.sh [--keep-data] [--force] [--dry-run] [--unattended]
#   --keep-data   保留替身数据卷 ts_*（默认连数据一起清除）
#   --force       数据销毁免二次确认（脚本化场景；危险，请确认已备份）
#   --dry-run     预演：只打印将执行的命令，不做任何改动
#   --unattended  跳过卸载总确认（数据卷删除仍需 --force 或交互二次确认）
# 退出码：0 成功；1 一般错误/用户取消
# 测试注入点（环境变量，与 install.sh 一致）：
#   DOPPEL_PREFIX       资产目录（默认 /opt/doppel，无 sudo 时 ~/.local/share/doppel）
#   DOPPEL_DAEMON_JSON  Docker daemon.json 路径（默认 /etc/docker/daemon.json）
# ============================================================================
set -euo pipefail

# 与 install.sh 写入的调优键一致，卸载时回滚该配置段
readonly DAEMON_JSON_KEY="max-download-attempts"

# ---------- 参数解析 ----------
KEEP_DATA=0
FORCE=0
DRY_RUN=0
UNATTENDED=0
for arg in "$@"; do  case "$arg" in
    --keep-data) KEEP_DATA=1 ;;
    --force) FORCE=1 ;;
    --dry-run) DRY_RUN=1 ;;
    --unattended) UNATTENDED=1 ;;
    -h|--help) sed -n '2,13p' "$0"; exit 0 ;;
    *) echo "未知参数：$arg（支持 --keep-data / --force / --dry-run / --unattended）" >&2; exit 1 ;;
  esac
done

# ---------- 中文回显助手 ----------
say()  { echo "$*"; }
ok()   { echo "  [成功] $*"; }
warn() { echo "  [警告] $*" >&2; }
die()  { echo "  [失败] $1" >&2; exit "${2:-1}"; }
step() { echo ""; echo "[$1/5] $2"; }

# docker 可用性统一判定点（同 install.sh 注入点，测试专用）。
docker_available() {
  [ -z "${DOPPEL_FORCE_NO_DOCKER:-}" ] && command -v docker >/dev/null 2>&1
}

# ---------- 权限判定与路径解析（同 install.sh） ----------
SUDO=""
if [ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null 2>&1; then SUDO="sudo"; fi
ROOT_OK=1
if [ "$(id -u)" -ne 0 ] && [ -z "$SUDO" ]; then ROOT_OK=0; fi
TARGET_USER="${DOPPEL_TARGET_USER:-${SUDO_USER:-${USER:-$(id -un)}}}"  # DOPPEL_TARGET_USER 为测试注入点
if [ -n "${DOPPEL_PREFIX:-}" ]; then
  PREFIX="$DOPPEL_PREFIX"
elif [ "$ROOT_OK" -eq 1 ]; then
  PREFIX="/opt/doppel"
else
  PREFIX="${HOME}/.local/share/doppel"
fi
DAEMON_JSON="${DOPPEL_DAEMON_JSON:-/etc/docker/daemon.json}"

# ---------- 命令执行包装：dry-run 只打印 ----------
run() {
  if [ "$DRY_RUN" -eq 1 ]; then echo "    + $*"; return 0; fi
  echo "    执行：$*"
  "$@"
}
run_root() {
  if [ "$DRY_RUN" -eq 1 ]; then echo "    + ${SUDO:+$SUDO }$*"; return 0; fi
  echo "    执行：${SUDO:+$SUDO }$*"
  if [ -n "$SUDO" ]; then sudo "$@"; else "$@"; fi
}

# ---------- 卸载总确认（--unattended/--dry-run 跳过） ----------
confirm_uninstall() {
  if [ "$DRY_RUN" -eq 1 ] || [ "$UNATTENDED" -eq 1 ]; then return 0; fi
  say "即将全量卸载替身 Tishen：外壳、资产目录、镜像、数据卷、daemon.json 配置段。"
  printf "确认卸载？[y/N] "
  local ans=""
  read -r ans < /dev/tty 2>/dev/null || ans=""
  case "$ans" in
    y|Y|yes|YES) return 0 ;;
    *) die "用户取消卸载" ;;
  esac
}

# ---------- [1/5] 删除外壳与资产目录 ----------
remove_assets() {
  step 1 "删除外壳与资产目录（$PREFIX）"
  if [ -d "$PREFIX" ]; then
    if [ "$PREFIX" = "/opt/doppel" ] && [ "$ROOT_OK" -eq 1 ]; then
      run_root rm -rf "$PREFIX"
    else
      run rm -rf "$PREFIX"
    fi
    ok "资产目录已清除（含外壳 AppImage）"
  else
    say "  资产目录不存在（或 dry-run 预演），跳过"
    if [ "$DRY_RUN" -eq 1 ]; then echo "    + rm -rf $PREFIX"; fi
  fi
}

# ---------- [2/5] 删除替身镜像（doppel-image*） ----------
remove_images() {
  step 2 "删除替身镜像（doppel-image*）"
  if ! docker_available; then
    say "  Docker 不在 PATH，跳过镜像清理"
    return 0
  fi
  local imgs
  imgs="$(docker images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | grep '^doppel-image' || true)"
  if [ -z "$imgs" ]; then
    say "  无 doppel-image* 镜像，跳过"
    return 0
  fi
  echo "$imgs" | while read -r img; do
    run docker rmi "$img"
  done
  ok "镜像清理完成"
}

# ---------- [3/5] 删除替身数据卷（ts_*，数据销毁需二次确认） ----------
remove_volumes() {
  step 3 "删除替身数据卷（ts_*）"
  if [ "$KEEP_DATA" -eq 1 ]; then
    say "  --keep-data：保留全部数据卷 ts_*，跳过本步"
    return 0
  fi
  if ! docker_available; then
    say "  Docker 不在 PATH，跳过数据卷清理"
    return 0
  fi
  local vols
  vols="$(docker volume ls --format '{{.Name}}' 2>/dev/null | grep '^ts_' || true)"
  if [ -z "$vols" ]; then
    say "  无 ts_* 数据卷，跳过"
    return 0
  fi
  # 数据销毁话术：卷内含替身全部持久数据，删除后不可恢复
  say "  【数据销毁警告】以下数据卷包含替身的全部持久数据，删除后不可恢复："
  say "    - ${vols//$'\n'/$'\n'    - }"
  if [ "$DRY_RUN" -eq 1 ]; then
    echo "$vols" | while read -r v; do echo "    + docker volume rm $v"; done
    say "  （dry-run：真实删除需 --force 或交互输入「销毁数据」二次确认）"
    return 0
  fi
  if [ "$FORCE" -eq 0 ]; then
    if [ "$UNATTENDED" -eq 1 ]; then
      warn "--unattended 但未给 --force，为保护数据跳过卷删除（加 --force 强制执行）"
      return 0
    fi
    local ans=""
    printf "  如确认销毁，请输入「销毁数据」："
    read -r ans < /dev/tty 2>/dev/null || ans=""
    if [ "$ans" != "销毁数据" ]; then
      warn "未确认，跳过数据卷删除（数据已保留；--force 可强制执行）"
      return 0
    fi
  fi
  echo "$vols" | while read -r v; do
    run docker volume rm "$v"
  done
  ok "数据卷已销毁"
}

# ---------- [4/5] 回滚 daemon.json 配置段（仅移除安装器写入的键） ----------
rollback_daemon_json() {
  step 4 "回滚 daemon.json 配置段（移除 $DAEMON_JSON_KEY，保留其余配置）"
  if [ "$DRY_RUN" -eq 1 ]; then
    echo "    + 从 $DAEMON_JSON 移除 \"$DAEMON_JSON_KEY\" 键（其余配置原样保留）"
    return 0
  fi
  if [ ! -s "$DAEMON_JSON" ]; then
    say "  daemon.json 不存在或为空，跳过"
    return 0
  fi
  local tmp
  tmp="$(mktemp)"
  if command -v jq >/dev/null 2>&1; then
    jq --arg k "$DAEMON_JSON_KEY" 'del(.[$k])' "$DAEMON_JSON" > "$tmp" \
      || { rm -f "$tmp"; die "daemon.json 解析失败，请手动检查 $DAEMON_JSON"; }
  elif command -v python3 >/dev/null 2>&1; then
    python3 - "$DAEMON_JSON" "$DAEMON_JSON_KEY" > "$tmp" <<'PYEOF'
import json, sys
path, key = sys.argv[1], sys.argv[2]
with open(path, encoding="utf-8") as f:
    data = json.load(f)
data.pop(key, None)
print(json.dumps(data, indent=2, ensure_ascii=False))
PYEOF
  else
    warn "缺少 jq/python3，请手动从 $DAEMON_JSON 移除 \"$DAEMON_JSON_KEY\""
    rm -f "$tmp"
    return 0
  fi
  if [ -n "$SUDO" ]; then sudo cp "$tmp" "$DAEMON_JSON"; else cp "$tmp" "$DAEMON_JSON"; fi
  rm -f "$tmp"
  ok "daemon.json 配置段已回滚"
}

# ---------- [5/5] 移出 docker 用户组并输出摘要 ----------
remove_group_and_summary() {
  step 5 "移出 docker 用户组并输出摘要"
  if [ "$ROOT_OK" -eq 1 ] && command -v gpasswd >/dev/null 2>&1 \
     && id -nG "$TARGET_USER" 2>/dev/null | tr ' ' '\n' | grep -qx docker; then
    # 组移出是清理尾项，失败（权限/组策略）不应致命——CI/受限环境实证。
    if ! run_root gpasswd -d "$TARGET_USER" docker; then
      warn "gpasswd 移出 docker 组失败（可手动执行：sudo gpasswd -d $TARGET_USER docker），继续收尾"
    else
      say "  docker 组变更需注销重登后生效"
    fi
  else
    say "  用户 $TARGET_USER 不在 docker 组或无权限，跳过"
  fi
  say ""
  if [ "$DRY_RUN" -eq 1 ]; then
    say "（本次为 dry-run 预演：未做任何实际改动）"
  else
    ok "替身 Tishen 已全量卸载"
  fi
  if [ "$KEEP_DATA" -eq 1 ]; then
    say "  数据卷 ts_* 已按 --keep-data 保留，重装后可继续使用"
  fi
}

# ---------- 主流程 ----------
main() {
  say "=================================================="
  say "  替身 Tishen（Doppel）卸载器 v0.1（INS-1）"
  say "=================================================="
  confirm_uninstall
  remove_assets              # [1/5] 外壳与资产目录
  remove_images              # [2/5] 镜像 doppel-image*
  remove_volumes             # [3/5] 数据卷 ts_*（二次确认）
  rollback_daemon_json       # [4/5] daemon.json 配置段回滚
  remove_group_and_summary   # [5/5] docker 组与摘要
}

main
