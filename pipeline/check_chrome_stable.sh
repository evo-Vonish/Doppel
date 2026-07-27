#!/usr/bin/env bash
# check_chrome_stable.sh — Chrome stable 更新流水线骨架（SPEC §8）
#
# 流程（注释化实现，钩子已留好）：
#   1. 取最新 stable 版本（dl.google.com 版本接口；curl 为可选步骤，无网络可跳过）
#   2. 与本地镜像标签比对：无变化则退出
#   3. docker build --build-arg CHROME_VERSION=<新版> 重建镜像
#   4. 冒烟：临时容器跑 persona_bake --dry-run + 断言 /etc/tishen/chrome_version
#   5. 打双标签：tishen/platform:<新版>-<序号> + latest-stable
#   6. 提示"各 persona 演化补丁待生成"（演化逻辑属后续里程碑，本脚本只留 TODO 钩子）
#
# 骨架模式：检测到 docker 等依赖缺失时提示并 exit 0（无 docker 环境可完整运行不报错）。

set -euo pipefail

IMAGE_NAME="${TISHEN_IMAGE_NAME:-tishen/platform}"
BUILD_SERIAL="$(date +%Y%m%d)"   # 构建序号：日期占位，真实流水线可换递增序号

log()  { echo "[pipeline] $*"; }
warn() { echo "[pipeline][警告] $*" >&2; }

# ---------------------------------------------------------------------------
# 0. 依赖检测：无 docker 即进入骨架模式，提示后退出 0
# ---------------------------------------------------------------------------
if ! command -v docker >/dev/null 2>&1; then
    warn "未检测到 docker，进入骨架模式（不执行构建）。"
    warn "在真实构建环境安装 docker 后重跑本脚本即可走完整流程。"
    log "骨架模式退出（exit 0）。"
    exit 0
fi

# ---------------------------------------------------------------------------
# 1. 取最新 stable 版本（curl 为可选步骤：无网络/无 curl 则跳过更新）
# ---------------------------------------------------------------------------
LATEST_STABLE=""
if command -v curl >/dev/null 2>&1; then
    # Google 官方版本接口（Version History API）；失败不致命，按"无更新"处理
    LATEST_STABLE="$(curl -fsS --max-time 30 \
        'https://versionhistory.googleapis.com/v1/chrome/platforms/linux/channels/stable/versions' \
        | grep -oE '"version": *"[0-9.]+"' | head -n1 | grep -oE '[0-9.]+' || true)"
fi
if [[ -z "${LATEST_STABLE}" ]]; then
    warn "无法获取最新 stable 版本（无 curl 或网络不可用）。"
    log "跳过本次更新检查，骨架模式退出（exit 0）。"
    exit 0
fi
log "最新 stable：${LATEST_STABLE}"

# ---------------------------------------------------------------------------
# 2. 与本地镜像标签比对：无变化则退出
# ---------------------------------------------------------------------------
CURRENT="$(docker image inspect "${IMAGE_NAME}:latest-stable" \
    --format '{{ index .Config.Labels "tishen.chrome.version" }}' 2>/dev/null || true)"
log "本地 latest-stable 标签版本：${CURRENT:-（无本地镜像）}"
if [[ "${CURRENT}" == "${LATEST_STABLE}" ]]; then
    log "本地镜像已是最新 stable，无需重建。退出（exit 0）。"
    exit 0
fi

# ---------------------------------------------------------------------------
# 3. 重建镜像（四层缓存命中加速）
# ---------------------------------------------------------------------------
NEW_TAG="${IMAGE_NAME}:${LATEST_STABLE}-${BUILD_SERIAL}"
log "开始重建镜像：${NEW_TAG}"
docker build \
    --build-arg "CHROME_VERSION=${LATEST_STABLE}" \
    --tag "${NEW_TAG}" \
    image/

# ---------------------------------------------------------------------------
# 4. 冒烟：临时容器跑 persona_bake --dry-run + 断言 /etc/tishen/chrome_version
# ---------------------------------------------------------------------------
SMOKE_CONTAINER="ts_smoke_$$"
log "冒烟检查：启动临时容器 ${SMOKE_CONTAINER}"
docker run -d --name "${SMOKE_CONTAINER}" --entrypoint /bin/true "${NEW_TAG}"
trap 'docker rm -f "${SMOKE_CONTAINER}" >/dev/null 2>&1 || true' EXIT
# TODO: 待 persona_bake.py 支持 --dry-run 后，替换为真实干跑：
#   docker exec "${SMOKE_CONTAINER}" python3 /opt/tishen/entrypoint/persona_bake.py --dry-run
BAKED_VERSION="$(docker exec "${SMOKE_CONTAINER}" cat /etc/tishen/chrome_version)"
if [[ "${BAKED_VERSION}" != "${LATEST_STABLE}"* ]]; then
    warn "冒烟失败：/etc/tishen/chrome_version=${BAKED_VERSION} 与期望 ${LATEST_STABLE} 不符"
    exit 1
fi
log "冒烟通过：chrome_version=${BAKED_VERSION}"

# ---------------------------------------------------------------------------
# 5. 打双标签：精确版本-序号 + latest-stable
# ---------------------------------------------------------------------------
docker tag "${NEW_TAG}" "${IMAGE_NAME}:latest-stable"
log "已打双标签：${NEW_TAG} 与 ${IMAGE_NAME}:latest-stable"

# ---------------------------------------------------------------------------
# 6. 演化补丁钩子（TODO：属后续里程碑，本脚本只留提示）
# ---------------------------------------------------------------------------
log "各 persona 演化补丁待生成（TODO 钩子）："
log "  遍历活跃 persona → 读 evolution.baseline_chrome → 计算新旧版本差分面"
log "  （UA / Sec-CH-UA / API 面）→ 按 drift_policy 生成演化补丁（草稿）→ 下次 start 应用"
log "流水线完成。"
