#!/usr/bin/env bash
# 替身观测守护（SPEC-M2M3 §2.4）：双进程监督。
#   ① tcpdump 环形抓包（-i any，8×64MB 分片，契约沿用 M1）；
#   ② python3 -m tishen.observ.daemon（keylog 对齐 → tshark 解密 → 事件落库 → 加密删明文）。
# 纪律：
#   - 任一阵亡则重启；重启失败写 events 日志，慢速重试，绝不 crash（原则 6：观测降级不影响链路）；
#   - 权限失败（缺 NET_RAW/NET_ADMIN capability）时降级写 events 日志说明；
#   - 故意不用 set -e——失败要走降级路径而非退出。
set -uo pipefail

PCAP_DIR="/persona/logs/pcap"
EVENTS_DIR="/persona/logs/events"
EVENTS_LOG="$EVENTS_DIR/observability.log"
RING_BASENAME="ring.pcap"
# 环形参数：单文件 64MB，保留 8 个（-C 单位为 MB，-W 为文件数）
RING_FILE_MB=64
RING_FILE_COUNT=8
# 权限失败降级后的重试间隔（秒）：capability 不会凭空出现，慢速重试即可
DEGRADED_RETRY=60
# 监督循环心跳（秒）：检查两个子进程存活
SUPERVISE_TICK=5
# 连续重启失败退避上限（秒）
BACKOFF_MAX=300

log_event() {
    # 观测事件落盘：ISO8601 时间戳 + 中文说明
    mkdir -p "$(dirname "$EVENTS_LOG")" 2>/dev/null || true
    printf '%s %s\n' "$(date -Is)" "$1" >>"$EVENTS_LOG" 2>/dev/null || true
    printf '[observability] %s\n' "$1"
}

mkdir -p "$PCAP_DIR" "$EVENTS_DIR" || log_event "警告：无法创建日志目录 $PCAP_DIR / $EVENTS_DIR"
# tcpdump 捕获初始化后会主动降权到镜像内 tcpdump 用户。named volume 初始目录是
# root:root 0755；若不在启动前交接写权限，抓包已成功打开但首个 ring 文件会失败。
# 只交接 pcap 子树，events/sslkeys 等观测资产继续维持各自最小权限边界。
if id tcpdump >/dev/null 2>&1; then
    chown -R tcpdump:tcpdump "$PCAP_DIR" 2>/dev/null \
        || log_event "警告：无法把 $PCAP_DIR 交接给 tcpdump 用户，抓包可能降级"
    chmod 0750 "$PCAP_DIR" 2>/dev/null \
        || log_event "警告：无法收紧 $PCAP_DIR 权限，抓包可能降级"
fi

# ---------------------------------------------------------------------------
# 子进程启动
# ---------------------------------------------------------------------------

TCPDUMP_PID=""
DAEMON_PID=""

start_tcpdump() {
    # 前台启动转后台：stderr 落临时文件供失败判因
    TCPDUMP_ERR="$(mktemp)"
    tcpdump -i any -w "$PCAP_DIR/$RING_BASENAME" \
        -C "$RING_FILE_MB" -W "$RING_FILE_COUNT" 2>"$TCPDUMP_ERR" &
    TCPDUMP_PID=$!
    log_event "tcpdump 已启动（pid=$TCPDUMP_PID，环形 ${RING_FILE_COUNT}×${RING_FILE_MB}MB）"
}

start_daemon() {
    TISHEN_PCAP_DIR="$PCAP_DIR" TISHEN_EVENTS_DIR="$EVENTS_DIR" \
        python3 -m tishen.observ.daemon &
    DAEMON_PID=$!
    log_event "观测守护已启动（pid=$DAEMON_PID，python3 -m tishen.observ.daemon）"
}

alive() {
    # $1=pid；空串或进程不存在视为阵亡
    [ -n "$1" ] && kill -0 "$1" 2>/dev/null
}

# ---------------------------------------------------------------------------
# 监督主循环：任一阵亡则重启；重启失败写 events 日志并退避重试
# ---------------------------------------------------------------------------

tcpdump_backoff=5
daemon_backoff=5
permission_degraded=0

log_event "观测守护启动：监督 tcpdump 环形抓包 + tishen.observ.daemon 解密流水线"
start_tcpdump
start_daemon

while true; do
    sleep "$SUPERVISE_TICK"

    # --- tcpdump 存活检查 ---
    if ! alive "$TCPDUMP_PID"; then
        wait "$TCPDUMP_PID" 2>/dev/null
        rc=$?
        err_msg="$(cat "${TCPDUMP_ERR:-/dev/null}" 2>/dev/null)"
        rm -f "${TCPDUMP_ERR:-/dev/null}"

        if printf '%s' "$err_msg" | grep -Eiq 'permission|permitted|Operation not allowed|cannot open device'; then
            # 权限类失败：降级——写 events 日志说明原因，慢速重试，绝不 crash
            if [ "$permission_degraded" -eq 0 ]; then
                log_event "降级：tcpdump 权限不足（rc=$rc，可能缺 NET_RAW/NET_ADMIN capability）：${err_msg:-无 stderr}；每 ${DEGRADED_RETRY}s 重试一次，不影响主会话"
                permission_degraded=1
            fi
            sleep "$DEGRADED_RETRY"
        else
            log_event "tcpdump 阵亡（rc=$rc）：${err_msg:-无 stderr}，${tcpdump_backoff}s 后重启"
            sleep "$tcpdump_backoff"
        fi
        start_tcpdump
        sleep 2
        if alive "$TCPDUMP_PID"; then
            tcpdump_backoff=5   # 重启成功，退避复位
        else
            # 重启失败：写 events 日志并加大退避（上限 BACKOFF_MAX）
            log_event "tcpdump 重启失败，退避加大至 $((tcpdump_backoff * 2))s 后继续尝试"
            tcpdump_backoff=$((tcpdump_backoff * 2))
            [ "$tcpdump_backoff" -gt "$BACKOFF_MAX" ] && tcpdump_backoff=$BACKOFF_MAX
        fi
    fi

    # --- 观测守护（解密流水线）存活检查 ---
    if ! alive "$DAEMON_PID"; then
        wait "$DAEMON_PID" 2>/dev/null
        rc=$?
        log_event "观测守护阵亡（rc=$rc），${daemon_backoff}s 后重启"
        sleep "$daemon_backoff"
        start_daemon
        sleep 2
        if alive "$DAEMON_PID"; then
            daemon_backoff=5
        else
            log_event "观测守护重启失败，退避加大至 $((daemon_backoff * 2))s 后继续尝试（抓包不受影响，事件解密降级）"
            daemon_backoff=$((daemon_backoff * 2))
            [ "$daemon_backoff" -gt "$BACKOFF_MAX" ] && daemon_backoff=$BACKOFF_MAX
        fi
    fi
done
