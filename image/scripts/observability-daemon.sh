#!/usr/bin/env bash
# 替身观测守护（SPEC §6）：环形抓包 8×64MB。
# 纪律：权限失败（缺 NET_RAW/NET_ADMIN capability）时降级写 events 日志说明，不 crash。
# 注意：故意不用 set -e——tcpdump 失败要走降级路径而非退出。
set -uo pipefail

PCAP_DIR="/persona/logs/pcap"
EVENTS_LOG="/persona/logs/events/observability.log"
RING_BASENAME="ring.pcap"
# 环形参数：单文件 64MB，保留 8 个（-C 单位为 MB，-W 为文件数）
RING_FILE_MB=64
RING_FILE_COUNT=8
# 权限失败降级后的重试间隔（秒）：capability 不会凭空出现，慢速重试即可
DEGRADED_RETRY=60

log_event() {
    # 观测事件落盘：ISO8601 时间戳 + 中文说明
    mkdir -p "$(dirname "$EVENTS_LOG")" 2>/dev/null || true
    printf '%s %s\n' "$(date -Is)" "$1" >>"$EVENTS_LOG" 2>/dev/null || true
    printf '[observability] %s\n' "$1"
}

mkdir -p "$PCAP_DIR" || log_event "警告：无法创建抓包目录 $PCAP_DIR"

log_event "观测守护启动：tcpdump -i any -w $PCAP_DIR/$RING_BASENAME -C $RING_FILE_MB -W $RING_FILE_COUNT（环形 ${RING_FILE_COUNT}×${RING_FILE_MB}MB）"

permission_degraded=0
while true; do
    err_file="$(mktemp)"
    if tcpdump -i any -w "$PCAP_DIR/$RING_BASENAME" -C "$RING_FILE_MB" -W "$RING_FILE_COUNT" 2>"$err_file"; then
        # tcpdump 正常返回（理论上不该发生，除非外部干预）——记事件后重启
        log_event "tcpdump 意外正常退出（rc=0），5 秒后重启抓包"
        rm -f "$err_file"
        sleep 5
        continue
    fi
    rc=$?
    err_msg="$(cat "$err_file")"
    rm -f "$err_file"

    # 权限类失败：降级——写 events 日志说明原因，慢速重试，绝不 crash
    if printf '%s' "$err_msg" | grep -Eiq 'permission|permitted|Operation not allowed|cannot open device'; then
        if [ "$permission_degraded" -eq 0 ]; then
            log_event "降级：tcpdump 权限不足（rc=$rc，可能缺 NET_RAW/NET_ADMIN capability）：${err_msg:-无 stderr}；每 ${DEGRADED_RETRY}s 重试一次，不影响主会话"
            permission_degraded=1
        fi
        sleep "$DEGRADED_RETRY"
    else
        # 其他失败（如接口瞬时异常）：记日志后较快重试
        log_event "tcpdump 异常退出（rc=$rc）：${err_msg:-无 stderr}，10 秒后重启抓包"
        sleep 10
    fi
done
