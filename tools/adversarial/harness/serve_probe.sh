#!/usr/bin/env bash
# 替身 Tishen M4 · 静态伺服 harness/ 于 127.0.0.1:8789（SPEC-M4 §5）
# 探针页打开方式：http://127.0.0.1:8789/probe.html?group=T-cold&persona=替身ID
# 仅绑定回环，永不暴露局域网（本地优先纪律）。
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

exec python3 -m http.server 8789 --bind 127.0.0.1 --directory "$SCRIPT_DIR"
