#!/usr/bin/env bash
# 替身 Tishen M4 · 静态伺服 CreepJS repo 于 127.0.0.1:8791（SPEC-M4 §5 T2）
# 前置：先跑 setup.sh 生成 ./repo。仅绑定回环，永不暴露局域网。
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$SCRIPT_DIR/repo"

# CreepJS 页面本体在 repo/docs/（GitHub Pages 源目录），index.html 在其中
SERVE_DIR="$REPO_DIR/docs"
if [ ! -f "$SERVE_DIR/index.html" ]; then
    echo "错误：$SERVE_DIR/index.html 不存在，请先运行 setup.sh 克隆 CreepJS。" >&2
    exit 1
fi

exec python3 -m http.server 8791 --bind 127.0.0.1 --directory "$SERVE_DIR"
