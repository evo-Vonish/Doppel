#!/usr/bin/env bash
# 替身 Tishen M4 · CreepJS（MIT）自托管源码获取（SPEC-M4 §5 T2）
# 幂等：git clone --depth 1 abrahamjuliot/creepjs 到 ./repo；
#       已存在则跳过克隆，仅刷新 commit.txt（当前检出的 commit）。
# 用法：bash setup.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$SCRIPT_DIR/repo"
COMMIT_FILE="$SCRIPT_DIR/commit.txt"
REPO_URL="https://github.com/abrahamjuliot/creepjs.git"

if [ -d "$REPO_DIR/.git" ]; then
    echo "repo 已存在，跳过克隆（幂等）。"
else
    echo "克隆 $REPO_URL（--depth 1）→ $REPO_DIR"
    git clone --depth 1 "$REPO_URL" "$REPO_DIR"
fi

# 记录当前 commit（导出 JSON 的 creepjs_commit 字段来源）
git -C "$REPO_DIR" rev-parse HEAD > "$COMMIT_FILE"
# 同步一份进 repo/docs/（serve.sh 的伺服根）：extract_inpage.js 经同源
# fetch("commit.txt") 读取
cp "$COMMIT_FILE" "$REPO_DIR/docs/commit.txt"
echo "commit 已记录到 $COMMIT_FILE：$(cat "$COMMIT_FILE")"
