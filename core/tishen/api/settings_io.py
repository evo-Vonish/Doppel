"""settings.json / alert_acks.json 读写（SPEC-API §9/§7）。

- 存 $TISHEN_HOME/settings.json；缺文件返回默认值；
- 写盘用临时文件 + os.replace（防半截写入）；
- ack 表：$TISHEN_HOME/alert_acks.json，{"acked": ["<event_id>", ...]}，幂等。
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from ..state import tishen_home

# §9 缺文件默认值
DEFAULT_SETTINGS = {
    "mode": "default",
    "packages": {"easyPrivacy": True, "trackerRadar": False, "trackerDb": False},
    "retainDays": 14,
}

_RETAIN_CHOICES = {7, 14, 30}
_MODE_CHOICES = {"default", "expert"}
_PACKAGE_KEYS = {"easyPrivacy", "trackerRadar", "trackerDb"}


def _settings_path() -> Path:
    return tishen_home() / "settings.json"


def _acks_path() -> Path:
    return tishen_home() / "alert_acks.json"


def _atomic_write_json(path: Path, data: dict) -> None:
    """临时文件 + os.replace，防半截写入。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


# ---------------------------------------------------------------------------
# settings.json
# ---------------------------------------------------------------------------

def read_settings() -> dict:
    """读设置；缺文件（或文件损坏）返回默认值。"""
    path = _settings_path()
    if not path.exists():
        return json.loads(json.dumps(DEFAULT_SETTINGS))  # 深拷贝，防调用方改默认值
    try:
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return json.loads(json.dumps(DEFAULT_SETTINGS))
    if not isinstance(data, dict):
        return json.loads(json.dumps(DEFAULT_SETTINGS))
    return data


def validate_settings(data) -> str | None:
    """全量校验（§9）：合法返回 None，否则返回中文错误消息。"""
    if not isinstance(data, dict):
        return "设置须为 JSON 对象"
    if data.get("mode") not in _MODE_CHOICES:
        return f"mode 须 ∈ {sorted(_MODE_CHOICES)}，实际为 {data.get('mode')!r}"
    if data.get("retainDays") not in _RETAIN_CHOICES \
            or isinstance(data.get("retainDays"), bool):
        return f"retainDays 须 ∈ {sorted(_RETAIN_CHOICES)}，实际为 {data.get('retainDays')!r}"
    packages = data.get("packages")
    if not isinstance(packages, dict) or set(packages) != _PACKAGE_KEYS:
        return f"packages 须恰为 {sorted(_PACKAGE_KEYS)} 三键"
    if not all(isinstance(v, bool) for v in packages.values()):
        return "packages 三个值须全为 bool"
    return None


def write_settings(data: dict) -> None:
    """全量替换写盘（调用方须先过 validate_settings）。"""
    _atomic_write_json(_settings_path(), data)


# ---------------------------------------------------------------------------
# alert_acks.json
# ---------------------------------------------------------------------------

def read_acks() -> set[str]:
    """读 ack 表；缺文件/损坏返回空集。"""
    path = _acks_path()
    if not path.exists():
        return set()
    try:
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return set()
    acked = data.get("acked") if isinstance(data, dict) else None
    if not isinstance(acked, list):
        return set()
    return {x for x in acked if isinstance(x, str)}


def add_ack(event_id: str) -> None:
    """登记 ack（幂等）。"""
    acked = read_acks()
    if event_id in acked:
        return
    acked.add(event_id)
    _atomic_write_json(_acks_path(), {"acked": sorted(acked)})
