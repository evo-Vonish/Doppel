"""通用下载器（SPEC-E2 §D1，Wave3 Coder D 拥有）。

urllib 实现，纯标准库零依赖：

- **file:// 注入**：测试以本地 fixture 文件注入，不真连网（同 SPEC-E
  §10-6 纪律）；http(s):// 走真实请求。
- **etag 侧车**：响应 ETag 写 `<name>.etag` 侧车文件；下次请求带
  If-None-Match，304 → `from_cache=True` 直接返回既有文件。
- **重试**：非 200/304 或超时/连接错误重试 `max_retries` 次，
  穷尽后抛 RuntimeError（调用方决定降级）。
- **流式写盘**：响应体大于 50MB（`_STREAM_THRESHOLD`）或长度未知时
  分块流式写盘，禁一次性读入内存。
"""

from __future__ import annotations

import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path

# 大于 50MB 的响应流式写盘（SPEC-E2 §D1）
_STREAM_THRESHOLD = 50 * 1024 * 1024

_CHUNK_SIZE = 1024 * 1024  # 流式写盘块大小 1MB

_USER_AGENT = "Mozilla/5.0 (tishen-engine)"


@dataclass
class FetchResult:
    """一次下载的结果（SPEC-E2 §D1）。"""

    path: Path            # 落盘文件路径
    bytes_written: int    # 文件字节数（304 命中时为既有文件大小）
    from_cache: bool      # 304/etag 命中时 True


def _target_name(url: str) -> str:
    """从 URL 推导落盘文件名（路径 basename，空则 download.bin）。"""
    parsed = urllib.parse.urlparse(url)
    name = Path(parsed.path).name
    return name or "download.bin"


def fetch(url: str, dest_dir: str | Path, *, etag_cache: bool = True,
          timeout_s: float = 60.0, max_retries: int = 2) -> FetchResult:
    """下载 url 到 dest_dir，返回 FetchResult（SPEC-E2 §D1）。

    etag_cache=True 且侧车/目标均存在时带 If-None-Match；304 命中
    from_cache=True 返回既有文件。非 200/304 或网络错误重试
    max_retries 次后抛 RuntimeError。
    """
    dest = Path(dest_dir)
    dest.mkdir(parents=True, exist_ok=True)
    target = dest / _target_name(url)
    etag_file = dest / (target.name + ".etag")

    headers: dict[str, str] = {"User-Agent": _USER_AGENT}
    if etag_cache and etag_file.exists() and target.exists():
        headers["If-None-Match"] = etag_file.read_text(encoding="utf-8").strip()

    last_error: str = "未知错误"
    for _attempt in range(max_retries + 1):
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=timeout_s) as resp:
                etag = resp.headers.get("ETag")
                length = resp.headers.get("Content-Length")
                size = _write_body(resp, target, length)
            if etag_cache and etag:
                etag_file.write_text(etag, encoding="utf-8")
            return FetchResult(path=target, bytes_written=size, from_cache=False)
        except urllib.error.HTTPError as exc:
            if exc.code == 304 and etag_cache and target.exists():
                return FetchResult(path=target,
                                   bytes_written=target.stat().st_size,
                                   from_cache=True)
            last_error = f"HTTP {exc.code}"
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last_error = str(exc)
    raise RuntimeError(
        f"下载失败（重试 {max_retries} 次后放弃）：{url}（{last_error}）")


def _write_body(resp, target: Path, content_length: str | None) -> int:
    """把响应体写入 target；>50MB 或长度未知时流式分块，返回字节数。"""
    size: int | None = None
    if content_length is not None:
        try:
            size = int(content_length)
        except ValueError:
            size = None
    if size is not None and size <= _STREAM_THRESHOLD:
        body = resp.read()
        target.write_bytes(body)
        return len(body)
    # 流式写盘：不一次性读入内存（SPEC-E2 §D1）
    written = 0
    with target.open("wb") as f:
        while True:
            chunk = resp.read(_CHUNK_SIZE)
            if not chunk:
                break
            f.write(chunk)
            written += len(chunk)
    return written
