"""native messaging host 离线测试（SPEC-E3 §2.2/§2.4）。

覆盖：帧协议编解码（BytesIO mock stdin/stdout）、event 翻译
（sampled/late 前缀、persona/session 补全）、payload_sample 落盘与
坏样本回执 error、未知类型回执、socket 端到端、bake dry-run 字符串级断言。
"""

import importlib.util
import io
import json
import socket
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

HOST_PATH = Path(__file__).resolve().parents[2] / "image" / "hook" / "tishen_native_host.py"
BAKE_PATH = Path(__file__).resolve().parents[2] / "image" / "entrypoint" / "persona_bake.py"


def _load_host():
    spec = importlib.util.spec_from_file_location("tishen_native_host", HOST_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


host = _load_host()


def _frame(obj) -> bytes:
    body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
    return struct.pack("<I", len(body)) + body


def _event_msg(**kw):
    event = {
        "event_type": "wasm_load",
        "summary": "WebAssembly.instantiate 加载 wasm 模块",
        "ts": 1_730_000_000_000,
        "page_url": "https://example.com/",
        "frame": "top",
        "actor_script": "https://example.com/x.js",
        "target_host": None,
    }
    event.update(kw)
    return {"v": 1, "type": "event", "event": event}


class _FakeWriter:
    """mock hook.sock 写入端：记录每行文本。"""

    def __init__(self):
        self.lines = []

    def send_line(self, line: str) -> None:
        self.lines.append(line)


# ── 帧协议编解码 ───────────────────────────────────────────────────────────
def test_frame_roundtrip():
    buf_in = io.BytesIO(_frame({"v": 1, "type": "ping"}))
    assert host.read_frame(buf_in) == {"v": 1, "type": "ping"}
    buf_out = io.BytesIO()
    host.write_frame(buf_out, {"ok": True})
    buf_out.seek(0)
    assert host.read_frame(buf_out) == {"ok": True}


def test_read_frame_eof_returns_none():
    assert host.read_frame(io.BytesIO(b"")) is None


def test_read_frame_bad_json_raises():
    body = b"{bad"
    with pytest.raises(ValueError, match="JSON"):
        host.read_frame(io.BytesIO(struct.pack("<I", len(body)) + body))


def test_read_frame_truncated_raises():
    with pytest.raises(ValueError):
        host.read_frame(io.BytesIO(struct.pack("<I", 100) + b"{}"))


# ── event 翻译：sampled/late 前缀 + persona/session 补全 ──────────────────
def test_translate_event_plain_passthrough():
    out = host.translate_event({"summary": "a b", "sampled": False,
                                "injected_late": False}, "p1", "s1")
    assert out["summary"] == "a b"
    assert "sampled" not in out and "injected_late" not in out


def test_translate_event_sampled_prefix():
    out = host.translate_event({"summary": "a b", "sampled": True}, "p1", "s1")
    assert out["summary"] == "[sampled] a b"


def test_translate_event_late_prefix_and_both():
    late = host.translate_event({"summary": "a b", "injected_late": True}, "p1", "s1")
    assert late["summary"] == "[late] a b"
    both = host.translate_event({"summary": "a b", "sampled": True,
                                 "injected_late": True}, "p1", "s1")
    assert both["summary"] == "[sampled] [late] a b"  # §1：两前缀可叠加


def test_translate_event_injects_persona_session_overriding():
    """argv 注入的身份一律覆盖 hook 侧声明（不可信）。"""
    out = host.translate_event({"summary": "a", "persona_id": "spoof",
                                "session_id": "spoof"}, "p_real", "s_real")
    assert out["persona_id"] == "p_real" and out["session_id"] == "s_real"


def test_handle_event_writes_socket_line(tmp_path):
    writer = _FakeWriter()
    receipt = host.handle_message(_event_msg(sampled=True), persona_id="p1",
                                  session_id="s1", writer=writer,
                                  payload_log=str(tmp_path / "s.jsonl"))
    assert receipt == {"ok": True}
    # 总线协议包装（SPEC-E3 §1 同构：{v,type,event}）——裸事件会被
    # hook_bus 按 dropped:type 丢弃，此处锁定包装形态防回归。
    wrapper = json.loads(writer.lines[0])
    assert wrapper["v"] == 1 and wrapper["type"] == "event"
    out = wrapper["event"]
    assert out["summary"].startswith("[sampled] ")
    assert out["persona_id"] == "p1" and out["session_id"] == "s1"
    assert out["event_type"] == "wasm_load"  # 其余字段原样


def test_handle_event_missing_payload_error(tmp_path):
    receipt = host.handle_message({"v": 1, "type": "event"}, persona_id="p1",
                                  session_id="s1", writer=_FakeWriter(),
                                  payload_log=str(tmp_path / "s.jsonl"))
    assert receipt["ok"] is False and "event" in receipt["error"]


# ── payload_sample：落盘与坏样本回执 ──────────────────────────────────────
def test_payload_sample_appends_jsonl(tmp_path):
    log = tmp_path / "samples.jsonl"
    msg = {"v": 1, "type": "payload_sample", "sha256": "ab12", "kind": "wasm",
           "size": 1234, "head_b64": "QUJD", "source_url": None,
           "ts": 1_730_000_000_000}
    receipt = host.handle_message(msg, persona_id="p1", session_id="s1",
                                  writer=_FakeWriter(), payload_log=str(log))
    assert receipt == {"ok": True}
    lines = log.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1 and json.loads(lines[0])["sha256"] == "ab12"


@pytest.mark.parametrize("bad", [
    {"sha256": "", "size": 1, "ts": 1},          # sha256 空
    {"size": 1, "ts": 1},                        # sha256 缺
    {"sha256": "x", "size": -1, "ts": 1},        # size 负
    {"sha256": "x", "size": 1, "ts": "soon"},    # ts 非整数
])
def test_payload_sample_bad_receipt_error(tmp_path, bad):
    bad["type"] = "payload_sample"
    log = tmp_path / "samples.jsonl"
    receipt = host.handle_message(bad, persona_id="p1", session_id="s1",
                                  writer=_FakeWriter(), payload_log=str(log))
    assert receipt["ok"] is False and receipt["error"]
    assert not log.exists()  # 坏样本绝不落盘


def test_unknown_type_receipt_error(tmp_path):
    receipt = host.handle_message({"v": 1, "type": "mystery"}, persona_id="p1",
                                  session_id="s1", writer=_FakeWriter(),
                                  payload_log=str(tmp_path / "s.jsonl"))
    assert receipt["ok"] is False and "未知消息类型" in receipt["error"]


# ── 端到端：子进程跑 host，真 unix socket 收行，回执走帧协议 ──────────────
def test_host_subprocess_end_to_end(tmp_path):
    sock_path = tmp_path / "hook.sock"
    received = []
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(sock_path))
    server.listen(1)
    ready = threading.Event()

    def serve():
        ready.set()
        conn, _ = server.accept()
        buf = b""
        conn.settimeout(5)
        try:
            while True:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    received.append(json.loads(line))
        except OSError:
            pass

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    ready.wait(5)
    proc = subprocess.Popen(
        [sys.executable, str(HOST_PATH),
         "--persona-id", "p_e2e", "--session-id", "sess-e2e",
         "--socket", str(sock_path),
         "--payload-log", str(tmp_path / "samples.jsonl"),
         "chrome-extension://bcabojndboldhfndgfiocodkhgahfckp/"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    try:
        proc.stdin.write(_frame(_event_msg(injected_late=True)))
        proc.stdin.write(_frame({"v": 1, "type": "nope"}))
        proc.stdin.flush()
        # 读两条回执
        receipts = []
        buf = b""
        while len(receipts) < 2:
            buf += proc.stdout.read1(4096)
            while len(buf) >= 4:
                (ln,) = struct.unpack("<I", buf[:4])
                if len(buf) < 4 + ln:
                    break
                receipts.append(json.loads(buf[4:4 + ln]))
                buf = buf[4 + ln:]
        assert receipts[0] == {"ok": True}
        assert receipts[1]["ok"] is False
        deadline = time.monotonic() + 5
        while not received and time.monotonic() < deadline:
            time.sleep(0.05)
        assert received[0]["type"] == "event" and received[0]["v"] == 1
        ev = received[0]["event"]
        assert ev["summary"].startswith("[late] ")
        assert ev["persona_id"] == "p_e2e"
        assert ev["session_id"] == "sess-e2e"
    finally:
        proc.terminate()
        proc.wait(timeout=10)
        server.close()


# ── bake dry-run 字符串级断言：新段在、旧十段零改动 ───────────────────────
_BAKE_SRC = BAKE_PATH.read_text(encoding="utf-8")


def _run_bake_dry_run(capsys):
    """以 _DRY_RUN 直接驱动新段函数（bake 主流程依赖镜像内文件，离线不可跑）。"""
    spec = importlib.util.spec_from_file_location("persona_bake", BAKE_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod._DRY_RUN = True
    mod.step7_7_hook(SimpleNamespace(meta=SimpleNamespace(id="p_bake")))
    persona = SimpleNamespace(
        region=SimpleNamespace(locale="zh-CN"),
        webrtc=SimpleNamespace(ip_handling_policy="default"),
        proxy=None)
    argv = mod.build_chrome_argv(persona, "mesa")
    return capsys.readouterr().out, argv


def test_bake_dry_run_contains_hook_section(capsys):
    out, _ = _run_bake_dry_run(capsys)
    assert "tishen.observ.hook_bus" in out            # 总线 spawn 计划
    assert "--socket /persona/logs/hook.sock" in out
    assert "native manifest" in out                   # manifest 落位计划
    assert "native-messaging-hosts" in out


def test_bake_chrome_argv_uses_registered_hook_extension(capsys):
    _, argv = _run_bake_dry_run(capsys)
    assert not any(arg.startswith("--load-extension=") for arg in argv)
    # 禁项未引入
    assert "--no-sandbox" not in argv and "--remote-debugging-port" not in argv


def test_bake_old_segments_untouched_string_level():
    """既有十段 BOOT_MARK 枚举与 engine 段一字不动（字符串级）。"""
    assert ("entry → lint_recheck → timezone → locale → fonts → xrandr → "
            "fcitx5 → observ → neko → chrome_launch") in _BAKE_SRC
    assert 'step7_6_engine(persona)  # SPEC-E §8：观测守护之后加挂引擎守护（失败降级跳过）' in _BAKE_SRC
    assert 'FORBIDDEN_FLAGS = ("--no-sandbox", "--remote-debugging-port")' in _BAKE_SRC
    # 信号/Chrome 自然退出共用同一个收尾序列，hook_bus 只登记一次。
    assert _BAKE_SRC.count('_terminate("hook_bus", timeout=2)') == 1
    assert "def _shutdown_children(*, include_chrome: bool)" in _BAKE_SRC
    # 新段调用紧随其后
    assert "step7_7_hook(persona)  # SPEC-E3 §2.3" in _BAKE_SRC


def test_bake_hook_section_degrades_not_blocks():
    """hook 段降级纪律：不含 fail( 调用（失败只记日志跳过）。"""
    start = _BAKE_SRC.index("def step7_7_hook")
    end = _BAKE_SRC.index("# ── 第 7.5 步")
    section = _BAKE_SRC[start:end]
    assert "fail(" not in section
    assert "降级跳过" in section
