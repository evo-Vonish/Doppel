"""R1 资源采样器离线测试（SPEC-M5 §3/§8）：解析纯函数 + provider 注入采样 + 落库行数。

全程不依赖 docker：stats_provider 注入假数据，docker 缺失路径经 monkeypatch 模拟。
"""

import sqlite3

import pytest

from tishen.resbench import sampler


def _line(mem_usage="123.4MiB / 2GiB", cpu_perc="12.34%"):
    import json
    return json.dumps({"MemUsage": mem_usage, "CPUPerc": cpu_perc})


# ── parse_stats_json：KiB/MiB/GiB 解析（IEC 1024 进制）──────────────────────
def test_parse_kib():
    r = sampler.parse_stats_json(_line("512KiB / 1GiB", "0.50%"))
    assert r == {"mem_bytes": 512 * 1024, "mem_limit_bytes": 1 << 30, "cpu_pct": 0.5}


def test_parse_mib_float():
    r = sampler.parse_stats_json(_line("123.4MiB / 2GiB", "12.34%"))
    assert r["mem_bytes"] == int(123.4 * (1 << 20))
    assert r["mem_limit_bytes"] == 2 << 30
    assert r["cpu_pct"] == 12.34


def test_parse_gib():
    r = sampler.parse_stats_json(_line("1.5GiB / 3.25GiB", "100.00%"))
    assert r["mem_bytes"] == int(1.5 * (1 << 30))
    assert r["mem_limit_bytes"] == int(3.25 * (1 << 30))
    assert r["cpu_pct"] == 100.0


def test_parse_no_limit_segment():
    """MemUsage 无 "/" 段 → mem_limit_bytes=None。"""
    r = sampler.parse_stats_json(_line("256MiB", "1.0%"))
    assert r["mem_bytes"] == 256 * (1 << 20)
    assert r["mem_limit_bytes"] is None


def test_parse_cpu_pct_float():
    r = sampler.parse_stats_json(_line(cpu_perc="0.07%"))
    assert r["cpu_pct"] == pytest.approx(0.07)


def test_parse_invalid_json_raises_chinese():
    with pytest.raises(ValueError, match="不是合法 JSON"):
        sampler.parse_stats_json("not-json")


def test_parse_bad_mem_unit_raises_chinese():
    with pytest.raises(ValueError, match="未知内存单位"):
        sampler.parse_stats_json(_line("10MB / 2GiB", "1.0%"))  # SI 单位不在 IEC 口径内


def test_parse_bad_cpu_raises_chinese():
    with pytest.raises(ValueError, match="CPUPerc"):
        sampler.parse_stats_json(_line(cpu_perc="abc"))


# ── sample_once：provider 注入 + docker 缺失中文错误 + 写库行数 ─────────────
def test_sample_once_with_mock_provider_writes_row(tmp_path):
    db = str(tmp_path / "resbench.db")
    run_id = sampler.open_run(db, "idle_5tab", loadset_version="LOADSET-v1")
    provider = lambda container: _line("1GiB / 2GiB", "5.5%")
    parsed = sampler.sample_once("tishen-x", db, run_id, stats_provider=provider)
    assert parsed["mem_bytes"] == 1 << 30
    conn = sqlite3.connect(db)
    rows = conn.execute(
        "SELECT run_id, mem_bytes, mem_limit_bytes, cpu_pct FROM samples").fetchall()
    conn.close()
    assert rows == [(run_id, 1 << 30, 2 << 30, 5.5)]


def test_sample_once_docker_missing_raises_runtimeerror(tmp_path, monkeypatch):
    """docker CLI 不存在 → RuntimeError 中文消息（不依赖环境真缺 docker）。"""
    def _boom(*a, **kw):
        raise FileNotFoundError("docker")
    monkeypatch.setattr(sampler.subprocess, "run", _boom)
    db = str(tmp_path / "resbench.db")
    run_id = sampler.open_run(db, "idle_5tab")
    with pytest.raises(RuntimeError, match="docker CLI 不可用"):
        sampler.sample_once("tishen-x", db, run_id)


def test_sample_once_container_missing_raises_runtimeerror(tmp_path, monkeypatch):
    """docker 返回非零（容器不存在）→ RuntimeError 中文消息。"""
    class _Proc:
        returncode = 1
        stdout = ""
        stderr = "Error response from daemon: No such container"
    monkeypatch.setattr(sampler.subprocess, "run", lambda *a, **kw: _Proc())
    db = str(tmp_path / "resbench.db")
    run_id = sampler.open_run(db, "idle_5tab")
    with pytest.raises(RuntimeError, match="docker stats 失败"):
        sampler.sample_once("ghost", db, run_id)


# ── sample_loop：mock 采样循环 + 快进 sleep + 单次失败不中断 ────────────────
def test_sample_loop_counts_samples(tmp_path):
    """快进 sleep（立即返回）+ 短窗口：返回样本数与 samples 行数一致。"""
    db = str(tmp_path / "resbench.db")
    run_id = sampler.open_run(db, "video_play")
    provider = lambda container: _line("800MiB / 2GiB", "25.0%")
    n = sampler.sample_loop("tishen-x", db, run_id, interval_s=0.0,
                            duration_s=0.05, stats_provider=provider, sleep=lambda s: None)
    assert n >= 1
    conn = sqlite3.connect(db)
    cnt = conn.execute("SELECT COUNT(*) FROM samples WHERE run_id = ?", (run_id,)).fetchone()[0]
    conn.close()
    assert cnt == n


def test_sample_loop_failure_records_note_and_continues(tmp_path):
    """单次失败记 runs.note 追加行，不中断循环；后续成功样本照常写库。"""
    db = str(tmp_path / "resbench.db")
    run_id = sampler.open_run(db, "stream_encode")
    calls = {"n": 0}

    def flaky(container):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("docker stats 失败：模拟一次闪断")
        return _line("1GiB / 2GiB", "10.0%")

    n = sampler.sample_loop("tishen-x", db, run_id, interval_s=0.0,
                            duration_s=0.05, stats_provider=flaky, sleep=lambda s: None)
    assert n >= 1  # 第一次失败后循环未中断，仍有成功样本
    conn = sqlite3.connect(db)
    note = conn.execute("SELECT note FROM runs WHERE id = ?", (run_id,)).fetchone()[0]
    conn.close()
    assert "采样失败" in note and "模拟一次闪断" in note


# ── open_run / close_run：runs 行与 note 追加 ───────────────────────────────
def test_open_and_close_run(tmp_path):
    db = str(tmp_path / "resbench.db")
    run_id = sampler.open_run(db, "idle_5tab", loadset_version="LOADSET-v1",
                              image_version="tishen:m5", note="首轮")
    assert run_id == 1
    sampler.close_run(db, run_id, note="采样完成")
    conn = sqlite3.connect(db)
    row = conn.execute(
        "SELECT scenario, loadset_version, image_version, started_at, note FROM runs"
        " WHERE id = ?", (run_id,)).fetchone()
    conn.close()
    assert row[0] == "idle_5tab" and row[1] == "LOADSET-v1" and row[2] == "tishen:m5"
    assert "T" in row[3]  # ISO8601 秒
    assert "首轮" in row[4] and "采样完成" in row[4]  # 追加不覆盖
