# M2 测试（SPEC-M2M3 §1.3）：
# 1) state.py 新增 host_port / neko_password 两列 + 旧库迁移安全；
# 2) cli --json 输出契约（list 数组、start 的 {id,state,host_port,embed_url,password}）；
# 3) events 子命令在观测模块（M3）缺失时的中文友好提示。
#
# 纪律：本环境无真实 docker——start --json 契约测试用 monkeypatch 假掉
# docker_ctl 的 subprocess 边界（只测编排纯逻辑分支，不真调 docker）。

from __future__ import annotations

import json
import sqlite3
import sys

import pytest

from tishen import cli, docker_ctl
from tishen.state import StateDB

FIXTURE_ID = "p_20260727_a7f3"  # fixtures/valid_cn.yaml 的 persona id


@pytest.fixture()
def home(tmp_path, monkeypatch):
    """隔离的 $TISHEN_HOME。"""
    monkeypatch.setenv("TISHEN_HOME", str(tmp_path))
    return tmp_path


def _add_record(db: StateDB, persona_id: str = "p_test01") -> None:
    db.add(persona_id=persona_id, name="测试替身", region="CN",
           state="creating", chrome_baseline="138.0.7204.0")


# ---------------------------------------------------------------------------
# state.py：新列与迁移
# ---------------------------------------------------------------------------

def test_new_columns_default_none(home):
    """新建库的替身记录含 host_port/neko_password 两列，默认 None。"""
    with StateDB() as db:
        _add_record(db)
        rec = db.get("p_test01")
    assert rec is not None
    assert "host_port" in rec and "neko_password" in rec
    assert rec["host_port"] is None and rec["neko_password"] is None


def test_update_connection_partial(home):
    """update_connection 写连接信息；传 None 的字段保持原值不被覆盖。"""
    with StateDB() as db:
        _add_record(db)
        db.update_connection("p_test01", host_port=49153, neko_password="abc123")
        rec = db.get("p_test01")
        assert rec["host_port"] == 49153 and rec["neko_password"] == "abc123"
        # 只刷新端口（start 既有容器场景）：口令必须保持原值
        db.update_connection("p_test01", host_port=49200)
        rec = db.get("p_test01")
        assert rec["host_port"] == 49200 and rec["neko_password"] == "abc123"


def test_migration_from_m1_schema(home, tmp_path):
    """旧库（M1 无新列）打开时 ALTER TABLE 补列，既有数据不丢（迁移安全）。"""
    db_path = tmp_path / "state.db"
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        "CREATE TABLE personas (id TEXT PRIMARY KEY, name TEXT NOT NULL,"
        " region TEXT NOT NULL, state TEXT NOT NULL, chrome_baseline TEXT NOT NULL,"
        " created_at TEXT NOT NULL, updated_at TEXT NOT NULL)")
    conn.execute(
        "INSERT INTO personas VALUES (?, ?, ?, ?, ?, ?, ?)",
        ("p_legacy", "旧替身", "CN", "active", "138.0.7204.0",
         "2026-07-01T00:00:00+08:00", "2026-07-01T00:00:00+08:00"))
    conn.commit()
    conn.close()

    with StateDB(path=db_path) as db:
        rec = db.get("p_legacy")
        assert rec is not None and rec["name"] == "旧替身"  # 旧数据完好
        assert rec["host_port"] is None and rec["neko_password"] is None
        # 迁移后可正常写新列
        db.update_connection("p_legacy", host_port=50000, neko_password="pw")
        rec = db.get("p_legacy")
        assert rec["host_port"] == 50000 and rec["neko_password"] == "pw"
    # 幂等：重复打开不报错（ALTER TABLE 列已存在被安全吞掉）
    with StateDB(path=db_path) as db:
        assert db.get("p_legacy")["host_port"] == 50000


# ---------------------------------------------------------------------------
# docker_ctl：M2 端口/口令注入与 docker port 解析（纯逻辑，monkeypatch 假边界）
# ---------------------------------------------------------------------------


def test_gpu_passthrough_args_wsl_grid3():
    """WSL2 格 3 必须注入 dxg、两处共享目录与用户态库搜索路径。"""
    argv = docker_ctl.gpu_passthrough_args("wsl")
    assert argv[:2] == ["--device", "/dev/dxg"]
    assert "type=bind,source=/usr/lib/wsl,target=/usr/lib/wsl,readonly" in argv
    assert "type=bind,source=/mnt/wslg,target=/mnt/wslg,readonly" in argv
    assert "LD_LIBRARY_PATH=/usr/lib/wsl/lib" in argv
    assert "/dev/dri" not in argv


def test_gpu_passthrough_args_dri_and_missing_compatibility():
    """普通 Linux 与无设备环境维持既有 DRI 命令，由 doctor 负责前置报错。"""
    expected = ["--device", "/dev/dri"]
    assert docker_ctl.gpu_passthrough_args("dri") == expected
    assert docker_ctl.gpu_passthrough_args("missing") == expected


def test_gpu_passthrough_args_rejects_unknown_backend():
    with pytest.raises(ValueError, match="未知 GPU 后端"):
        docker_ctl.gpu_passthrough_args("software")


def test_build_run_command_uses_detected_wsl_gpu(monkeypatch, home):
    """真实命令组装必须使用自动探测结果，而非继续硬编码 /dev/dri。"""
    from pathlib import Path
    from tishen.persona import load

    monkeypatch.setattr(docker_ctl, "detect_gpu_backend", lambda: "wsl")
    persona = load(Path(__file__).parent / "fixtures" / "valid_cn.yaml")
    argv = docker_ctl.build_run_command(persona, "tag", home / "personas")

    assert "/dev/dxg" in argv
    assert "/dev/dri" not in argv
    assert "LD_LIBRARY_PATH=/usr/lib/wsl/lib" in argv


def test_build_run_command_neko_args(home):
    """docker run 追加 -p 127.0.0.1:0:8080 与 -e NEKO_PASSWORD=<口令>。"""
    from tishen.persona import load
    from pathlib import Path
    persona = load(Path(__file__).parent / "fixtures" / "valid_cn.yaml")
    argv = docker_ctl.build_run_command(persona, "tishen/platform:latest-stable",
                                        home / "personas", "pw-xyz")
    # 端口只发布到宿主 loopback 的随机空闲端口
    assert "-p" in argv
    assert argv[argv.index("-p") + 1] == "127.0.0.1:0:8080"
    # 口令经环境变量注入（persona-bake 第 7.5 步读取）
    assert "-e" in argv
    assert argv[argv.index("-e") + 1] == "NEKO_PASSWORD=pw-xyz"
    # M1 基线不回归
    assert f"--shm-size={docker_ctl.SHM_SIZE}" in argv
    assert "--no-sandbox" not in " ".join(argv)


def test_build_run_command_without_password_keeps_m1(home):
    """不传口令时命令与 M1 完全一致（向后兼容路径）。"""
    from tishen.persona import load
    from pathlib import Path
    persona = load(Path(__file__).parent / "fixtures" / "valid_cn.yaml")
    argv = docker_ctl.build_run_command(persona, "tag", home / "personas")
    assert "-p" not in argv and "-e" not in argv


def test_container_host_port_parse(monkeypatch):
    """docker port 输出解析：取第一个合法端口；失败返回 None。"""
    monkeypatch.setattr(docker_ctl, "_run",
                        lambda args: (0, "127.0.0.1:49153\n", ""))
    assert docker_ctl.container_host_port("p_x") == 49153
    monkeypatch.setattr(docker_ctl, "_run", lambda args: (1, "", "No such container"))
    assert docker_ctl.container_host_port("p_x") is None
    monkeypatch.setattr(docker_ctl, "_run", lambda args: (0, "垃圾输出\n", ""))
    assert docker_ctl.container_host_port("p_x") is None


def test_image_has_stream_reads_capability_label(monkeypatch):
    monkeypatch.setattr(docker_ctl, "_run", lambda args: (0, "true\n", ""))
    assert docker_ctl.image_has_stream("stream-tag") is True
    monkeypatch.setattr(docker_ctl, "_run", lambda args: (0, "false\n", ""))
    assert docker_ctl.image_has_stream("m1-tag") is False
    monkeypatch.setattr(docker_ctl, "_run", lambda args: (1, "", "missing"))
    assert docker_ctl.image_has_stream("missing-tag") is False


# ---------------------------------------------------------------------------
# cli --json 输出契约
# ---------------------------------------------------------------------------

def test_list_json_contract(home, capsys):
    """tishen list --json 输出替身数组（含 M2 新列）。"""
    with StateDB() as db:
        _add_record(db)
    assert cli.main(["list", "--json"]) == 0
    rows = json.loads(capsys.readouterr().out)
    assert isinstance(rows, list) and len(rows) == 1
    row = rows[0]
    assert row["id"] == "p_test01" and row["state"] == "creating"
    assert "host_port" in row and "neko_password" in row


def test_list_json_flag_before_subcommand(home, capsys):
    """全局 --json 放子命令前同样生效（tishen --json list）。"""
    with StateDB() as db:
        _add_record(db)
    assert cli.main(["--json", "list"]) == 0
    rows = json.loads(capsys.readouterr().out)
    assert isinstance(rows, list) and rows[0]["id"] == "p_test01"


def test_embed_url_pure_logic():
    """embed_url 拼接契约：http://127.0.0.1:{port}/?embed=1&usr=admin&pwd={口令}。"""
    url = cli._embed_url(49153, "pw123")
    assert url == "http://127.0.0.1:49153/?embed=1&usr=admin&pwd=pw123"
    # 端口或口令缺失不编造不可用 URL
    assert cli._embed_url(None, "pw123") is None
    assert cli._embed_url(49153, None) is None
    assert cli._embed_url(49153, "") is None


def _install_persona_yaml(home):
    """把合法 fixture persona 放进 $TISHEN_HOME/personas/ 供 start 加载。"""
    import shutil
    from pathlib import Path
    personas_dir = home / "personas"
    personas_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy(Path(__file__).parent / "fixtures" / "valid_cn.yaml",
                personas_dir / f"{FIXTURE_ID}.yaml")


def test_start_json_contract_new_container(home, capsys, monkeypatch):
    """start --json 契约：{id,state,host_port,embed_url,password}（假 docker 边界）。

    模拟「容器不存在 → docker run 创建」路径：口令应现场生成并经 -e 注入，
    端口经 docker port 解析，embed_url 与 password 回填一致。
    """
    _install_persona_yaml(home)
    with StateDB() as db:
        _add_record(db, FIXTURE_ID)

    captured = {}

    def fake_run_persona_container(persona, image_tag, personas_dir, neko_password):
        captured["neko_password"] = neko_password
        return 0, "container-id", ""

    monkeypatch.setattr(cli.docker_ctl, "container_exists", lambda pid: False)
    monkeypatch.setattr(cli.docker_ctl, "image_has_stream", lambda tag: True)
    monkeypatch.setattr(cli.docker_ctl, "run_persona_container",
                        fake_run_persona_container)
    monkeypatch.setattr(cli.docker_ctl, "container_host_port", lambda pid: 49153)

    assert cli.main(["start", FIXTURE_ID, "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    # 契约五字段一字不缺
    assert set(payload) == {"id", "state", "host_port", "embed_url", "password"}
    assert payload["id"] == FIXTURE_ID and payload["state"] == "active"
    assert payload["host_port"] == 49153
    assert payload["password"] == captured["neko_password"]  # 创建时生成并注入容器
    assert payload["embed_url"] == (
        f"http://127.0.0.1:49153/?embed=1&usr=admin&pwd={payload['password']}")
    # 连接信息已落状态库（外壳 getEmbedUrl 依赖）
    with StateDB() as db:
        rec = db.get(FIXTURE_ID)
        assert rec["host_port"] == 49153
        assert rec["neko_password"] == payload["password"]


def test_start_json_m1_image_has_no_fake_stream_connection(home, capsys, monkeypatch):
    """M1 四层镜像不注入口令、不发布端口，也不返回伪造的 embed URL。"""
    _install_persona_yaml(home)
    with StateDB() as db:
        _add_record(db, FIXTURE_ID)

    captured = {}

    def fake_run_persona_container(persona, image_tag, personas_dir, neko_password):
        captured["neko_password"] = neko_password
        return 0, "container-id", ""

    monkeypatch.setattr(cli.docker_ctl, "container_exists", lambda pid: False)
    monkeypatch.setattr(cli.docker_ctl, "image_has_stream", lambda tag: False)
    monkeypatch.setattr(cli.docker_ctl, "run_persona_container",
                        fake_run_persona_container)
    monkeypatch.setattr(cli.docker_ctl, "container_host_port", lambda pid: None)

    assert cli.main(["start", FIXTURE_ID, "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert captured["neko_password"] is None
    assert payload["host_port"] is None
    assert payload["password"] is None
    assert payload["embed_url"] is None


def test_start_json_existing_container_uses_stored_password(home, capsys, monkeypatch):
    """start 既有容器：不重新生成口令，取状态库已存口令拼 embed_url。"""
    _install_persona_yaml(home)
    with StateDB() as db:
        _add_record(db, FIXTURE_ID)
        db.update_connection(FIXTURE_ID, host_port=48000, neko_password="stored-pw")

    monkeypatch.setattr(cli.docker_ctl, "container_exists", lambda pid: True)
    monkeypatch.setattr(cli.docker_ctl, "start_container",
                        lambda pid: (0, "", ""))
    monkeypatch.setattr(cli.docker_ctl, "container_host_port", lambda pid: 49153)

    assert cli.main(["start", FIXTURE_ID, "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["password"] == "stored-pw"
    assert payload["embed_url"].endswith(f"pwd=stored-pw")


def test_start_human_mode_unchanged(home, capsys, monkeypatch):
    """非 --json 人类模式：输出中文连接信息，stdout 不含 JSON（M1 语义不回归）。"""
    _install_persona_yaml(home)
    with StateDB() as db:
        _add_record(db, FIXTURE_ID)
    monkeypatch.setattr(cli.docker_ctl, "container_exists", lambda pid: True)
    monkeypatch.setattr(cli.docker_ctl, "start_container", lambda pid: (0, "", ""))
    monkeypatch.setattr(cli.docker_ctl, "container_host_port", lambda pid: 49153)
    with StateDB() as db:
        db.update_connection(FIXTURE_ID, neko_password="stored-pw")

    assert cli.main(["start", FIXTURE_ID]) == 0
    out = capsys.readouterr().out
    assert "已上线" in out and "嵌入地址" in out
    assert "http://127.0.0.1:49153/?embed=1" in out


def test_events_without_observ_module(home, capsys, monkeypatch):
    """events 子命令：观测模块（M3）未安装时中文友好提示，非 traceback。"""
    with StateDB() as db:
        _add_record(db)
    # m3 合并后 observ 包常驻仓库：sys.modules 置 None 模拟"模块未安装"环境，
    # 验证 cli 的 ImportError 降级路径仍是中文人话而非 traceback（主代理合并后修正本用例）。
    monkeypatch.setitem(sys.modules, "tishen.observ.query", None)
    rc = cli.main(["events", "p_test01"])
    captured = capsys.readouterr()
    assert rc == 1
    assert "观测模块未安装（M3）" in captured.err
    assert "Traceback" not in captured.err


def test_events_with_fake_observ_module(home, capsys, monkeypatch):
    """events --json 契约：observ.query 就绪后透传 type/limit 并输出事件数组。"""
    import sys
    import types

    calls = {}
    fake_pkg = types.ModuleType("tishen.observ")
    fake_query = types.ModuleType("tishen.observ.query")

    def query_events(db_path, event_type=None, limit=50):
        calls["db_path"] = db_path
        calls["event_type"] = event_type
        calls["limit"] = limit
        return [{"type": "request", "host": "example.com"}]

    fake_query.query_events = query_events
    fake_pkg.query = fake_query
    monkeypatch.setitem(sys.modules, "tishen.observ", fake_pkg)
    monkeypatch.setitem(sys.modules, "tishen.observ.query", fake_query)

    with StateDB() as db:
        _add_record(db)
    assert cli.main(["events", "p_test01", "--type", "request",
                     "--limit", "5", "--json"]) == 0
    events = json.loads(capsys.readouterr().out)
    assert events == [{"type": "request", "host": "example.com"}]
    assert calls["event_type"] == "request" and calls["limit"] == 5
    assert calls["db_path"].endswith(f"events/p_test01.db")
