"""FastAPI 应用（SPEC-API §1/§2/§5/§6/§7/§8/§9/§10）：本地 API 桥。

运行：
    uvicorn tishen.api.app:app --host 127.0.0.1 --port ${TISHEN_API_PORT:-8788}

纪律：
- 仅绑定回环（本地优先，永不暴露局域网）；
- 函数级复用 cli/sampler/docker_ctl/state/linter/observ，严禁 shell 调 CLI 进程；
- 复用 cli 私有成员（_Doctor/_doctor_global/_current_stable_chrome/_image_tag/
  _embed_url）——同包私有成员 import，随 cli 演进需同步。
"""

from __future__ import annotations

from fastapi import Body, FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .. import cli, docker_ctl
from ..linter import LintContext, lint_persona
from ..observ.events import EVENT_TYPES
from ..persona import dump as dump_persona, validate_structure
from ..sampler import create_persona
from ..state import StateDB
from . import adapter, settings_io
from .schemas import (AlertSchema, AppSettingsSchema, CreatePersonaRequest,
                      DoctorReportSchema, EmbedSchema, LintResultSchema,
                      ObservEventSchema, PersonaSchema)

app = FastAPI(title="tishen 本地 API 桥", version="0.1.0")

# §1 CORS：vite dev 回环来源
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["GET", "POST", "PUT"],
    allow_headers=["*"],
)

_ACTIONS = {"start", "stop", "suspend", "resume", "reset", "destroy"}
# destroyed 替身拒绝的动作（§5 前置校验）；destroy 幂等可重复
_DESTROYED_FORBIDDEN = {"start", "stop", "suspend", "resume", "reset"}


# ---------------------------------------------------------------------------
# §10 统一错误格式
# ---------------------------------------------------------------------------

def _err(status: int, code: str, message: str) -> JSONResponse:
    return JSONResponse(status_code=status,
                        content={"error": {"code": code, "message": message}})


def _not_found(persona_id: str) -> JSONResponse:
    return _err(404, "PERSONA_NOT_FOUND", f"替身 {persona_id} 不存在。")


def _docker_unavailable(action: str) -> JSONResponse:
    return _err(502, "DOCKER_UNAVAILABLE",
                f"本机未找到 docker，无法执行{action}；请安装并启动 docker 后重试。")


def _docker_failed(action: str, rc: int, out: str, err: str) -> JSONResponse:
    detail = (err or out).strip()
    msg = f"{action}：docker 调用失败（退出码 {rc}）。"
    if detail:
        msg += f"docker 输出：{detail}"
    return _err(502, "DOCKER_FAILED", msg)


# ---------------------------------------------------------------------------
# 合成辅助
# ---------------------------------------------------------------------------

def _compose_or_none(persona_id: str) -> dict | None:
    """按 id 重新合成 Persona 响应；rec/persona.yaml 缺失返回 None。"""
    with StateDB() as db:
        rec = db.get(persona_id)
    if rec is None:
        return None
    persona = adapter.load_persona_or_none(persona_id)
    if persona is None:
        return None
    return adapter.compose_persona(rec, persona)


# ---------------------------------------------------------------------------
# §2 #1/#2 personas 列表与单个
# ---------------------------------------------------------------------------

@app.get("/api/personas", response_model=list[PersonaSchema],
         response_model_exclude_none=True)
def list_personas():
    with StateDB() as db:
        rows = db.list_all()  # 默认不含 destroyed
    out = []
    for rec in rows:
        persona = adapter.load_persona_or_none(rec["id"])
        if persona is None:
            # persona.yaml 缺失/损坏时 tz/resolution 等无真实来源——不编造，跳过该项
            continue
        out.append(adapter.compose_persona(rec, persona))
    return out


@app.get("/api/personas/{persona_id}", response_model=PersonaSchema,
         response_model_exclude_none=True)
def get_persona(persona_id: str):
    composed = _compose_or_none(persona_id)
    if composed is None:
        return _not_found(persona_id)
    return composed


# ---------------------------------------------------------------------------
# §2 #3 创建（对齐 cli.cmd_create 步骤；docker 缺失只警告不阻断登记）
# ---------------------------------------------------------------------------

@app.post("/api/personas", response_model=PersonaSchema, status_code=201,
          response_model_exclude_none=True)
def create_persona_endpoint(body: CreatePersonaRequest):
    if body.region not in cli.REGION_CHOICES:
        return _err(400, "INVALID_PARAM",
                    f"region 须 ∈ {cli.REGION_CHOICES}，实际为 {body.region!r}")
    try:
        persona = create_persona(
            name=body.name,
            region=body.region,
            stable_chrome=cli._current_stable_chrome(),  # 复用 cli 口径
            ip_region=None,  # 网络探测属使用者环境动作，API 不主动联网（同 cmd_create）
        )
    except (ValueError, RuntimeError) as e:
        return _err(400, "INVALID_PARAM", f"创建替身失败：{e}")

    # 落盘 persona.yaml（同 cmd_create）
    dump_persona(persona, adapter.personas_dir() / f"{persona.meta.id}.yaml")

    # 创建两个卷：docker 不可用时警告但不阻断登记（同 cmd_create 降级语义）
    for vol in (persona.storage.profile_volume, persona.storage.log_volume):
        try:
            docker_ctl.volume_create(vol)
        except FileNotFoundError:
            continue  # 沙盒/未装 docker：使用者在真实环境补建

    # 状态库登记 creating（同 cmd_create）
    with StateDB() as db:
        db.add(persona_id=persona.meta.id, name=persona.meta.name,
               region=persona.region.detected_ip_region,
               state="creating",
               chrome_baseline=persona.evolution.baseline_chrome)
    return _compose_or_none(persona.meta.id)


# ---------------------------------------------------------------------------
# §2 #4 / §5 生命周期动作
# ---------------------------------------------------------------------------

@app.post("/api/personas/{persona_id}/{action}", response_model=PersonaSchema,
          response_model_exclude_none=True)
def persona_action(persona_id: str, action: str):
    if action not in _ACTIONS:
        # 实现自择（SPEC-API §11.3）：非法 action → 400 INVALID_PARAM
        return _err(400, "INVALID_PARAM",
                    f"未知生命周期动作 {action!r}，合法动作：{sorted(_ACTIONS)}")
    with StateDB() as db:
        rec = db.get(persona_id)
        if rec is None:
            return _not_found(persona_id)
        if rec["state"] == "destroyed" and action in _DESTROYED_FORBIDDEN:
            return _err(409, "STATE_CONFLICT",
                        f"替身 {persona_id} 已销毁，不可执行 {action}。")

        persona = None
        if action in {"start", "reset", "destroy"}:
            # 同 cli：这三个动作需要 persona.yaml（容器编排/卷名来源）
            persona = adapter.load_persona_or_none(persona_id)
            if persona is None:
                return _err(404, "PERSONA_NOT_FOUND",
                            f"替身 {persona_id} 的 persona 文件缺失或损坏。")

        try:
            if action == "start":
                # 步骤与 cli.cmd_start 对齐（json_mode 分支除外）
                exists = docker_ctl.container_exists(persona_id)
                new_password = None
                if exists:
                    rc, out, err = docker_ctl.start_container(persona_id)
                else:
                    # M2：创建容器时生成随机 neko 口令，经 -e 注入
                    new_password = docker_ctl.generate_neko_password()
                    rc, out, err = docker_ctl.run_persona_container(
                        persona, cli._image_tag(), adapter.personas_dir(),
                        new_password)
                if rc != 0:
                    return _docker_failed(f"启动替身 {persona_id}", rc, out, err)
                db.update_state(persona_id, "active")
                host_port = docker_ctl.container_host_port(persona_id)
                db.update_connection(persona_id, host_port=host_port,
                                     neko_password=new_password)

            elif action == "stop":
                # 对齐 cli.cmd_stop；M1 四态枚举无 stopped，归并 suspended
                rc, out, err = docker_ctl.stop_container(persona_id)
                if rc != 0:
                    return _docker_failed(f"停止替身 {persona_id}", rc, out, err)
                db.update_state(persona_id, "suspended")

            elif action == "suspend":
                # 对齐 cli.cmd_suspend
                rc, out, err = docker_ctl.pause_container(persona_id)
                if rc != 0:
                    return _docker_failed(f"挂起替身 {persona_id}", rc, out, err)
                db.update_state(persona_id, "suspended")

            elif action == "resume":
                # 对齐 cli.cmd_resume
                rc, out, err = docker_ctl.unpause_container(persona_id)
                if rc != 0:
                    return _docker_failed(f"恢复替身 {persona_id}", rc, out, err)
                db.update_state(persona_id, "active")

            elif action == "reset":
                # 无交互变体：前端已做输名确认，API 不重复。
                # 以下步骤与 cli.cmd_reset 逐行对齐（仅去掉交互确认段）：
                docker_ctl.rm_container(persona_id, force=True)
                rc, out, err = docker_ctl.volume_rm(persona.storage.profile_volume)
                # cli 中删 profile 卷失败仅警告不阻断（容器已删，卷可能本就不在）
                rc, out, err = docker_ctl.volume_create(persona.storage.profile_volume)
                if rc != 0:
                    return _docker_failed(
                        f"重建 profile 卷 {persona.storage.profile_volume}",
                        rc, out, err)
                db.update_state(persona_id, "creating")

            else:  # destroy
                # 步骤与 cli.cmd_destroy 对齐
                rc, out, err = docker_ctl.rm_container(persona_id, force=True)
                if rc != 0 and "No such container" not in (err or ""):
                    return _docker_failed("删除容器", rc, out, err)
                for vol in (persona.storage.profile_volume,
                            persona.storage.log_volume):
                    # cli 中删卷失败仅警告（尽力清理，状态推进不阻断）
                    docker_ctl.volume_rm(vol)
                db.update_state(persona_id, "destroyed")

        except FileNotFoundError:
            return _docker_unavailable(f"{action} 替身 {persona_id}")

    composed = _compose_or_none(persona_id)
    if composed is None:
        return _not_found(persona_id)
    return composed


# ---------------------------------------------------------------------------
# §2 #5 embed 地址
# ---------------------------------------------------------------------------

@app.get("/api/personas/{persona_id}/embed", response_model=EmbedSchema)
def get_embed(persona_id: str):
    with StateDB() as db:
        rec = db.get(persona_id)
    if rec is None:
        return _not_found(persona_id)
    # 复用 cli._embed_url：host_port/neko_password 缺任一 → 无连接信息
    url = cli._embed_url(rec.get("host_port"), rec.get("neko_password"))
    return {"embedUrl": url or ""}


# ---------------------------------------------------------------------------
# §2 #6 / §4 事件查询
# ---------------------------------------------------------------------------

@app.get("/api/personas/{persona_id}/events",
         response_model=list[ObservEventSchema])
def get_events(persona_id: str,
               type: str | None = Query(default=None),
               limit: int = Query(default=50),
               q: str | None = Query(default=None)):
    with StateDB() as db:
        if db.get(persona_id) is None:
            return _not_found(persona_id)
    if type is not None and type not in EVENT_TYPES:
        return _err(400, "INVALID_PARAM",
                    f"type 须 ∈ {sorted(EVENT_TYPES)}，实际为 {type!r}")
    if limit <= 0 or limit > 1000:
        return _err(400, "INVALID_PARAM",
                    f"limit 须为 1–1000，实际为 {limit!r}")

    from ..observ.query import query_events
    db_path = adapter.events_db_path(persona_id)
    if q:
        # q 为 API 层内存过滤（query_events 不支持 q）——近似口径：
        # 先取 limit×4 条再过滤再截 limit，命中数可能少于库内真实命中数
        raw = query_events(db_path, event_type=type, limit=limit * 4)
        mapped = adapter.filter_by_q([adapter.map_event(e) for e in raw], q)
        return mapped[:limit]
    raw = query_events(db_path, event_type=type, limit=limit)
    return [adapter.map_event(e) for e in raw]


# ---------------------------------------------------------------------------
# §2 #7 / §6 lint 门禁
# ---------------------------------------------------------------------------

# V1–V10 检查项中文短句（label 自 linter.py 各规则语义提炼，非前端 mock 标签）
_CHECK_LABELS = {
    "V1": "属地族一致：时区/locale/语言与实测 IP 属地同族",
    "V2": "OS 锁定：声明平台与真实运行环境（linux）一致",
    "V3": "GPU 禁撒谎：host 透传且渲染器字符串取宿主真实值",
    "V4": "分辨率真实：分辨率 ∈ 常见真实集且 DPR ∈ 真实缩放比",
    "V5": "硬件搭配合理：核数与内存档位符合真实设备分布",
    "V6": "版本新鲜：基线 Chrome 不落后当前 stable 超过一个主版本",
    "V7": "字体包匹配：字体包与 OS 族匹配，CJK 附加包有语言/属地依据",
    "V8": "种子合法：farbling 种子为 128-bit 小写十六进制",
    "V9": "WebRTC 禁泄露：IP 处理策略为 disable_non_proxied_udp",
    "V10": "代理边界：proxy 为 null 或合法 socks5/http 端点",
}


@app.get("/api/personas/{persona_id}/lint", response_model=LintResultSchema)
def get_lint(persona_id: str):
    with StateDB() as db:
        if db.get(persona_id) is None:
            return _not_found(persona_id)
    persona = adapter.load_persona_or_none(persona_id)
    if persona is None:
        return _err(404, "PERSONA_NOT_FOUND",
                    f"替身 {persona_id} 的 persona 文件缺失或损坏。")

    errors: list[dict] = []
    struct_errors = validate_structure(persona)
    for msg in struct_errors:
        # 结构错误 code 固定 STRUCT；消息形如 "path: msg"，按首个 ": " 切分；无则 field=""
        field, sep, text = msg.partition(": ")
        if sep:
            errors.append({"code": "STRUCT", "field": field, "message": text})
        else:
            errors.append({"code": "STRUCT", "field": "", "message": msg})

    # LintContext 与 cmd_lint 口径一致：current stable 走环境变量/默认值，
    # detected_ip_region 取 persona.region.detected_ip_region
    ctx = LintContext(current_stable_chrome=cli._current_stable_chrome(),
                      detected_ip_region=persona.region.detected_ip_region)
    lint_errors = lint_persona(persona, ctx)
    for e in lint_errors:
        errors.append({"code": e.code, "field": e.field, "message": e.message})

    lint_codes = {e.code for e in lint_errors}
    checks = []
    for i in range(1, 11):
        code = f"V{i}"
        # pass = 该 code 未出现在 errors 且结构校验通过
        # （STRUCT 失败时 V1 标 fail，其余按实际）
        passed = f"LINT_{code}" not in lint_codes
        if i == 1 and struct_errors:
            passed = False
        checks.append({"code": code, "label": _CHECK_LABELS[code], "pass": passed})

    return {"ok": not errors, "errors": errors, "checks": checks}


# ---------------------------------------------------------------------------
# §2 #8/#11 / §7 告警
# ---------------------------------------------------------------------------

@app.get("/api/alerts", response_model=list[AlertSchema])
def list_alerts():
    with StateDB() as db:
        rows = db.list_all()  # 不含 destroyed
    return adapter.derive_alerts(rows, settings_io.read_acks())


@app.post("/api/alerts/{event_id}/ack", response_model=AlertSchema)
def ack_alert(event_id: str):
    with StateDB() as db:
        rows = db.list_all()
    acked = settings_io.read_acks()
    for alert in adapter.derive_alerts(rows, acked):
        if alert["id"] == event_id:
            settings_io.add_ack(event_id)  # 幂等
            alert["acknowledged"] = True
            return alert
    return _err(404, "EVENT_NOT_FOUND", f"告警事件 {event_id} 不存在。")


# ---------------------------------------------------------------------------
# §2 #9 / §8 doctor
# ---------------------------------------------------------------------------

@app.get("/api/doctor", response_model=DoctorReportSchema)
def get_doctor():
    # 复用 cli._Doctor 与 cli._doctor_global（同包私有成员 import，随 cli 演进需同步）；
    # 有失败项仍 200——前端引导页需要完整报告，不用错误码表达
    doc = cli._Doctor(json_mode=True)
    cli._doctor_global(doc)
    return {"items": [{"name": it["item"], "ok": it["ok"],
                       "hint": it["fix"] or it["detail"]}
                      for it in doc.items]}


# ---------------------------------------------------------------------------
# §2 #10 / §9 settings
# ---------------------------------------------------------------------------

@app.get("/api/settings", response_model=AppSettingsSchema)
def get_settings():
    data = settings_io.read_settings()
    if settings_io.validate_settings(data) is not None:
        # 文件内容形状非法：视同缺文件，回退默认（不编造、不 500）
        data = dict(settings_io.DEFAULT_SETTINGS)
    return data


@app.put("/api/settings", response_model=AppSettingsSchema)
def put_settings(body: dict = Body(...)):
    msg = settings_io.validate_settings(body)
    if msg is not None:
        return _err(400, "INVALID_PARAM", msg)
    settings_io.write_settings(body)
    return body
