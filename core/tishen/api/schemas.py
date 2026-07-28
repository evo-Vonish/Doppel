"""API 桥 Pydantic 模型（SPEC-API §3/§4/§6/§7/§8/§9）。

字段名与前端 app/src/api/types.ts 逐字段一致（camelCase）。
数据真实性纪律：没有真实来源的可选字段（embedUrl/hostPort）为 None，
由路由层以 response_model_exclude_none=True 省略该键，不编造。
"""

from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field


# ---------------------------------------------------------------------------
# §3 Persona（替身）
# ---------------------------------------------------------------------------

class PersonaSchema(BaseModel):
    id: str
    name: str
    region: str                                  # ISO alpha-2，如 CN
    state: Literal["creating", "active", "suspended", "destroyed"]
    chromeVersion: str
    createdAt: str                               # ISO8601 字符串原样输出
    todayMinutes: int
    embedUrl: Optional[str] = None               # 缺连接信息时省略该键
    hostPort: Optional[int] = None               # None 时省略该键
    tz: str
    locale: str
    resolution: str                              # f"{w}×{h} @{dpr:g}x"（× = U+00D7）
    gpu: str                                     # 宿主 GPU 透传（renderer_string_source）


class CreatePersonaRequest(BaseModel):
    """POST /api/personas 请求体（SPEC-API §2 表 #3）。"""
    name: str = Field(min_length=1, max_length=32)
    region: str = "auto"                         # auto/CN/HK/TW/JP/US/GB/DE


# ---------------------------------------------------------------------------
# §4 ObservEvent（观测事件，后端 18 字段 dict → 前端 9 字段）
# ---------------------------------------------------------------------------

class ObservEventSchema(BaseModel):
    id: str
    ts: str                                      # Unix 毫秒 → ISO8601 秒（东八区）
    personaId: str
    type: str
    pageHost: str
    targetHost: str
    summary: str
    alertLevel: int                              # 0=普通 1=提示 2=警告 3=危险
    detail: dict[str, str]                       # 其余原始字段平铺（None→""，int→str）


# ---------------------------------------------------------------------------
# §7 Alert（分级告警）
# ---------------------------------------------------------------------------

class AlertSchema(BaseModel):
    id: str
    level: int                                   # 1|2|3（alert_level ≥ 1 派生）
    title: str
    personaId: str
    host: str
    evidence: list[str]
    ts: str
    acknowledged: bool


# ---------------------------------------------------------------------------
# §6 LintResult（出厂门禁）
# ---------------------------------------------------------------------------

class LintErrorSchema(BaseModel):
    code: str                                    # STRUCT / LINT_V1..LINT_V10
    field: str
    message: str


class LintCheckSchema(BaseModel):
    """V1–V10 逐条检查；前端字段名为 pass（Python 关键字，用别名）。"""
    model_config = ConfigDict(populate_by_name=True)

    code: str                                    # V1..V10
    label: str                                   # 中文短句（linter.py 规则语义提炼）
    passed: bool = Field(alias="pass")


class LintResultSchema(BaseModel):
    ok: bool
    errors: list[LintErrorSchema]
    checks: list[LintCheckSchema]


# ---------------------------------------------------------------------------
# §8 Doctor（自检）
# ---------------------------------------------------------------------------

class DoctorItemSchema(BaseModel):
    name: str
    ok: bool
    hint: str


class DoctorReportSchema(BaseModel):
    items: list[DoctorItemSchema]


# ---------------------------------------------------------------------------
# §9 Settings（设置，含双模式开关）
# ---------------------------------------------------------------------------

class SettingsPackagesSchema(BaseModel):
    easyPrivacy: bool
    trackerRadar: bool
    trackerDb: bool


class AppSettingsSchema(BaseModel):
    mode: Literal["default", "expert"]
    packages: SettingsPackagesSchema
    retainDays: int                              # 合法值 {7,14,30}，路由层校验


# ---------------------------------------------------------------------------
# §5 Embed / §10 统一错误
# ---------------------------------------------------------------------------

class EmbedSchema(BaseModel):
    embedUrl: str                                # 无连接信息时 ""


class ErrorBody(BaseModel):
    code: str
    message: str


class ErrorResponse(BaseModel):
    error: ErrorBody
