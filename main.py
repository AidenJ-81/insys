import os
import json
import sqlite3
import hashlib
import secrets
import urllib.request
import urllib.error
from contextlib import closing
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, Request, Response, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

# ---------------------------------------------------------------------------
# 설정 (환경변수)
# ---------------------------------------------------------------------------
DB_PATH = os.environ.get("DB_PATH", "./data/app.db")
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "true").lower() != "false"
ALLOWED_EMAIL_DOMAIN = os.environ.get("ALLOWED_EMAIL_DOMAIN", "xicna.com").strip().lstrip("@")
SESSION_COOKIE_NAME = "insys_session"

# AI 제공자 설정 - Anthropic이 기본값이지만 다른 제공자로 교체 가능
AI_PROVIDER = os.environ.get("AI_PROVIDER", "anthropic")  # anthropic | openai | worksai | custom
AI_API_KEY = os.environ.get("AI_API_KEY", "")
AI_MODEL = os.environ.get("AI_MODEL", "claude-sonnet-4-6")
AI_BASE_URL = os.environ.get("AI_BASE_URL", "")  # custom 제공자(예: 웍스AI) 사용 시 엔드포인트 지정
AI_AGENT_ID = os.environ.get("AI_AGENT_ID", "")  # 웍스AI 전용 - 사용할 에이전트 ID

app = FastAPI(title="INSYS")


# ---------------------------------------------------------------------------
# DB
# ---------------------------------------------------------------------------
def get_db():
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


DEFAULT_EVAL_ITEMS = [
    {"name": "최적의 의사결정", "desc":
"""[직책자] 합의가 어렵거나, 저항 및 부정적 반응이 예상되는 사안에 대해서도 분명하게 의사결정하는 리더입니까?
[비직책자] 축적된 경험과 노하우를 기반으로 사안의 중요도와 우선순위를 고려하여 시의적절하게 대처하는 동료입니까?
1~2점: 해당 업무 혹은 현안 이슈에 대한 이해와 전문지식/경험이 부족함
3~5점: 본인 업무 및 타 분야의 업무지식까지 두루 갖추었으며, 복잡한 문제들의 근본원인을 파악하고 대안을 제시함
6~7점: 새롭고 창의적인 방법론을 만들 수 있을 정도로 유능하며, 잠재적인 문제도 예측하여 새로운 대안을 수립함"""},
    {"name": "신속한 의사결정 및 정보/의견 제공", "desc":
"""[직책자] 다양한 대안들을 신속하게 검토하여 의사결정하는 리더입니까?
[비직책자] 리더가 최적의 의사결정을 할 수 있도록 다양한 정보와 구성원들의 의견을 수집/제공할 수 있는 동료입니까?
1~2점: 책임전가/회피를 위해 의도적으로 의사결정을 지연함
3~5점: 수집된 정보/이슈 등을 정확히 분석하고, 의사결정시 적절히 활용함
6~7점: 깊은 Insight를 바탕으로, 여러 대안들을 정확히 판단하고 의사결정의 파급효과까지 고려하여 적시에 의사결정함"""},
    {"name": "업무의 조정/조율", "desc":
"""[직책자] 팀 내 업무 공백 및 중복을 최소화하기 위해 팀원 간의 업무를 조율하거나 조정하는 리더입니까?
[비직책자] 팀 내 업무 공백 및 중복 발생 여부를 파악하고, 업무를 조율 및 조정하는 데 능동적으로 참여하는 동료입니까?
1~2점: 개인의 이익을 최우선시하며 본인의 업무효율만을 중요시함
3~5점: 업무관련 절차를 준수하는 수준에서 팀 내 업무를 조정/조율함
6~7점: 회사의 전략과 목표 달성을 위해 절차를 준수하며 성과창출에 기여할 수 있도록 팀 내 업무를 조정/조율함"""},
    {"name": "구체적 정보제공 및 이슈사항 공유", "desc":
"""[직책자] 구체적인 설명(배경, 산출물, 마감기한 등)과 함께 명확하게 업무를 지시하는 리더입니까?
[비직책자] 업무 수행 과정에서 본인의 경험, 노하우를 기반으로 파악한 이슈사항을 구성원들에게 자발적으로 공유하는 동료입니까?
1~2점: 업무에 대한 공유 및 지시가 매우 미흡함
3~5점: 업무 수행과정에 있어 필요한 범위 내 공유함
6~7점: 이슈사항을 구체적이고 명확하게 전달하며 본인의 경험을 자발적으로 공유함"""},
    {"name": "업무추진사항 모니터링 및 장애요인 파악", "desc":
"""[직책자] 구성원들의 업무 추진 현황을 지속적으로 모니터링하고, 개선이 필요한 부분을 파악하여 적절한 지시를 내리는 리더입니까?
[비직책자] 구성원들의 성과 창출을 저해하는 요인을 파악하고, 해소할 수 있도록 의견을 제공할 수 있는 동료입니까?
1~2점: '일단 하고보자'라는 식으로 무조건적인 실행만 강조하며, 업무 진척도를 주기적으로 관리하지 않음
3~5점: 도전적 목표를 설정하고, 달성방법과 추진일정 등을 구체적으로 수립함
6~7점: 실행 중 발생가능한 예상이슈를 사전에 발굴하고 대안까지 마련하며, 이슈 발생 시 즉각 개선 방안을 마련하여 강력히 실천함"""},
    {"name": "환경변화에 따른 상황적응력", "desc":
"""[직책자] 내/외부 환경 변화를 고려하며 업무의 우선순위를 조율 및 조정하는 리더입니까?
[비직책자] 내/외부 환경 변화에 업무 수행 방식 및 수행 시기를 유연하게 변화시킬 수 있는 동료입니까?
1~2점: 본인 업무 외 경영환경 및 시장 변화에 무관심하고, 단기적 목표 달성에 얽매이며 기존의 방식을 고수함
3~5점: 단기적 이슈에 대응하는 수준이며, 본인 업무에 국한하여 개선을 시도함
6~7점: 환경 변화를 예측하여 새로운 기회를 발굴하고, 이를 선점하기 위한 전략, 혁신방안을 개발/적용함"""},
    {"name": "행동변화 독려 및 비전 정렬", "desc":
"""[직책자] 내/외부 환경 변화에 대응하기 위해 본인은 물론 구성원들의 행동변화를 독려하는 리더입니까?
[비직책자] 조직의 비전과 개인의 비전 간 연계를 위해 스스로 어떠한 노력을 해야하는지 계획을 구체화하고, 계획대로 실행하기 위해 노력하는 동료입니까?
1~2점: 조직의 비전, 환경의 변화에 무관심하며 개인의 이익만을 최우선시하며 업무를 수행함
3~5점: 본인의 행동변화를 개선하는 수준임
6~7점: 환경변화에 대응하기 위해 스스로 노력하고 본인 뿐만 아니라 구성원들의 행동변화를 독려함"""},
    {"name": "비전 및 목적 제시", "desc":
"""[직책자] 조직의 비전과 목적에 대해 충분한 설명을 제시하고, 비전 달성에 대한 열정을 가질 수 있도록 독려하는 리더입니까?
[비직책자] 조직의 비전 및 목적에 대해 충분히 이해하고 있으며, 비전 및 목적 달성에 열정을 가지고 있는 동료입니까?
1~2점: 비전/미션 및 중장기 목표보다는 단기목표 달성에 얽매임
3~5점: 조직의 비전과 미션을 명확히 제시하는 수준임
6~7점: 조직의 비전과 구성원 개인간의 비전을 Alignment 하여, 구성원들의 자발적 참여를 유도함"""},
    {"name": "적극적 소통 및 심리적안전감 조성", "desc":
"""[직책자] 구성원들이 Speak Up 할 수 있도록 분위기를 조성하며 구성원들의 의견을 적극적으로 경청/수렴하는 리더입니까?
[비직책자] 문제 해결을 위해 상대방의 의견을 경청하고, 새로운 아이디어와 접근 방식을 적극적으로 제안하는 동료입니까?
1~2점: 이기주의 성향이 있으며 업무정보와 자원을 독점함
3~5점: 평균적인 수준에서 헌신하며 조직 내에서 협력을 창출하기 위해 노력함
6~7점: 회사 전체의 성과를 위해 개인과 부서의 이익도 기꺼이 희생하며, 구성원(동료)에게도 협력을 적극 독려함"""},
    {"name": "코칭 및 피드백", "desc":
"""[직책자] 적극적으로 자상하게 코칭하고 업무결과에 대하여 즉시 피드백 하며, 부하(후배)직원의 개인적 성장을 물심양면 지원하는 리더입니까?
[비직책자] 동료의 성장과 업무적 성공을 위해 관심을 가지고 적극적으로 의견을 전달하는 동료입니까?
1~2점: 구성원의 성장에 무관심하며 업무수행만을 강조함
3~5점: 업무수행과 관련된 코칭/피드백은 있으나 구성원 개인의 장기적 성장에 대해서는 다소 무관심함
6~7점: 평소 세밀하게 코칭하고 격려할 뿐만 아니라 개인의 성장에도 적극 관심을 가지고 다양하게 지원함"""},
]

DEFAULT_COMPANY_PROFILE = """[비전] 국내 Top Tier 산업플랜트 Provider

[핵심가치 및 조직문화 4대 지향점]
- 혁신: 실패에서 배우고, 재발을 막는 조직
- 전문성: 전문성을 최고의 가치로 여기는 조직
- 사람중심: 오픈 커뮤니케이션이 당연한 조직
- 동반성장: 부서·현장을 넘어 함께 움직이는 조직 (One-Team Spirit에 기반한 조직 플레이)

[핵심가치 선순환 체계]
역량에 대한 자신감이 생기면 틀릴 것을 두려워하지 않고 솔직하게 소통할 수 있다. 심리적 안전감이 보장된 조직에서는 같은 실패를 반복하지 않고 새로운 도전이 가능해진다. 이렇게 실패와 도전을 통해 축적된 경험을 함께 나누면 우리만의 자산이 되고, 신뢰를 기반으로 함께 성장함으로써 더욱 높은 수준의 전문성을 갖추게 된다.

[2026년 슬로건]
2026년 실행의 해 - 우리가 함께 만드는 조직문화. 자이C&A의 실행력은 우리가 함께 만드는 조직문화에서 시작된다.

[마무리 메시지]
우리는 배움을 두려워하지 않는 전문가이며, 언제나 솔직하게 소통하는 하나의 팀이다."""


def init_db():
    with closing(get_db()) as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'member',
                app_admin_role TEXT NOT NULL DEFAULT 'member',
                approved INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS user_data (
                user_id INTEGER PRIMARY KEY,
                data_json TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS company_settings (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                company_profile TEXT NOT NULL DEFAULT '',
                eval_items TEXT NOT NULL DEFAULT '[]',
                eval_item_details TEXT NOT NULL DEFAULT '{}',
                updated_at TEXT NOT NULL
            );
            """
        )
        # 기존 DB에 app_admin_role 컬럼이 없을 수 있으니 안전하게 추가 시도 (이미 있으면 무시)
        try:
            conn.execute("ALTER TABLE users ADD COLUMN app_admin_role TEXT NOT NULL DEFAULT 'member'")
        except sqlite3.OperationalError:
            pass
        conn.commit()

        # 기존 DB를 업그레이드하는 경우, 관리자(정)이 아무도 없으면 가장 먼저 가입한 사람을 승격
        primary_count = conn.execute("SELECT COUNT(*) c FROM users WHERE app_admin_role = 'primary'").fetchone()["c"]
        if primary_count == 0:
            earliest = conn.execute("SELECT id FROM users ORDER BY created_at ASC LIMIT 1").fetchone()
            if earliest:
                conn.execute("UPDATE users SET app_admin_role = 'primary' WHERE id = ?", (earliest["id"],))
                conn.commit()

        row = conn.execute("SELECT id FROM company_settings WHERE id = 1").fetchone()
        if not row:
            conn.execute(
                "INSERT INTO company_settings (id, company_profile, eval_items, eval_item_details, updated_at) "
                "VALUES (1, ?, ?, ?, ?)",
                (
                    DEFAULT_COMPANY_PROFILE,
                    json.dumps([it["name"] for it in DEFAULT_EVAL_ITEMS], ensure_ascii=False),
                    json.dumps({it["name"]: it["desc"] for it in DEFAULT_EVAL_ITEMS}, ensure_ascii=False),
                    now_iso(),
                ),
            )
            conn.commit()


# ---------------------------------------------------------------------------
# 비밀번호 해싱 (외부 라이브러리 없이 표준 라이브러리만 사용)
# ---------------------------------------------------------------------------
def make_salt() -> str:
    return secrets.token_hex(16)


def hash_password(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 200_000).hex()


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

init_db()


# ---------------------------------------------------------------------------
# 세션 / 인증 헬퍼
# ---------------------------------------------------------------------------
def create_session(user_id: int) -> str:
    token = secrets.token_urlsafe(32)
    with closing(get_db()) as conn:
        conn.execute(
            "INSERT INTO sessions (token, user_id, created_at) VALUES (?, ?, ?)",
            (token, user_id, now_iso()),
        )
        conn.commit()
    return token


def get_user_from_request(request: Request):
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if not token:
        return None
    with closing(get_db()) as conn:
        row = conn.execute(
            "SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ?",
            (token,),
        ).fetchone()
    return row


def require_user(request: Request):
    user = get_user_from_request(request)
    if not user:
        raise HTTPException(status_code=401, detail="로그인이 필요합니다.")
    if not user["approved"]:
        raise HTTPException(status_code=403, detail="관리자 승인 대기중입니다.")
    return user


def require_admin(request: Request):
    user = require_user(request)
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="관리자만 접근할 수 있습니다.")
    return user


def require_app_admin(request: Request):
    user = require_user(request)
    if user["app_admin_role"] not in ("primary", "secondary"):
        raise HTTPException(status_code=403, detail="관리자(정) 또는 관리자(부) 권한이 필요합니다.")
    return user


def require_app_primary(request: Request):
    user = require_user(request)
    if user["app_admin_role"] != "primary":
        raise HTTPException(status_code=403, detail="관리자(정) 권한이 필요합니다.")
    return user


def set_session_cookie(response: Response, token: str):
    response.set_cookie(
        SESSION_COOKIE_NAME,
        token,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="lax",
        max_age=60 * 60 * 24 * 30,
        path="/",
    )


# ---------------------------------------------------------------------------
# 요청 바디 모델
# ---------------------------------------------------------------------------
class AuthBody(BaseModel):
    email: str
    password: str


class RoleBody(BaseModel):
    role: str


class DataBody(BaseModel):
    data: dict


class CompanySettingsBody(BaseModel):
    companyProfile: Optional[str] = None
    evalItems: Optional[list] = None
    evalItemDetails: Optional[dict] = None


class TransferPrimaryBody(BaseModel):
    targetUserId: int


class SecondaryBody(BaseModel):
    targetUserId: int
    enabled: bool


class AIBody(BaseModel):
    prompt: str = ""
    max_tokens: int = 1200
    content: Optional[list] = None  # 이미지/문서 등 멀티모달 콘텐츠 블록 (있으면 prompt 대신 사용)


# ---------------------------------------------------------------------------
# 인증 API
# ---------------------------------------------------------------------------
@app.post("/api/auth/signup")
def signup(body: AuthBody, response: Response):
    email = body.email.strip().lower()
    if not email or "@" not in email:
        raise HTTPException(400, "올바른 이메일을 입력해주세요.")
    if ALLOWED_EMAIL_DOMAIN and not email.endswith("@" + ALLOWED_EMAIL_DOMAIN):
        raise HTTPException(400, f"{ALLOWED_EMAIL_DOMAIN} 도메인 이메일만 가입할 수 있습니다.")
    if len(body.password) < 6:
        raise HTTPException(400, "비밀번호는 6자 이상이어야 합니다.")

    salt = make_salt()
    pw_hash = hash_password(body.password, salt)

    with closing(get_db()) as conn:
        existing = conn.execute("SELECT COUNT(*) c FROM users").fetchone()["c"]
        is_first = existing == 0
        try:
            cur = conn.execute(
                "INSERT INTO users (email, password_hash, salt, role, app_admin_role, approved, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (email, pw_hash, salt, "admin" if is_first else "member",
                 "primary" if is_first else "member", 1, now_iso()),
            )
        except sqlite3.IntegrityError:
            raise HTTPException(400, "이미 가입된 이메일입니다.")
        conn.commit()
        user_id = cur.lastrowid
        conn.execute(
            "INSERT INTO user_data (user_id, data_json, updated_at) VALUES (?, ?, ?)",
            (user_id, "{}", now_iso()),
        )
        conn.commit()

    token = create_session(user_id)
    set_session_cookie(response, token)
    return {
        "status": "ok", "approved": True,
        "role": "admin" if is_first else "member",
        "appAdminRole": "primary" if is_first else "member",
    }


@app.post("/api/auth/login")
def login(body: AuthBody, response: Response):
    email = body.email.strip().lower()
    with closing(get_db()) as conn:
        user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    if not user or hash_password(body.password, user["salt"]) != user["password_hash"]:
        raise HTTPException(401, "이메일 또는 비밀번호가 올바르지 않습니다.")
    if not user["approved"]:
        raise HTTPException(403, "관리자 승인 대기중입니다.")
    token = create_session(user["id"])
    set_session_cookie(response, token)
    return {"status": "ok", "email": user["email"], "role": user["role"], "appAdminRole": user["app_admin_role"]}


@app.post("/api/auth/logout")
def logout(request: Request, response: Response):
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if token:
        with closing(get_db()) as conn:
            conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
            conn.commit()
    response.delete_cookie(SESSION_COOKIE_NAME, path="/")
    return {"status": "ok"}


@app.get("/api/auth/me")
def me(request: Request):
    user = get_user_from_request(request)
    if not user:
        raise HTTPException(401, "로그인이 필요합니다.")
    return {
        "email": user["email"], "role": user["role"], "approved": bool(user["approved"]),
        "appAdminRole": user["app_admin_role"],
    }


# ---------------------------------------------------------------------------
# 관리자 API (팀원 관리)
# ---------------------------------------------------------------------------
@app.get("/api/admin/users")
def list_users(request: Request):
    require_admin(request)
    with closing(get_db()) as conn:
        rows = conn.execute(
            "SELECT id, email, role, approved, created_at FROM users ORDER BY created_at"
        ).fetchall()
    return [dict(r) for r in rows]


@app.post("/api/admin/users/{user_id}/role")
def change_role(user_id: int, body: RoleBody, request: Request):
    require_admin(request)
    if body.role not in ("admin", "member"):
        raise HTTPException(400, "잘못된 역할입니다.")
    with closing(get_db()) as conn:
        if body.role == "member":
            admin_count = conn.execute("SELECT COUNT(*) c FROM users WHERE role='admin'").fetchone()["c"]
            target = conn.execute("SELECT role FROM users WHERE id = ?", (user_id,)).fetchone()
            if target and target["role"] == "admin" and admin_count <= 1:
                raise HTTPException(400, "마지막 관리자는 일반으로 내릴 수 없습니다.")
        conn.execute("UPDATE users SET role = ? WHERE id = ?", (body.role, user_id))
        conn.commit()
    return {"status": "ok"}


@app.post("/api/admin/users/{user_id}/remove")
def remove_user(user_id: int, request: Request):
    admin = require_admin(request)
    if admin["id"] == user_id:
        raise HTTPException(400, "본인 계정은 스스로 내보낼 수 없습니다.")
    with closing(get_db()) as conn:
        target = conn.execute("SELECT role FROM users WHERE id = ?", (user_id,)).fetchone()
        if not target:
            raise HTTPException(404, "사용자를 찾을 수 없습니다.")
        if target["role"] == "admin":
            admin_count = conn.execute("SELECT COUNT(*) c FROM users WHERE role='admin'").fetchone()["c"]
            if admin_count <= 1:
                raise HTTPException(400, "마지막 관리자는 내보낼 수 없습니다.")
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.execute("DELETE FROM user_data WHERE user_id = ?", (user_id,))
        conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
        conn.commit()
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# 개인 데이터 API (기록/목표/구성원 등 - window.storage를 대체)
# ---------------------------------------------------------------------------
@app.get("/api/data")
def get_data(request: Request):
    user = require_user(request)
    with closing(get_db()) as conn:
        row = conn.execute(
            "SELECT data_json FROM user_data WHERE user_id = ?", (user["id"],)
        ).fetchone()
    if not row:
        return {}
    try:
        return json.loads(row["data_json"])
    except Exception:
        return {}


@app.put("/api/data")
def put_data(body: DataBody, request: Request):
    user = require_user(request)
    payload = json.dumps(body.data, ensure_ascii=False)
    if len(payload.encode("utf-8")) > 8_000_000:
        raise HTTPException(400, "저장할 데이터가 너무 큽니다.")
    with closing(get_db()) as conn:
        conn.execute(
            "INSERT INTO user_data (user_id, data_json, updated_at) VALUES (?, ?, ?) "
            "ON CONFLICT(user_id) DO UPDATE SET data_json = excluded.data_json, updated_at = excluded.updated_at",
            (user["id"], payload, now_iso()),
        )
        conn.commit()
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# 회사 공용 설정 (회사 비전/조직문화, 리더십 평가요소) - 모든 계정이 함께 보는 데이터.
# 조회는 로그인한 누구나 가능(리더십 진단 AI가 참고해야 하므로), 수정은 관리자(정/부)만 가능.
# ---------------------------------------------------------------------------
@app.get("/api/company-settings")
def get_company_settings(request: Request):
    require_user(request)
    with closing(get_db()) as conn:
        row = conn.execute(
            "SELECT company_profile, eval_items, eval_item_details FROM company_settings WHERE id = 1"
        ).fetchone()
    if not row:
        return {"companyProfile": "", "evalItems": [], "evalItemDetails": {}}
    try:
        eval_items = json.loads(row["eval_items"])
    except Exception:
        eval_items = []
    try:
        eval_item_details = json.loads(row["eval_item_details"])
    except Exception:
        eval_item_details = {}
    return {
        "companyProfile": row["company_profile"] or "",
        "evalItems": eval_items,
        "evalItemDetails": eval_item_details,
    }


@app.put("/api/company-settings")
def put_company_settings(body: CompanySettingsBody, request: Request):
    require_app_admin(request)
    with closing(get_db()) as conn:
        row = conn.execute(
            "SELECT company_profile, eval_items, eval_item_details FROM company_settings WHERE id = 1"
        ).fetchone()
        company_profile = row["company_profile"] if row else ""
        eval_items = json.loads(row["eval_items"]) if row else []
        eval_item_details = json.loads(row["eval_item_details"]) if row else {}

        if body.companyProfile is not None:
            company_profile = body.companyProfile
        if body.evalItems is not None:
            eval_items = body.evalItems
        if body.evalItemDetails is not None:
            eval_item_details = body.evalItemDetails

        payload_profile = company_profile
        payload_items = json.dumps(eval_items, ensure_ascii=False)
        payload_details = json.dumps(eval_item_details, ensure_ascii=False)
        if len(payload_profile.encode("utf-8")) + len(payload_items.encode("utf-8")) + len(payload_details.encode("utf-8")) > 4_000_000:
            raise HTTPException(400, "저장할 데이터가 너무 큽니다.")

        conn.execute(
            "INSERT INTO company_settings (id, company_profile, eval_items, eval_item_details, updated_at) "
            "VALUES (1, ?, ?, ?, ?) "
            "ON CONFLICT(id) DO UPDATE SET company_profile = excluded.company_profile, "
            "eval_items = excluded.eval_items, eval_item_details = excluded.eval_item_details, "
            "updated_at = excluded.updated_at",
            (payload_profile, payload_items, payload_details, now_iso()),
        )
        conn.commit()
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# 앱 관리자(정/부) 권한 관리 - 서버 계정관리자(role)와는 별개의 권한 체계.
# ---------------------------------------------------------------------------
@app.get("/api/app-admin/users")
def list_app_admin_users(request: Request):
    require_app_primary(request)
    with closing(get_db()) as conn:
        rows = conn.execute(
            "SELECT id, email, app_admin_role FROM users ORDER BY created_at"
        ).fetchall()
    return [dict(r) for r in rows]


@app.post("/api/app-admin/transfer-primary")
def transfer_primary(body: TransferPrimaryBody, request: Request):
    current = require_app_primary(request)
    if body.targetUserId == current["id"]:
        raise HTTPException(400, "본인에게는 양도할 수 없습니다.")
    with closing(get_db()) as conn:
        target = conn.execute("SELECT id FROM users WHERE id = ?", (body.targetUserId,)).fetchone()
        if not target:
            raise HTTPException(404, "대상 사용자를 찾을 수 없습니다.")
        conn.execute("UPDATE users SET app_admin_role = 'member' WHERE id = ?", (current["id"],))
        conn.execute("UPDATE users SET app_admin_role = 'primary' WHERE id = ?", (body.targetUserId,))
        conn.commit()
    return {"status": "ok"}


@app.post("/api/app-admin/secondary")
def set_secondary(body: SecondaryBody, request: Request):
    require_app_primary(request)
    with closing(get_db()) as conn:
        target = conn.execute("SELECT id, app_admin_role FROM users WHERE id = ?", (body.targetUserId,)).fetchone()
        if not target:
            raise HTTPException(404, "대상 사용자를 찾을 수 없습니다.")
        if target["app_admin_role"] == "primary":
            raise HTTPException(400, "관리자(정)의 역할은 여기서 바꿀 수 없습니다.")
        new_role = "secondary" if body.enabled else "member"
        conn.execute("UPDATE users SET app_admin_role = ? WHERE id = ?", (new_role, body.targetUserId))
        conn.commit()
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# AI 프록시 - 브라우저가 아니라 이 서버가 대신 AI API를 호출한다.
# (API 키가 브라우저에 노출되지 않고, 고정 서버 IP로 호출되므로 IP 허용목록 기반
#  사내 API에도 대응 가능)
# ---------------------------------------------------------------------------
def _post_json(url: str, body: dict, headers: dict) -> dict:
    req = urllib.request.Request(url, data=json.dumps(body).encode("utf-8"), headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", errors="ignore")
        raise HTTPException(status_code=502, detail=f"AI 제공자 오류({e.code}): {detail[:300]}")
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"AI 요청 실패: {e}")


@app.post("/api/ai/complete")
def ai_complete(body: AIBody, request: Request):
    user = require_user(request)
    if not AI_API_KEY:
        raise HTTPException(500, "서버에 AI_API_KEY 환경변수가 설정되어 있지 않습니다.")

    # 이미지/문서 등 멀티모달 콘텐츠가 오면 그대로 쓰고, 아니면 텍스트 프롬프트를 그대로 쓴다.
    message_content = body.content if body.content else body.prompt
    # anthropic 외의 제공자는 멀티모달 형식이 다를 수 있으므로, 텍스트 블록만 추려 폴백한다.
    fallback_text_content = body.prompt
    if body.content:
        fallback_text_content = "\n".join(
            block.get("text", "") for block in body.content if isinstance(block, dict) and block.get("type") == "text"
        )

    if AI_PROVIDER == "anthropic":
        url = AI_BASE_URL or "https://api.anthropic.com/v1/messages"
        req_body = {
            "model": AI_MODEL,
            "max_tokens": body.max_tokens,
            "messages": [{"role": "user", "content": message_content}],
        }
        headers = {
            "Content-Type": "application/json",
            "x-api-key": AI_API_KEY,
            "anthropic-version": "2023-06-01",
        }
        data = _post_json(url, req_body, headers)
        text = "".join(b.get("text", "") for b in data.get("content", []))
        return {"text": text}

    if AI_PROVIDER == "openai":
        url = AI_BASE_URL or "https://api.openai.com/v1/chat/completions"
        req_body = {
            "model": AI_MODEL,
            "max_tokens": body.max_tokens,
            "messages": [{"role": "user", "content": fallback_text_content}],
        }
        headers = {"Content-Type": "application/json", "Authorization": f"Bearer {AI_API_KEY}"}
        data = _post_json(url, req_body, headers)
        text = (data.get("choices") or [{}])[0].get("message", {}).get("content", "")
        return {"text": text}

    if AI_PROVIDER == "worksai":
        # 에이전트 대화 API v2 (단발 JSON 경로) - https://gateway-api.wrks.ai/v2/chat/json
        if not AI_AGENT_ID:
            raise HTTPException(
                500,
                "AI_AGENT_ID 환경변수가 필요합니다. 웍스AI에서 GET /v2/agents 로 조회한 "
                "에이전트의 id 값을 넣어주세요.",
            )
        base = (AI_BASE_URL or "https://gateway-api.wrks.ai").rstrip("/")
        url = f"{base}/v2/chat/json"
        req_body = {"message": fallback_text_content, "agentId": AI_AGENT_ID}
        headers = {
            "Content-Type": "application/json",
            "API-KEY": AI_API_KEY,
            # 실제 로그인한 직원 신원으로 호출 - 웍스AI 쪽 사용량/감사 로그가 이 직원 기준으로 남는다.
            "X-Actor-User-Email": user["email"],
        }
        data = _post_json(url, req_body, headers)
        if data.get("result") == "error":
            code = data.get("code", "UNKNOWN")
            raise HTTPException(502, f"웍스AI 오류({code}): {json.dumps(data, ensure_ascii=False)[:300]}")
        text = (data.get("data") or {}).get("message", "")
        if not text:
            # 응답 스키마가 예상과 다를 때 원인을 바로 알 수 있도록 원본을 보여준다.
            raise HTTPException(
                502,
                f"응답에서 텍스트를 찾지 못했습니다. 원본 응답: {json.dumps(data, ensure_ascii=False)[:500]}",
            )
        return {"text": text}

    # custom: 위 세 가지 외에 다른 사내 API를 쓰는 경우 이 블록만 수정해서 쓰면 된다.
    if not AI_BASE_URL:
        raise HTTPException(500, "AI_PROVIDER=custom일 때는 AI_BASE_URL 환경변수가 필요합니다.")
    req_body = {
        "model": AI_MODEL,
        "max_tokens": body.max_tokens,
        "messages": [{"role": "user", "content": fallback_text_content}],
    }
    headers = {"Content-Type": "application/json", "Authorization": f"Bearer {AI_API_KEY}"}
    data = _post_json(AI_BASE_URL, req_body, headers)
    text = data.get("text") or "".join(b.get("text", "") for b in data.get("content", []))
    return {"text": text}


# ---------------------------------------------------------------------------
# 정적 파일 서빙
# ---------------------------------------------------------------------------
app.mount("/assets", StaticFiles(directory="static"), name="assets")


@app.get("/")
def index():
    return FileResponse("static/index.html")
