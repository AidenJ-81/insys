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
AI_PROVIDER = os.environ.get("AI_PROVIDER", "anthropic")  # anthropic | openai | custom
AI_API_KEY = os.environ.get("AI_API_KEY", "")
AI_MODEL = os.environ.get("AI_MODEL", "claude-sonnet-4-6")
AI_BASE_URL = os.environ.get("AI_BASE_URL", "")  # custom 제공자(예: 웍스AI) 사용 시 엔드포인트 지정

app = FastAPI(title="INSYS")


# ---------------------------------------------------------------------------
# DB
# ---------------------------------------------------------------------------
def get_db():
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


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
            """
        )
        conn.commit()


init_db()


# ---------------------------------------------------------------------------
# 비밀번호 해싱 (외부 라이브러리 없이 표준 라이브러리만 사용)
# ---------------------------------------------------------------------------
def make_salt() -> str:
    return secrets.token_hex(16)


def hash_password(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 200_000).hex()


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


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


class AIBody(BaseModel):
    prompt: str
    max_tokens: int = 1200


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
                "INSERT INTO users (email, password_hash, salt, role, approved, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (email, pw_hash, salt, "admin" if is_first else "member", 1, now_iso()),
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
    return {"status": "ok", "approved": True, "role": "admin" if is_first else "member"}


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
    return {"status": "ok", "email": user["email"], "role": user["role"]}


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
    return {"email": user["email"], "role": user["role"], "approved": bool(user["approved"])}


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
    require_user(request)
    if not AI_API_KEY:
        raise HTTPException(500, "서버에 AI_API_KEY 환경변수가 설정되어 있지 않습니다.")

    if AI_PROVIDER == "anthropic":
        url = AI_BASE_URL or "https://api.anthropic.com/v1/messages"
        req_body = {
            "model": AI_MODEL,
            "max_tokens": body.max_tokens,
            "messages": [{"role": "user", "content": body.prompt}],
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
            "messages": [{"role": "user", "content": body.prompt}],
        }
        headers = {"Content-Type": "application/json", "Authorization": f"Bearer {AI_API_KEY}"}
        data = _post_json(url, req_body, headers)
        text = (data.get("choices") or [{}])[0].get("message", {}).get("content", "")
        return {"text": text}

    # custom: 사내 API(예: 웍스AI)처럼 별도 엔드포인트/형식을 쓰는 경우.
    # 기본적으로 Anthropic 호환 형식(messages)으로 보내되, 응답은 text 또는
    # content[].text 두 가지 형태 모두 시도해서 파싱한다. 실제 API 문서에 맞춰
    # 이 블록만 수정하면 된다.
    if not AI_BASE_URL:
        raise HTTPException(500, "AI_PROVIDER=custom일 때는 AI_BASE_URL 환경변수가 필요합니다.")
    req_body = {
        "model": AI_MODEL,
        "max_tokens": body.max_tokens,
        "messages": [{"role": "user", "content": body.prompt}],
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
