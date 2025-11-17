import os
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict, Any

from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, EmailStr
from jose import jwt, JWTError
from passlib.context import CryptContext
from bson import ObjectId

from database import db, create_document, get_documents

# App setup
app = FastAPI(title="Conventional Commit Assistant API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Auth/JWT config
JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret-change-me")
JWT_ALG = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Usage limits
FREE_TIER_LIMIT = int(os.getenv("FREE_TIER_MONTHLY_LIMIT", "50"))
PRO_TIER_LIMIT = int(os.getenv("PRO_TIER_MONTHLY_LIMIT", "1000"))


# ---------- Utility ----------
class TokenData(BaseModel):
    user_id: str
    email: EmailStr
    is_admin: bool = False


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALG)
    return encoded_jwt


def verify_password(plain_password: str, password_hash: str) -> bool:
    return pwd_context.verify(plain_password, password_hash)


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def month_key(dt: Optional[datetime] = None) -> str:
    dt = dt or datetime.now(timezone.utc)
    return dt.strftime("%Y-%m")


def get_collection(name: str):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    return db[name]


# ---------- Auth Dependency ----------
async def get_current_user(authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")
    token = authorization.split(" ", 1)[1]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        user_id: str = payload.get("user_id")
        email: str = payload.get("email")
        is_admin: bool = payload.get("is_admin", False)
        if user_id is None or email is None:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    users = get_collection("user")
    user = users.find_one({"_id": ObjectId(user_id)})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    user["id"] = str(user["_id"])
    user.pop("_id", None)
    return user


# ---------- Request/Response Models ----------
class SignupRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=6)
    name: Optional[str] = None


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class AuthResponse(BaseModel):
    token: str
    user: Dict[str, Any]


class ConfigUpdate(BaseModel):
    favorite_types: Optional[List[str]] = None
    favorite_scopes: Optional[List[str]] = None
    footer_template: Optional[str] = None


class GenerateRequest(BaseModel):
    git_status: Optional[str] = None
    version: Optional[str] = None
    description: Optional[str] = None
    preferred_type: Optional[str] = None
    scope: Optional[str] = None


class GenerateResponse(BaseModel):
    type: str
    scope: Optional[str]
    message: str
    changelog_line: str
    usage_left: Optional[int] = None


# ---------- Routes ----------
@app.get("/")
def root():
    return {"service": "Conventional Commit Assistant API", "status": "ok"}


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set",
        "database_name": "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set",
        "connection_status": "Not Connected",
        "collections": [],
    }
    try:
        if db is not None:
            response["database"] = "✅ Connected & Working"
            response["connection_status"] = "Connected"
            response["collections"] = db.list_collection_names()
    except Exception as e:
        response["database"] = f"⚠️ Connected but Error: {str(e)[:80]}"
    return response


# Auth endpoints
@app.post("/auth/signup", response_model=AuthResponse)
def signup(payload: SignupRequest):
    users = get_collection("user")
    existing = users.find_one({"email": payload.email.lower()})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    doc = {
        "email": payload.email.lower(),
        "password_hash": hash_password(payload.password),
        "name": payload.name,
        "is_admin": False,
        "plan": "free",
        "usage": {},
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    result = users.insert_one(doc)

    # Create default config
    configs = get_collection("userconfig")
    configs.insert_one({
        "user_id": str(result.inserted_id),
        "favorite_types": ["feat", "fix", "chore", "docs", "refactor"],
        "favorite_scopes": [],
        "footer_template": None,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    })

    token = create_access_token({
        "user_id": str(result.inserted_id),
        "email": payload.email.lower(),
        "is_admin": False,
    })
    user = doc.copy()
    user["id"] = str(result.inserted_id)
    user.pop("password_hash", None)
    return {"token": token, "user": user}


@app.post("/auth/login", response_model=AuthResponse)
def login(payload: LoginRequest):
    users = get_collection("user")
    user = users.find_one({"email": payload.email.lower()})
    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    if not verify_password(payload.password, user.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    token = create_access_token({
        "user_id": str(user["_id"]),
        "email": user["email"],
        "is_admin": user.get("is_admin", False),
    })
    user_public = {k: v for k, v in user.items() if k != "password_hash"}
    user_public["id"] = str(user_public.pop("_id"))
    return {"token": token, "user": user_public}


@app.get("/me")
async def me(user=Depends(get_current_user)):
    return user


@app.get("/config")
async def get_config(user=Depends(get_current_user)):
    configs = get_collection("userconfig")
    cfg = configs.find_one({"user_id": user["id"]})
    if not cfg:
        cfg = {
            "user_id": user["id"],
            "favorite_types": ["feat", "fix", "chore", "docs", "refactor"],
            "favorite_scopes": [],
            "footer_template": None,
        }
        configs.insert_one({**cfg, "created_at": datetime.now(timezone.utc), "updated_at": datetime.now(timezone.utc)})
    cfg["id"] = str(cfg.pop("_id")) if "_id" in cfg else None
    return cfg


@app.put("/config")
async def update_config(update: ConfigUpdate, user=Depends(get_current_user)):
    configs = get_collection("userconfig")
    now = datetime.now(timezone.utc)
    configs.update_one(
        {"user_id": user["id"]},
        {"$set": {**{k: v for k, v in update.model_dump(exclude_none=True).items()}, "updated_at": now}},
        upsert=True,
    )
    return {"ok": True}


# Conventional Commit logic
TYPES = ["feat", "fix", "docs", "style", "refactor", "perf", "test", "build", "ci", "chore", "revert"]
BREAKING_HINTS = ["breaking", "breaking change", "major", "incompatible"]


def infer_type_from_status(git_status: Optional[str], description: Optional[str]) -> str:
    text = ((git_status or "") + "\n" + (description or "")).lower()
    if any(k in text for k in ["fix", "bug", "hotfix", "patch"]):
        return "fix"
    if any(k in text for k in ["feat", "feature", "add", "implement", "new"]):
        return "feat"
    if any(k in text for k in ["doc", "readme", "docs"]):
        return "docs"
    if any(k in text for k in ["refactor", "cleanup", "restructure"]):
        return "refactor"
    if any(k in text for k in ["perf", "performance", "optimize"]):
        return "perf"
    if any(k in text for k in ["test", "tests", "jest", "pytest"]):
        return "test"
    if any(k in text for k in ["build", "deps", "dependency", "package.json", "requirements.txt"]):
        return "build"
    if any(k in text for k in ["ci", "workflow", "github actions", "pipeline"]):
        return "ci"
    if any(k in text for k in ["style", "format", "lint", "prettier", "eslint"]):
        return "style"
    return "chore"


def infer_scope(git_status: Optional[str]) -> Optional[str]:
    if not git_status:
        return None
    # simple heuristic: take first folder name from modified files
    lines = [l.strip() for l in git_status.splitlines() if l.strip()]
    for l in lines:
        parts = l.split()
        path = parts[-1] if parts else ""
        if "/" in path:
            return path.split("/")[0]
    return None


def build_message(commit_type: str, scope: Optional[str], description: Optional[str], version: Optional[str], breaking: bool, footer_template: Optional[str]) -> Dict[str, str]:
    desc = (description or "update").strip()
    # first line
    scope_part = f"({scope})" if scope else ""
    bang = "!" if breaking else ""
    # Spec: type(scope)!: description
    header = f"{commit_type}{scope_part}{bang}: {desc}"

    body_lines: List[str] = []
    if version:
        body_lines.append(f"Version: {version}")

    footer_lines: List[str] = []
    if breaking:
        footer_lines.append("BREAKING CHANGE: behavior changed in an incompatible way")
    if footer_template:
        footer_lines.append(footer_template)

    sections = [header]
    if body_lines:
        sections.append("\n".join(body_lines))
    if footer_lines:
        sections.append("\n".join(footer_lines))
    message = "\n\n".join(sections)

    # simple changelog line
    scope_disp = f"({scope})" if scope else ""
    changelog = f"- {commit_type}{scope_disp}: {desc}"
    return {"message": message, "changelog": changelog}


@app.post("/generate", response_model=GenerateResponse)
async def generate_commit(req: GenerateRequest, user=Depends(get_current_user)):
    # usage check
    users = get_collection("user")
    month = month_key()
    plan = user.get("plan", "free")
    limit = PRO_TIER_LIMIT if plan == "pro" else FREE_TIER_LIMIT
    usage = user.get("usage", {})
    used = int(usage.get(month, 0))
    if used >= limit:
        raise HTTPException(status_code=402, detail="Monthly generation limit reached for your plan")

    # load user config
    cfg = get_collection("userconfig").find_one({"user_id": user["id"]}) or {}

    ctype = req.preferred_type or infer_type_from_status(req.git_status, req.description)
    if ctype not in TYPES:
        # fallback to first favorite type or chore
        favs = cfg.get("favorite_types") or []
        ctype = favs[0] if favs else "chore"

    scope = (req.scope or infer_scope(req.git_status)) or None

    # breaking change detection (case-insensitive)
    desc_l = (req.description or "").lower()
    status_l = (req.git_status or "").lower()
    breaking = any(h in desc_l for h in BREAKING_HINTS) or any(h in status_l for h in BREAKING_HINTS)

    built = build_message(ctype, scope, req.description, req.version, breaking, cfg.get("footer_template"))

    # persist history
    history = get_collection("commithistory")
    doc = {
        "user_id": user["id"],
        "git_status": req.git_status,
        "version": req.version,
        "description": req.description,
        "type": ctype,
        "scope": scope,
        "message": built["message"],
        "changelog_line": built["changelog"],
        "meta": {"breaking": breaking},
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    history.insert_one(doc)

    # increment usage
    users.update_one(
        {"_id": ObjectId(user["id"])},
        {"$inc": {f"usage.{month}": 1}, "$set": {"updated_at": datetime.now(timezone.utc)}}
    )

    usage_left = limit - (used + 1)
    return {
        "type": ctype,
        "scope": scope,
        "message": built["message"],
        "changelog_line": built["changelog"],
        "usage_left": usage_left,
    }


@app.get("/history")
async def get_history(user=Depends(get_current_user)):
    history = get_collection("commithistory")
    items = list(history.find({"user_id": user["id"]}).sort("created_at", -1).limit(50))
    for it in items:
        it["id"] = str(it.pop("_id"))
    return items


@app.delete("/history/{item_id}")
async def delete_history(item_id: str, user=Depends(get_current_user)):
    history = get_collection("commithistory")
    res = history.delete_one({"_id": ObjectId(item_id), "user_id": user["id"]})
    if res.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Item not found")
    return {"ok": True}


@app.get("/admin/stats")
async def admin_stats(user=Depends(get_current_user)):
    if not user.get("is_admin"):
        raise HTTPException(status_code=403, detail="Admin only")
    users = get_collection("user")
    history = get_collection("commithistory")
    total_users = users.count_documents({})
    total_msgs = history.count_documents({})
    # Active users in current month
    mk = month_key()
    active = users.count_documents({f"usage.{mk}": {"$gt": 0}})
    return {"total_users": total_users, "total_messages": total_msgs, "active_users_this_month": active}


# Optional: expose schemas to Flames database viewer
@app.get("/schema")
async def get_schema():
    try:
        from schemas import User, UserConfig, CommitHistory
        return {
            "user": User.model_json_schema(),
            "userconfig": UserConfig.model_json_schema(),
            "commithistory": CommitHistory.model_json_schema(),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
