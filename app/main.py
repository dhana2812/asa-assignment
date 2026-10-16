import hashlib
import logging
import secrets
import traceback
from datetime import datetime, timedelta
from typing import List, Optional

import httpx
from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

import models
from auth import create_access_token, get_current_user, get_password_hash, verify_password
from config import NOTIFY_SERVICE_URL
from database import engine, get_db, search_scans_by_query

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

models.Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="VulnTracker API",
    description="Vulnerability tracking and management REST API",
    version="1.0.0",
)


ALLOWED_ORIGINS = {
    "http://localhost:8000",
    "http://127.0.0.1:8000",
    "http://localhost:3000",
    "http://localhost:3001",
}


@app.middleware("http")
async def cors_middleware(request: Request, call_next):
    response = await call_next(request)
    origin = request.headers.get("origin")
    # Strict CORS whitelist prevents arbitrary cross-origin data exfiltration (CWE-942)
    if origin and origin in ALLOWED_ORIGINS:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, PATCH, DELETE, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type"
    return response


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    # Log detailed traceback internally for diagnostics
    logger.error("Unhandled exception on %s: %s", request.url, exc, exc_info=True)
    # Sanitize client response to prevent internal information disclosure (CWE-209)
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal Server Error",
            "detail": "An unexpected error occurred. Please contact the administrator.",
        },
    )



# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class UserRegister(BaseModel):
    username: str
    email: str
    password: str


class UserLogin(BaseModel):
    username: str
    password: str


class UserOut(BaseModel):
    id: int
    username: str
    email: str
    created_at: datetime

    class Config:
        from_attributes = True


class ScanCreate(BaseModel):
    title: str
    description: Optional[str] = None
    severity: str = "medium"
    cve_id: Optional[str] = None
    affected_component: str
    remediation_notes: Optional[str] = None


class ScanUpdate(BaseModel):
    status: Optional[str] = None
    remediation_notes: Optional[str] = None


class ScanOut(BaseModel):
    id: int
    title: str
    description: Optional[str]
    severity: str
    status: str
    cve_id: Optional[str]
    affected_component: str
    remediation_notes: Optional[str]
    owner_id: int
    created_at: datetime

    class Config:
        from_attributes = True


class ShareCreate(BaseModel):
    password: Optional[str] = None


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _hash_share_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _fire_notify(event: str, payload: dict) -> None:
    try:
        httpx.post(
            f"{NOTIFY_SERVICE_URL}/notify",
            json={"event": event, "payload": payload},
            timeout=5.0,
        )
    except Exception as exc:
        logger.warning("Notification service unreachable: %s", exc)


# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------

@app.post("/auth/register", response_model=UserOut, status_code=201)
def register(payload: UserRegister, db: Session = Depends(get_db)):
    if db.query(models.User).filter(models.User.username == payload.username).first():
        raise HTTPException(status_code=400, detail="Username already registered")
    if db.query(models.User).filter(models.User.email == payload.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")
    user = models.User(
        username=payload.username,
        email=payload.email,
        hashed_password=get_password_hash(payload.password),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@app.post("/auth/login")
def login(payload: UserLogin, db: Session = Depends(get_db)):
    # Do not log plaintext passwords (CWE-532)
    logger.info("Login attempt for username: %s", payload.username)
    user = db.query(models.User).filter(models.User.username == payload.username).first()
    if not user or not verify_password(payload.password, user.hashed_password):
        logger.warning("Failed login attempt for username: %s", payload.username)
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    token = create_access_token({"sub": user.username})
    return {"access_token": token, "token_type": "bearer"}



# ---------------------------------------------------------------------------
# Scan routes
# ---------------------------------------------------------------------------

@app.get("/scans", response_model=List[ScanOut])
def list_scans(
    skip: int = 0,
    limit: int = 50,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    return (
        db.query(models.ScanResult)
        .filter(models.ScanResult.owner_id == current_user.id)
        .offset(skip)
        .limit(limit)
        .all()
    )


@app.post("/scans", response_model=ScanOut, status_code=201)
def create_scan(
    payload: ScanCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    if payload.severity not in ("critical", "high", "medium", "low"):
        raise HTTPException(status_code=400, detail="severity must be critical | high | medium | low")
    scan = models.ScanResult(**payload.model_dump(), owner_id=current_user.id)
    db.add(scan)
    db.commit()
    db.refresh(scan)
    background_tasks.add_task(_fire_notify, "scan.created", {
        "id": scan.id,
        "title": scan.title,
        "severity": scan.severity,
        "owner": current_user.username,
    })
    return scan


@app.post(
    "/scans/{scan_id}/share",
    summary="Generate a shared report link",
    response_description="A unique expiring share URL",
)
def create_share_link(
    scan_id: int,
    payload: Optional[ShareCreate] = None,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """
    Generate a 24-hour expiring shareable link for a scan report.
    Only the owner of the scan can generate a share link.
    Optionally accepts a password to protect the report.
    """
    scan = db.query(models.ScanResult).filter(
        models.ScanResult.id == scan_id,
        models.ScanResult.owner_id == current_user.id,
    ).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    password = payload.password if payload is not None else None
    if password is not None and (
        not password or len(password.encode("utf-8")) > 72
    ):
        raise HTTPException(
            status_code=422,
            detail="password must contain between 1 and 72 UTF-8 bytes",
        )

    token = secrets.token_urlsafe(32)
    share_link = models.ShareLink(
        token_hash=_hash_share_token(token),
        password_hash=get_password_hash(password) if password is not None else None,
        scan_id=scan.id,
        expires_at=datetime.utcnow() + timedelta(hours=24),
    )
    db.add(share_link)
    db.commit()
    return {"share_url": f"http://localhost:8000/share/{token}"}


# In-memory attempt tracking for password-protected shared report links (VT-08 Remediation)
# Maps token_hash -> {"failed_attempts": int, "locked_until": Optional[datetime]}
_share_link_rate_limits: dict = {}
MAX_SHARE_PASSWORD_ATTEMPTS = 5
SHARE_LOCKOUT_MINUTES = 15


@app.get(
    "/share/{token}",
    response_model=ScanOut,
    summary="Access a shared scan report",
    response_description="Scan finding details",
)
def get_shared_scan(
    token: str,
    password: Optional[str] = None,
    db: Session = Depends(get_db),
):
    """
    Publicly retrieve a shared scan finding using its unique share token.
    Enforces a strict 24-hour expiration window.
    If the link is password-protected, requires the correct `password` query parameter.
    Includes rate-limiting lockout after 5 consecutive failed attempts to prevent brute-force attacks (VT-08).
    """
    token_hash = _hash_share_token(token)
    now = datetime.utcnow()

    # Check if token is locked out due to excessive failed attempts
    rate_data = _share_link_rate_limits.get(token_hash)
    if rate_data and rate_data.get("locked_until") and rate_data["locked_until"] > now:
        retry_seconds = int((rate_data["locked_until"] - now).total_seconds())
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed password attempts. Link is temporarily locked.",
            headers={"Retry-After": str(max(retry_seconds, 1))},
        )

    share_link = db.query(models.ShareLink).filter(
        models.ShareLink.token_hash == token_hash,
    ).first()
    if not share_link or share_link.expires_at <= now:
        raise HTTPException(status_code=404, detail="Share link not found or expired")

    if share_link.password_hash is not None:
        is_valid = False
        if password is not None and 1 <= len(password.encode("utf-8")) <= 72:
            is_valid = verify_password(password, share_link.password_hash)

        if not is_valid:
            if token_hash not in _share_link_rate_limits:
                _share_link_rate_limits[token_hash] = {"failed_attempts": 0, "locked_until": None}
            _share_link_rate_limits[token_hash]["failed_attempts"] += 1

            if _share_link_rate_limits[token_hash]["failed_attempts"] >= MAX_SHARE_PASSWORD_ATTEMPTS:
                _share_link_rate_limits[token_hash]["locked_until"] = now + timedelta(minutes=SHARE_LOCKOUT_MINUTES)
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Too many failed password attempts. Link is temporarily locked.",
                    headers={"Retry-After": str(SHARE_LOCKOUT_MINUTES * 60)},
                )
            raise HTTPException(status_code=403, detail="Password required or incorrect")

        # Reset failed attempts upon successful password verification
        if token_hash in _share_link_rate_limits:
            _share_link_rate_limits.pop(token_hash, None)

    scan = db.query(models.ScanResult).filter(
        models.ScanResult.id == share_link.scan_id,
    ).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Shared scan not found")
    return scan


@app.get("/scans/search")
def search_scans(
    q: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    if not q or len(q) < 2:
        raise HTTPException(status_code=400, detail="Search query must be at least 2 characters")
    results = search_scans_by_query(db, q)
    return {"results": results, "count": len(results)}


@app.get("/scans/{scan_id}", response_model=ScanOut)
def get_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    scan = db.query(models.ScanResult).filter(models.ScanResult.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@app.patch("/scans/{scan_id}", response_model=ScanOut)
def update_scan(
    scan_id: int,
    payload: ScanUpdate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    scan = db.query(models.ScanResult).filter(
        models.ScanResult.id == scan_id,
        models.ScanResult.owner_id == current_user.id,
    ).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if payload.status is not None:
        if payload.status not in ("open", "in_progress", "resolved"):
            raise HTTPException(status_code=400, detail="status must be open | in_progress | resolved")
        scan.status = payload.status
    if payload.remediation_notes is not None:
        scan.remediation_notes = payload.remediation_notes
    scan.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(scan)
    background_tasks.add_task(_fire_notify, "scan.updated", {
        "id": scan.id,
        "title": scan.title,
        "status": scan.status,
        "owner": current_user.username,
    })
    return scan


@app.delete("/scans/{scan_id}", status_code=204)
def delete_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    scan = db.query(models.ScanResult).filter(
        models.ScanResult.id == scan_id,
        models.ScanResult.owner_id == current_user.id,
    ).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    db.delete(scan)
    db.commit()


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@app.get("/health")
def health():
    return {"status": "ok", "service": "vulntracker-api"}
