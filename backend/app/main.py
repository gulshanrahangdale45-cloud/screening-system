import csv
import hashlib
import io
import json
from contextlib import asynccontextmanager
from datetime import datetime

from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, Request, UploadFile
from fastapi.responses import JSONResponse, Response
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from app import digilocker, ledger, verification
from app.config import settings
from app.database import Alert, LedgerEntry, Screening, SessionLocal, User, get_db, init_db
from app.security import current_user, hash_password, make_token, require, verify_password

DOC_TYPES = {"aadhaar", "pan", "passport", "other"}
DECISIONS = {"CLEARED", "ESCALATED", "REJECTED"}
MAX_BYTES = settings.MAX_FILE_MB * 1024 * 1024


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    db = SessionLocal()
    try:  # seed initial accounts from env; replicas may race, so duplicates are ignored
        for name, pw in settings.SEED_PASSWORDS.items():
            if pw and not db.query(User).filter(User.username == name).first():
                db.add(User(username=name, password_hash=hash_password(pw), role=name.upper()))
        db.commit()
    except IntegrityError:
        db.rollback()
    finally:
        db.close()
    yield


app = FastAPI(title="Identity & Document Screening Platform", version="2.0.0",
              lifespan=lifespan, docs_url="/api/docs", openapi_url="/api/openapi.json")


@app.exception_handler(Exception)
async def unhandled(request: Request, exc: Exception):
    print("UNHANDLED", request.url.path, repr(exc))  # logged server-side only
    return JSONResponse({"detail": "Internal error"}, status_code=500)


@app.get("/health")
def health():
    return {"status": "healthy"}


# ---------- auth ----------
@app.post("/api/auth/login")
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form.username).first()
    if not user or not verify_password(form.password, user.password_hash):
        raise HTTPException(401, "Invalid username or password")
    return {"access_token": make_token(user), "token_type": "bearer", "role": user.role}


@app.get("/api/auth/me")
def me(user: User = Depends(current_user)):
    return {"username": user.username, "role": user.role}


# ---------- screening ----------
@app.post("/api/screenings")
async def create_screening(
    document: UploadFile = File(...),
    doc_type: str = Form(...),
    document_number: str | None = Form(None),
    live_photo: UploadFile | None = File(None),
    use_digilocker: bool = Form(False),
    digilocker_token: str | None = Form(None),
    user: User = Depends(require("ADMIN", "OFFICER")),
    db: Session = Depends(get_db),
):
    doc_type = doc_type.lower()
    if doc_type not in DOC_TYPES:
        raise HTTPException(400, "doc_type must be one of: aadhaar, pan, passport, other")
    doc = (document.filename or "", await document.read(MAX_BYTES + 1))
    selfie = None
    if live_photo is not None and live_photo.filename:
        selfie = (live_photo.filename, await live_photo.read(MAX_BYTES + 1))
    if len(doc[1]) > MAX_BYTES or (selfie and len(selfie[1]) > MAX_BYTES):
        raise HTTPException(413, f"File exceeds {settings.MAX_FILE_MB} MB")
    return await run_in_threadpool(
        verification.run_screening, db, user=user.username, doc=doc, doc_type=doc_type,
        number=document_number, selfie=selfie, use_digilocker=use_digilocker,
        dl_token=digilocker_token,
    )


def _summary(r: Screening) -> dict:
    """List view carries no personal data, so auditors can see it too."""
    return {"screening_id": r.id, "doc_type": r.doc_type, "status": r.status,
            "risk_score": r.risk_score, "risk_level": r.risk_level,
            "issuer_status": r.issuer_status, "recommended_action": r.recommended_action,
            "decision": r.decision, "created_at": r.created_at.isoformat()}


def _get_screening(db: Session, sid: str) -> Screening:
    row = db.get(Screening, sid)
    if not row:
        raise HTTPException(404, "Screening not found")
    return row


@app.get("/api/screenings")
def list_screenings(limit: int = 100, db: Session = Depends(get_db), user: User = Depends(current_user)):
    rows = db.query(Screening).order_by(Screening.created_at.desc()).limit(min(limit, 500)).all()
    return [_summary(r) for r in rows]


@app.get("/api/screenings/{sid}")
def get_screening(sid: str, db: Session = Depends(get_db), user: User = Depends(require("ADMIN", "OFFICER"))):
    return json.loads(_get_screening(db, sid).result_json)


def _flatten(d: dict, prefix: str = "") -> dict:
    out = {}
    for k, v in d.items():
        key = f"{prefix}{k}"
        if isinstance(v, dict):
            out.update(_flatten(v, key + "."))
        else:
            out[key] = json.dumps(v) if isinstance(v, list) else v
    return out


@app.get("/api/screenings/{sid}/report")
def screening_report(sid: str, format: str = "json", db: Session = Depends(get_db),
                     user: User = Depends(require("ADMIN", "OFFICER"))):
    if format not in {"json", "csv"}:
        raise HTTPException(400, "format must be json or csv")
    row = _get_screening(db, sid)
    result = json.loads(row.result_json)
    ledger.append_event(db, "REPORT_EXPORTED", sid, {"format": format, "by": user.username})

    if format == "csv":
        flat = _flatten(result)
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=list(flat.keys()))
        writer.writeheader()
        writer.writerow(flat)
        return Response(buf.getvalue(), media_type="text/csv",
                        headers={"Content-Disposition": f'attachment; filename="{sid}.csv"'})
    return Response(json.dumps(result, indent=2, default=str), media_type="application/json",
                    headers={"Content-Disposition": f'attachment; filename="{sid}.json"'})


class DecisionIn(BaseModel):
    decision: str
    remarks: str | None = None


@app.post("/api/screenings/{sid}/decision")
def record_decision(sid: str, body: DecisionIn, db: Session = Depends(get_db),
                    user: User = Depends(require("OFFICER"))):
    if body.decision not in DECISIONS:
        raise HTTPException(400, "decision must be CLEARED, ESCALATED or REJECTED")
    row = _get_screening(db, sid)
    officer_decision = {"decision": body.decision, "officer": user.username,
                        "at": datetime.utcnow().isoformat()}
    result = json.loads(row.result_json)
    result["officer_decision"] = officer_decision
    row.result_json = json.dumps(result, default=str)
    row.decision = body.decision
    row.status = body.decision
    if body.decision == "ESCALATED":
        db.add(Alert(screening_id=sid, severity="HIGH", message="Escalated by officer"))
    remarks_hash = hashlib.sha256(body.remarks.encode()).hexdigest() if body.remarks else None
    ledger.append_event(db, "OFFICER_DECISION", sid,
                        {"decision": body.decision, "officer": user.username, "remarks_sha256": remarks_hash})
    db.commit()
    return officer_decision


# ---------- alerts ----------
@app.get("/api/alerts")
def list_alerts(db: Session = Depends(get_db), user: User = Depends(current_user)):
    rows = db.query(Alert).order_by(Alert.created_at.desc()).limit(200).all()
    return [{"alert_id": a.id, "screening_id": a.screening_id, "severity": a.severity,
             "message": a.message, "status": a.status, "created_at": a.created_at.isoformat()}
            for a in rows]


@app.patch("/api/alerts/{alert_id}/resolve")
def resolve_alert(alert_id: int, db: Session = Depends(get_db),
                  user: User = Depends(require("ADMIN", "OFFICER"))):
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(404, "Alert not found")
    alert.status = "RESOLVED"
    db.commit()
    return {"alert_id": alert.id, "status": alert.status}


# ---------- DigiLocker ----------
@app.get("/api/digilocker/lookup")
def digilocker_lookup(doc_type: str, document_number: str,
                      x_digilocker_token: str | None = Header(None),
                      user: User = Depends(require("ADMIN", "OFFICER"))):
    try:
        return digilocker.lookup(doc_type.lower(), document_number.strip().upper(), x_digilocker_token)
    except digilocker.DigiLockerError as exc:
        raise HTTPException(502, str(exc))


# ---------- ledger ----------
@app.get("/api/ledger/verify")
def ledger_verify(db: Session = Depends(get_db), user: User = Depends(require("ADMIN", "AUDITOR"))):
    return ledger.verify_ledger(db)


@app.get("/api/ledger/entries")
def ledger_entries(limit: int = 50, db: Session = Depends(get_db),
                   user: User = Depends(require("ADMIN", "AUDITOR"))):
    rows = db.query(LedgerEntry).order_by(LedgerEntry.id.desc()).limit(min(limit, 500)).all()
    return [{"id": r.id, "event": r.event, "subject": r.subject, "entry_hash": r.entry_hash,
             "block_index": r.block_index, "created_at": r.created_at.isoformat()} for r in rows]


@app.post("/api/ledger/seal")
def ledger_seal(db: Session = Depends(get_db), user: User = Depends(require("ADMIN"))):
    return ledger.seal(db) or {"message": "No pending entries"}
# ---------- serve the frontend (local development only) ----------
from pathlib import Path
from fastapi.staticfiles import StaticFiles

FRONTEND_DIR = Path(__file__).resolve().parents[2] / "frontend"
if FRONTEND_DIR.exists():
    app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")