"""
Screening pipeline with Issuer Consensus Triage.

Issuer Consensus Triage compares the submitted document with the record the
issuing authority holds (via DigiLocker, when the applicant consents). The
result sets the review route directly, so an issuer mismatch is never hidden
behind a low heuristic score. Missing data yields INSUFFICIENT_DATA rather than
a guessed mismatch, which keeps false alarms down.

Outputs are triage indicators. A human officer makes the decision.
"""

import difflib
import hashlib
import json
import os
import re
import tempfile
import uuid
from datetime import datetime
from pathlib import Path

from cryptography.fernet import Fernet
from fastapi import HTTPException
from sqlalchemy.orm import Session

from app import digilocker, ledger
from app.config import settings
from app.database import Alert, Screening
from app.services.anomaly_detection import detect_anomalies
from app.services.face_verification import verify_face
from app.services.id_validators import validate_document_number
from app.services.ocr_service import extract_document_text
from app.services.tamper_detection import detect_tampering

UPLOAD_DIR = Path(settings.UPLOAD_DIR)
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
_fernet = Fernet(settings.FERNET_KEY.encode())

_MAGIC = {
    ".jpg": b"\xff\xd8\xff", ".jpeg": b"\xff\xd8\xff",
    ".png": b"\x89PNG\r\n\x1a\n", ".pdf": b"%PDF",
}
WEIGHTS = {
    "ID_CHECKSUM_INVALID": 35,
    "DOC_TAMPER_INDICATOR": 30,
    "FACE_MISMATCH": 30,
    "ISSUER_MISMATCH": 30,
    "DATA_INCONSISTENCY": 15,
}


def _check_file(name: str, data: bytes, allowed: set[str]) -> str:
    """Extension and magic bytes must both match: a renamed file is rejected."""
    ext = Path(name or "").suffix.lower()
    if ext not in allowed or not data.startswith(_MAGIC[ext]):
        raise HTTPException(400, f"File must be a genuine {', '.join(sorted(allowed))} file")
    return ext


def _norm_num(value: str | None) -> str:
    return re.sub(r"[^A-Z0-9]", "", (value or "").upper())


def _mask(value: str | None) -> str | None:
    n = _norm_num(value)
    return None if not n else "X" * max(len(n) - 4, 0) + n[-4:]


def _name_ratio(a: str | None, b: str | None) -> float | None:
    a = re.sub(r"[^a-z ]", "", (a or "").lower()).strip()
    b = re.sub(r"[^a-z ]", "", (b or "").lower()).strip()
    if not a or not b:
        return None
    return difflib.SequenceMatcher(None, a, b).ratio()


def issuer_consensus(typed_number: str | None, ocr: dict, issuer: dict | None, doc_sha256: str) -> dict:
    if issuer is None:
        return {"status": "NOT_REQUESTED", "checks": {}}
    if issuer.get("status") == "NOT_FOUND":
        return {"status": "NO_ISSUER_RECORD", "checks": {}}
    if issuer.get("status") != "FOUND":
        return {"status": "ISSUER_UNAVAILABLE", "checks": {}}

    # Strongest signal: the submitted file is byte-identical to the issued file
    if issuer.get("issued_file_sha256") and issuer["issued_file_sha256"] == doc_sha256:
        return {"status": "CORROBORATED_FILE_IDENTICAL", "checks": {"file_hash": True}}

    entered = _norm_num(typed_number or ocr.get("document_number"))
    num_ok = (entered == _norm_num(issuer.get("document_number"))) if entered else None
    ratio = _name_ratio(ocr.get("name"), issuer.get("holder_name"))
    name_ok = None if ratio is None else ratio >= 0.85

    checks = {
        "document_number": num_ok,
        "holder_name": name_ok,
        "name_similarity": round(ratio, 2) if ratio is not None else None,
    }
    decided = [v for v in (num_ok, name_ok) if v is not None]
    if not decided:
        return {"status": "INSUFFICIENT_DATA", "checks": checks}
    return {"status": "CORROBORATED" if all(decided) else "MISMATCH_WITH_ISSUER", "checks": checks}


def _score(indicators: dict) -> tuple[int, str]:
    score = min(100, sum(WEIGHTS[k] for k, on in indicators.items() if on))
    level = "CRITICAL" if score >= 85 else "HIGH" if score >= 70 else "MEDIUM" if score >= 40 else "LOW"
    return score, level


def _action(level: str, consensus_status: str) -> str:
    if level in ("HIGH", "CRITICAL") or consensus_status == "MISMATCH_WITH_ISSUER":
        return "PRIORITY_REVIEW"
    if level == "LOW" and consensus_status.startswith("CORROBORATED"):
        return "LIGHT_REVIEW"
    return "STANDARD_REVIEW"


def _temp(data: bytes, ext: str, bag: list) -> str:
    fd, path = tempfile.mkstemp(suffix=ext)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    bag.append(path)
    return path


def run_screening(db: Session, *, user: str, doc: tuple, doc_type: str, number: str | None,
                  selfie: tuple | None, use_digilocker: bool, dl_token: str | None) -> dict:
    doc_name, doc_bytes = doc
    doc_ext = _check_file(doc_name, doc_bytes, {".jpg", ".jpeg", ".png", ".pdf"})
    if selfie:
        _check_file(selfie[0], selfie[1], {".jpg", ".jpeg", ".png"})

    sid = f"SCR-{uuid.uuid4().hex[:8].upper()}"
    doc_sha = hashlib.sha256(doc_bytes).hexdigest()
    enc_path = UPLOAD_DIR / f"{sid}.enc"
    enc_path.write_bytes(_fernet.encrypt(doc_bytes))
    if selfie:
        (UPLOAD_DIR / f"{sid}-live.enc").write_bytes(_fernet.encrypt(selfie[1]))

    temps: list[str] = []
    try:
        doc_path = _temp(doc_bytes, doc_ext, temps)
        selfie_path = _temp(selfie[1], Path(selfie[0]).suffix.lower(), temps) if selfie else None

        ocr = extract_document_text(doc_path)
        lookup_number = number or ocr.get("document_number")
        id_val = validate_document_number(doc_type, lookup_number)
        tamper = detect_tampering(doc_path)
        face = verify_face(doc_path, selfie_path)
        anomaly = detect_anomalies({
            "name": ocr.get("name"),
            "document_number": lookup_number,
            "expiry_date": ocr.get("expiry_date"),
        })

        issuer = None
        if use_digilocker:
            try:
                if not lookup_number:
                    raise digilocker.DigiLockerError("No document number available for lookup")
                issuer = digilocker.lookup(doc_type, _norm_num(lookup_number), dl_token)
            except digilocker.DigiLockerError as exc:
                issuer = {"status": "ERROR", "message": str(exc)}
        consensus = issuer_consensus(number, ocr, issuer, doc_sha)
    finally:
        for p in temps:
            Path(p).unlink(missing_ok=True)

    indicators = {
        "ID_CHECKSUM_INVALID": id_val.get("valid") is False,
        "DOC_TAMPER_INDICATOR": bool(tamper.get("tampering_detected")),
        "FACE_MISMATCH": face.get("status") == "NO_MATCH",
        "ISSUER_MISMATCH": consensus["status"] == "MISMATCH_WITH_ISSUER",
        "DATA_INCONSISTENCY": anomaly["count"] > 0,
    }
    score, level = _score(indicators)
    reasons = [k for k, on in indicators.items() if on]
    action = _action(level, consensus["status"])

    ledger_hash = ledger.append_event(db, "SCREENING_COMPLETED", sid, {
        "doc_sha256": doc_sha,
        "doc_type": doc_type,
        "risk_score": score,
        "risk_level": level,
        "reason_codes": reasons,
        "issuer_status": consensus["status"],
        "recommended_action": action,
        "created_by": user,
    })

    result = {
        "screening_id": sid,
        "doc_type": doc_type,
        "filename": doc_name,
        "status": "REVIEW_REQUIRED",
        "risk": {"score": score, "level": level, "reason_codes": reasons},
        "recommended_action": action,
        "issuer_consensus": consensus,
        "checks": {
            "id_checksum": "N/A" if id_val.get("valid") is None else ("VALID" if id_val["valid"] else "INVALID"),
            "tamper_analysis": ("UNAVAILABLE" if tamper.get("tampering_detected") is None
                                else "FLAGGED" if tamper["tampering_detected"] else "CLEAR"),
            "face_verification": face.get("status"),
            "anomaly_detection": "REVIEW_REQUIRED" if anomaly["count"] else "NO_ANOMALY",
            "ocr_extraction": "FAILED" if ocr.get("error") else "SUCCESS",
        },
        "ocr_result": ocr,
        "id_validation": id_val,
        "tamper_result": tamper,
        "face_result": face,
        "anomaly_result": anomaly,
        "audit": {"document_sha256": doc_sha, "ledger_event_hash": ledger_hash},
        "created_at": datetime.utcnow().isoformat(),
        "disclaimer": "AI-assisted screening indicators for authorised human review. "
                      "Not a final identity determination.",
    }

    db.add(Screening(
        id=sid, doc_type=doc_type, doc_number_masked=_mask(lookup_number),
        file_path=str(enc_path), doc_sha256=doc_sha, status="REVIEW_REQUIRED",
        risk_score=score, risk_level=level, reason_codes=",".join(reasons),
        issuer_status=consensus["status"], recommended_action=action,
        result_json=json.dumps(result, default=str), created_by=user,
    ))
    if action == "PRIORITY_REVIEW":
        db.add(Alert(
            screening_id=sid,
            severity=level if level in ("HIGH", "CRITICAL") else "HIGH",
            message=f"Priority review: {', '.join(reasons) or consensus['status']}",
        ))
    db.commit()
    return result
