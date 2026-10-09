"""
DigiLocker issuer lookup.

- sandbox: returns a simulated issued record so the full flow can be demonstrated.
  Sandbox results are NOT evidence of anything.
- live: calls the DigiLocker partner API. Access requires DigiLocker partner
  onboarding and the applicant's consent. Base URL and lookup path come from
  configuration; nothing is hard-coded to an unverified endpoint.
"""

import httpx

from app.config import settings


class DigiLockerError(Exception):
    pass


# Simulated issuer records for demonstrations only. Not real people or documents.
SANDBOX_RECORDS = {
    "ABCPE1234F": {"holder_name": "RAVI KUMAR"},
}


def lookup(doc_type: str, number: str, access_token: str | None) -> dict:
    if settings.DIGILOCKER_MODE == "sandbox":
        record = SANDBOX_RECORDS.get(number)
        if record is None:
            return {"status": "NOT_FOUND", "source": "DIGILOCKER_SANDBOX"}
        return {"status": "FOUND", "source": "DIGILOCKER_SANDBOX", "doc_type": doc_type,
                "document_number": number, "holder_name": record["holder_name"],
                "issued_file_sha256": None}

    if not (access_token and settings.DIGILOCKER_API_BASE):
        raise DigiLockerError("Live mode needs the applicant's access token and DIGILOCKER_API_BASE.")
    try:
        r = httpx.get(
            settings.DIGILOCKER_API_BASE.rstrip("/") + settings.DIGILOCKER_LOOKUP_PATH,
            params={"doctype": doc_type, "docnumber": number},
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=10,
        )
    except httpx.HTTPError as exc:
        raise DigiLockerError(f"DigiLocker unreachable: {exc.__class__.__name__}") from exc

    if r.status_code == 404:
        return {"status": "NOT_FOUND", "source": "DIGILOCKER"}
    if r.status_code != 200:
        raise DigiLockerError(f"DigiLocker returned HTTP {r.status_code}")
    return {**r.json(), "status": "FOUND", "source": "DIGILOCKER"}
