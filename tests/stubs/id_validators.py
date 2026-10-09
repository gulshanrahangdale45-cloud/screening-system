import re
def validate_document_number(doc_type, number):
    if doc_type != "pan":
        return {"valid": None, "reason": "no validator"}
    n = (number or "").upper()
    ok = bool(re.fullmatch(r"[A-Z]{3}[ABCFGHLJPT][A-Z][0-9]{4}[A-Z]", n))
    return {"valid": ok, "reason": None if ok else "PAN format invalid"}
