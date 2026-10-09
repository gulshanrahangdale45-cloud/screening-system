import os, sqlite3, httpx

B = "http://127.0.0.1:8000"
c = httpx.Client(base_url=B, timeout=30)
results = []

def check(name, cond, extra=""):
    results.append(bool(cond))
    print(("PASS " if cond else "FAIL ") + name + (f"  [{extra}]" if extra else ""))

def login(u, env):
    r = c.post("/api/auth/login", data={"username": u, "password": os.environ[env]})
    r.raise_for_status()
    return r.json()["access_token"]

def H(t): return {"Authorization": f"Bearer {t}"}

def png(name_line):
    return b"\x89PNG\r\n\x1a\n" + f"NAME:{name_line}\n".encode() + b"\0" * 200

def screen(token, content, filename="id.png", doc_type="pan", number="ABCPE1234F", dl=True):
    data = {"doc_type": doc_type, "use_digilocker": "true" if dl else "false"}
    if number is not None:
        data["document_number"] = number
    return c.post("/api/screenings", headers=H(token),
                  files={"document": (filename, content, "image/png")}, data=data)

# ---- health and auth ----
check("health endpoint", c.get("/health").status_code == 200)
adm = login("admin", "ADMIN_PASSWORD")
off = login("officer", "OFFICER_PASSWORD")
aud = login("auditor", "AUDITOR_PASSWORD")
check("three roles can sign in", all([adm, off, aud]))
check("wrong password rejected", c.post("/api/auth/login", data={"username": "admin", "password": "nope"}).status_code == 401)
check("no token rejected", c.get("/api/screenings").status_code == 401)
check("garbage token rejected", c.get("/api/screenings", headers=H("abc.def.ghi")).status_code == 401)
check("/me returns role", c.get("/api/auth/me", headers=H(off)).json()["role"] == "OFFICER")

# ---- RBAC ----
check("auditor cannot screen documents", screen(aud, png("RAVI KUMAR")).status_code == 403)
check("auditor can list screenings", c.get("/api/screenings", headers=H(aud)).status_code == 200)

# ---- file validation ----
r = screen(adm, png("RAVI KUMAR"), filename="fake.pdf")
check("renamed file rejected (magic bytes mismatch)", r.status_code == 400, str(r.status_code))
r = screen(adm, png("RAVI KUMAR"), doc_type="driving-licence")
check("unknown doc_type rejected", r.status_code == 400 or r.status_code == 422, str(r.status_code))

# ---- Issuer Consensus Triage: the three outcomes ----
r = screen(adm, png("RAVI KUMAR"))
check("A: consistent record -> 200", r.status_code == 200, str(r.status_code))
A = r.json()
check("A: issuer consensus CORROBORATED", A["issuer_consensus"]["status"] == "CORROBORATED", A["issuer_consensus"]["status"])
check("A: low risk routed to LIGHT_REVIEW", A["recommended_action"] == "LIGHT_REVIEW", A["recommended_action"])
check("A: id checksum VALID", A["checks"]["id_checksum"] == "VALID", A["checks"]["id_checksum"])
check("A: result has ledger hash", len(A["audit"]["ledger_event_hash"]) == 64)

r = screen(off, png("PRIYA SHARMA"))
B_ = r.json()
check("B: name mismatch with issuer -> MISMATCH", B_["issuer_consensus"]["status"] == "MISMATCH_WITH_ISSUER", B_["issuer_consensus"]["status"])
check("B: mismatch forces PRIORITY_REVIEW even below HIGH risk",
      B_["recommended_action"] == "PRIORITY_REVIEW" and B_["risk"]["level"] not in ("HIGH", "CRITICAL"),
      f"{B_['recommended_action']} / {B_['risk']['level']} {B_['risk']['score']}")
check("B: ISSUER_MISMATCH reason code present", "ISSUER_MISMATCH" in B_["risk"]["reason_codes"])

r = screen(adm, png("RAVI KUMAR"), number="ABCPE9999Z")
C = r.json()
check("C: number absent from issuer -> NO_ISSUER_RECORD", C["issuer_consensus"]["status"] == "NO_ISSUER_RECORD", C["issuer_consensus"]["status"])
check("C: no issuer record -> STANDARD_REVIEW", C["recommended_action"] == "STANDARD_REVIEW", C["recommended_action"])

D = screen(adm, png("RAVI KUMAR"), dl=False).json()
check("D: DigiLocker not requested -> NOT_REQUESTED", D["issuer_consensus"]["status"] == "NOT_REQUESTED", D["issuer_consensus"]["status"])

E = screen(adm, png("RAVI KUMAR"), number="XYZ").json()
check("E: invalid PAN format flagged INVALID", E["checks"]["id_checksum"] == "INVALID", E["checks"]["id_checksum"])

dl_ok = c.get("/api/digilocker/lookup", params={"doc_type": "pan", "document_number": "ABCPE1234F"}, headers=H(off))
check("DigiLocker lookup endpoint (found)", dl_ok.status_code == 200 and dl_ok.json()["status"] == "FOUND")
check("DigiLocker lookup needs authorised role", c.get("/api/digilocker/lookup", params={"doc_type": "pan", "document_number": "X"}, headers=H(aud)).status_code == 403)

# ---- screening records, detail, RBAC on detail ----
sid_A, sid_B = A["screening_id"], B_["screening_id"]
check("list shows the screenings", len(c.get("/api/screenings", headers=H(aud)).json()) >= 5)
check("auditor gets summaries without personal data",
      "ocr_result" not in c.get("/api/screenings", headers=H(aud)).json()[0])
check("auditor cannot open full record", c.get(f"/api/screenings/{sid_A}", headers=H(aud)).status_code == 403)
check("officer can open full record", c.get(f"/api/screenings/{sid_A}", headers=H(off)).status_code == 200)
check("unknown screening -> 404", c.get("/api/screenings/SCR-NOPE0000", headers=H(off)).status_code == 404)

# ---- reports (file creation) ----
rj = c.get(f"/api/screenings/{sid_A}/report", params={"format": "json"}, headers=H(off))
check("JSON report download", rj.status_code == 200 and "attachment" in rj.headers.get("content-disposition", ""))
rc = c.get(f"/api/screenings/{sid_A}/report", params={"format": "csv"}, headers=H(adm))
check("CSV report download", rc.status_code == 200 and rc.text.splitlines()[0].startswith("screening_id"), rc.headers.get("content-type", ""))
check("auditor cannot export report", c.get(f"/api/screenings/{sid_A}/report", headers=H(aud)).status_code == 403)

# ---- officer decisions ----
check("admin cannot record officer decision", c.post(f"/api/screenings/{sid_B}/decision", json={"decision": "CLEARED"}, headers=H(adm)).status_code == 403)
check("invalid decision value rejected", c.post(f"/api/screenings/{sid_B}/decision", json={"decision": "APPROVED"}, headers=H(off)).status_code == 400)
r = c.post(f"/api/screenings/{sid_B}/decision", json={"decision": "ESCALATED", "remarks": "confirm with issuer"}, headers=H(off))
check("officer records ESCALATED", r.status_code == 200 and r.json()["decision"] == "ESCALATED", str(r.status_code))
check("decision visible on record", c.get(f"/api/screenings/{sid_B}", headers=H(off)).json()["officer_decision"]["officer"] == "officer")

# ---- alerts ----
alerts = c.get("/api/alerts", headers=H(aud)).json()
open_alerts = [a for a in alerts if a["status"] == "OPEN"]
check("alerts created for priority/escalated cases", len(alerts) >= 2, f"{len(alerts)} alerts")
r = c.patch(f"/api/alerts/{open_alerts[0]['alert_id']}/resolve", headers=H(off))
check("officer resolves an alert", r.status_code == 200 and r.json()["status"] == "RESOLVED")
check("auditor cannot resolve alerts", c.patch(f"/api/alerts/{open_alerts[-1]['alert_id']}/resolve", headers=H(aud)).status_code == 403)

# ---- blockchain ledger ----
check("ledger entries visible to auditor", c.get("/api/ledger/entries", headers=H(aud)).status_code == 200)
check("officer cannot read ledger", c.get("/api/ledger/verify", headers=H(off)).status_code == 403)
check("officer cannot seal ledger", c.post("/api/ledger/seal", headers=H(off)).status_code == 403)
seal = c.post("/api/ledger/seal", headers=H(adm)).json()
print("      seal ->", seal.get("message"))
v = c.get("/api/ledger/verify", headers=H(aud)).json()
check("ledger verifies intact", v["valid"] is True and v["blocks"] >= 1, f"blocks={v.get('blocks')} entries={v.get('entries_checked')}")

# tamper with a sealed record directly in the database, then verify the chain catches it
db = sqlite3.connect("/tmp/run/screening.db")
orig = db.execute("SELECT payload FROM ledger_entries WHERE id = (SELECT MIN(id) FROM ledger_entries)").fetchone()[0]
db.execute("UPDATE ledger_entries SET payload = replace(payload, 'LOW', 'CRITICAL') WHERE id = (SELECT MIN(id) FROM ledger_entries)")
db.commit()
v = c.get("/api/ledger/verify", headers=H(aud)).json()
check("tampered ledger entry detected", v["valid"] is False and v.get("broken_at_block") == 0, v["message"])
db.execute("UPDATE ledger_entries SET payload = ? WHERE id = (SELECT MIN(id) FROM ledger_entries)", (orig,))
db.commit()
v = c.get("/api/ledger/verify", headers=H(aud)).json()
check("restoring the entry makes the chain valid again", v["valid"] is True)

# deletion attack
db.execute("DELETE FROM ledger_entries WHERE id = (SELECT MAX(id) FROM ledger_entries WHERE block_index IS NOT NULL)")
db.commit()
v = c.get("/api/ledger/verify", headers=H(aud)).json()
check("deleted ledger entry detected", v["valid"] is False, v["message"])

print(f"\n{sum(results)}/{len(results)} checks passed")
