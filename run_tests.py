"""
ThreatCommand End-to-End Test Suite — Flask Test Client
Run: python run_tests.py
No running server needed — uses Flask's built-in test client.
"""
import sys, json, time, os

# ── Setup ──────────────────────────────────────────────────────
os.environ.setdefault("INGEST_API_KEY", "change-this-to-a-random-key")
os.environ.setdefault("SECRET_KEY", "test-secret-key")

from backend.app import create_app, db

app = create_app()
app.config["TESTING"] = True
app.config["WTF_CSRF_ENABLED"] = False
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
app.config["INGEST_API_KEY"] = "change-this-to-a-random-key"

PASS = 0
FAIL = 0
results = []

def test(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
    else:
        FAIL += 1
    mark = "[OK]" if ok else "[!!]"
    msg = f"  {mark} {name}"
    if detail and not ok:
        msg += f"\n       -> {detail}"
    print(msg)
    results.append((name, ok, detail))

def check(name, r, expected_status, check_json=None):
    ok = r.status_code == expected_status
    detail = f"HTTP {r.status_code} (expected {expected_status})"
    if not ok and r.status_code in (301, 302):
        detail += f" -> Location: {r.headers.get('Location', '?')}"
    if ok and check_json:
        try:
            body = r.get_json()
            if body is None:
                body = json.loads(r.data)
            for k, v in check_json.items():
                if body.get(k) != v:
                    ok = False
                    detail = f"JSON field '{k}' = {body.get(k)!r} (expected {v!r})"
                    break
        except Exception as e:
            ok = False
            detail = f"JSON parse error: {e} | body: {r.data[:200]}"
    if ok:
        detail = ""
    test(name, ok, detail)
    return ok


print("\n" + "="*57)
print("  ThreatCommand End-to-End Test Suite (Flask Test Client)")
print("="*57 + "\n")

with app.app_context():
    # Create all tables in memory DB
    db.create_all()

    client = app.test_client()

    # ── 1. Health ─────────────────────────────────────────────
    print("[ Health ]")
    r = client.get("/api/v1/health")
    check("GET /api/v1/health -> 200 + status:ok", r, 200, {"status": "ok"})

    # ── 2. Landing page ────────────────────────────────────────
    print("\n[ Landing page ]")
    r = client.get("/")
    check("GET / -> 200 (landing page)", r, 200)

    # ── 3. Register ────────────────────────────────────────────
    print("\n[ Auth ]")
    email = f"tester_{int(time.time())}@example.com"
    r = client.post("/auth/register", data={
        "org_name": "TestOrg", "email": email,
        "password": "Test1234!", "confirm": "Test1234!"
    }, follow_redirects=False)
    ok = r.status_code in (200, 302)
    test("POST /auth/register -> 200 or 302", ok, f"HTTP {r.status_code}")

    # Follow register redirect (logs us in)
    r = client.post("/auth/register", data={
        "org_name": "TestOrg2", "email": f"t2_{int(time.time())}@example.com",
        "password": "Test1234!", "confirm": "Test1234!"
    }, follow_redirects=True)
    logged_in = b"dashboard" in r.data.lower() or r.status_code == 200

    # Verify we're logged in by hitting dashboard
    r = client.get("/dashboard")
    check("GET /dashboard -> 200 (logged in after register)", r, 200)

    # ── 4. Cases ──────────────────────────────────────────────
    print("\n[ Cases ]")
    r = client.get("/cases")
    check("GET /cases -> 200", r, 200)

    r = client.post("/cases/new", data={
        "title": "Test Case - Suspicious Login",
        "description": "Multiple failed logins from 1.2.3.4",
        "severity": "high",
        "source": "test",
        "entities": "ip:1.2.3.4\nuser:badactor@evil.com",
        "initial_event": "Brute force detected"
    }, follow_redirects=False)
    ok = r.status_code in (200, 302)
    test("POST /cases/new -> 200 or 302", ok, f"HTTP {r.status_code}")

    case_id = 1
    if r.status_code == 302:
        loc = r.headers.get("Location", "")
        if "/cases/" in loc:
            try:
                case_id = int(loc.rstrip("/").split("/")[-1])
            except:
                pass

    r = client.get(f"/cases/{case_id}")
    check(f"GET /cases/{case_id} -> 200", r, 200)

    r = client.post(f"/cases/{case_id}/status",
                    data=json.dumps({"status": "investigating"}),
                    content_type="application/json")
    check(f"POST /cases/{case_id}/status -> 200", r, 200)

    r = client.post(f"/cases/{case_id}/timeline",
                    data=json.dumps({"description": "Analyst noted lateral movement", "event_type": "analyst_note"}),
                    content_type="application/json")
    check(f"POST /cases/{case_id}/timeline -> 201", r, 201)

    r = client.post(f"/cases/{case_id}/evidence",
                    data=json.dumps({"name": "firewall.log", "type": "log", "content": "Blocked 1.2.3.4"}),
                    content_type="application/json")
    check(f"POST /cases/{case_id}/evidence -> 201", r, 201)

    # ── 5. Metrics ────────────────────────────────────────────
    print("\n[ Metrics ]")
    r = client.get("/metrics/api/data")
    check("GET /metrics/api/data -> 200", r, 200)
    r = client.get("/metrics/")
    check("GET /metrics/ -> 200", r, 200)

    # ── 6. Threat Intel ────────────────────────────────────────
    print("\n[ Threat Intel ]")
    r = client.get("/threats/")
    check("GET /threats/ -> 200", r, 200)
    r = client.get("/threats/api/latest")
    check("GET /threats/api/latest -> 200", r, 200)

    # ── 7. Patches ────────────────────────────────────────────
    print("\n[ Patches ]")
    r = client.get("/patches/")
    check("GET /patches/ -> 200", r, 200)
    r = client.get("/patches/api/pending-count")
    check("GET /patches/api/pending-count -> 200", r, 200)

    # ── 8. Playbooks ──────────────────────────────────────────
    print("\n[ Playbooks ]")
    r = client.get("/playbooks/")
    check("GET /playbooks/ -> 200", r, 200)

    # ── 9. Reports ────────────────────────────────────────────
    print("\n[ Reports ]")
    r = client.get("/reports/")
    check("GET /reports/ -> 200", r, 200)
    r = client.get("/reports/nist-framework")
    check("GET /reports/nist-framework -> 200", r, 200)

    # ── 10. Ingest API ────────────────────────────────────────
    print("\n[ Ingest API ]")
    INGEST_KEY = "change-this-to-a-random-key"

    r = client.post("/api/v1/alerts/test",
                    headers={"X-API-Key": INGEST_KEY},
                    data=json.dumps({"title": "Test Alert", "severity": "high",
                                     "src_ip": "192.168.1.100", "user": "jdoe"}),
                    content_type="application/json")
    check("POST /api/v1/alerts/test -> 200", r, 200)

    r = client.post("/api/v1/alerts",
                    headers={"X-API-Key": INGEST_KEY},
                    data=json.dumps({"title": "Malware Detected", "severity": "critical",
                                     "id": f"test-{int(time.time())}",
                                     "src_ip": "10.0.0.5", "hostname": "DESKTOP-001"}),
                    content_type="application/json")
    ok = r.status_code in (200, 201)
    body = r.get_json() or {}
    detail = f"status={body.get('status')}, case_id={body.get('case_id')}" if ok else f"HTTP {r.status_code} | {r.data[:200]}"
    test(f"POST /api/v1/alerts -> 200/201", ok, "" if ok else detail)

    r = client.post("/api/v1/alerts",
                    headers={"X-API-Key": "wrong-key"},
                    data=json.dumps({"title": "Should Fail"}),
                    content_type="application/json")
    check("POST /api/v1/alerts (bad key) -> 401", r, 401)

    # ── 11. Billing ───────────────────────────────────────────
    print("\n[ Billing ]")
    r = client.get("/billing/")
    check("GET /billing/ -> 200", r, 200)

    # ── 12. AI routes ─────────────────────────────────────────
    print("\n[ AI Analysis ]")
    r = client.post(f"/ai/analyze/{case_id}",
                    data=json.dumps({}),
                    content_type="application/json")
    ok = r.status_code != 404
    test("POST /ai/analyze/<id> route exists", ok, f"HTTP {r.status_code}" if not ok else "")

    # ── 13. Auth logout ────────────────────────────────────────
    print("\n[ Auth logout ]")
    r = client.get("/auth/logout", follow_redirects=False)
    ok = r.status_code in (200, 302)
    test("GET /auth/logout -> 200 or 302", ok, f"HTTP {r.status_code}")

# ── Summary ───────────────────────────────────────────────────
total = PASS + FAIL
print("\n" + "="*57)
print(f"  Results: {PASS}/{total} passed  |  {FAIL} failed")
print("="*57)

if FAIL:
    print("\nFailed tests:")
    for name, ok, detail in results:
        if not ok:
            print(f"  - {name}")
            if detail:
                print(f"    {detail}")

sys.exit(0 if FAIL == 0 else 1)
