"""
Demo data seeder — creates a realistic, fully-populated ContainIQ environment
for demos, screenshots, and portfolio presentations.

Run: flask seed-demo  (or call seed_demo_data() in app context)
"""
from datetime import datetime, timedelta, timezone, date
from ..app import db
from ..models.case import Case, Entity, TimelineEvent, Evidence
from ..models.playbook import Playbook, PlaybookRun, PlaybookApproval
from ..models.audit import AuditLog
from ..models.threat import ThreatUpdate, ThreatProposal
from ..models.patch import PatchRelease, Detection, ChangeLog
import hashlib

# ── Helpers ──────────────────────────────────────────────────────────────────

def _dt(days_ago=0, hours_ago=0, minutes_ago=0):
    return datetime.now(timezone.utc) - timedelta(
        days=days_ago, hours=hours_ago, minutes=minutes_ago
    )

def _audit(action, org_id, user_id=1, resource_type=None, resource_id=None,
           case_id=None, payload=None, outcome="success"):
    entry = AuditLog(
        org_id=org_id, user_id=user_id, action=action,
        resource_type=resource_type, resource_id=str(resource_id) if resource_id else None,
        case_id=case_id, ip_address="10.0.0.42", outcome=outcome,
    )
    if payload:
        entry.payload = payload
    db.session.add(entry)


# ── Main seeder ───────────────────────────────────────────────────────────────

def seed_demo_data():
    from ..models.org import Org
    from ..models.user import User

    org = Org.query.first()
    admin = User.query.filter_by(role="admin").first()
    if not org or not admin:
        print("[DEMO] No org/admin found — run app first to seed defaults.")
        return

    org_id = org.id
    admin_id = admin.id

    # Add a second analyst user
    analyst = User.query.filter_by(email="analyst@containiq.local").first()
    if not analyst:
        analyst = User(
            org_id=org_id, email="analyst@containiq.local",
            display_name="Alex Chen", role="analyst"
        )
        analyst.set_password("changeme")
        db.session.add(analyst)
        db.session.flush()
    analyst_id = analyst.id

    # ── Case 1: BEC / Inbox Forwarding (CRITICAL, Contained) ─────────────────
    c1 = Case(
        org_id=org_id, title="Suspected BEC — CFO inbox forwarding to external Gmail",
        description="Finance team flagged that CFO's inbox has an auto-forwarding rule sending all mail to external-audit2024@gmail.com. Wire transfer request received the same day.",
        severity="critical", status="contained", source="alert",
        source_ref="MDR-2024-001", created_by=admin_id,
        created_at=_dt(days_ago=3), updated_at=_dt(days_ago=2),
    )
    db.session.add(c1)
    db.session.flush()

    for etype, val in [("user","cfo@acmecorp.com"),("ip","185.220.101.47"),
                       ("domain","external-audit2024@gmail.com"),("device","DESKTOP-CFO-01")]:
        db.session.add(Entity(case_id=c1.id, entity_type=etype, value=val))

    for ev_time, etype, desc, src in [
        (_dt(days_ago=3,hours_ago=14), "alert_fired",    "MDR alert: Inbox rule created forwarding all mail to external Gmail address", "MDR Platform"),
        (_dt(days_ago=3,hours_ago=13), "analyst_note",   "Confirmed rule: name='Archive', forwards to external-audit2024@gmail.com. Created at 02:17 UTC from IP 185.220.101.47.", "Manual"),
        (_dt(days_ago=3,hours_ago=12), "login",          "Attacker sign-in from 185.220.101.47 (RU) — impossible travel from CFO's last login 4h earlier in NYC", "Entra ID"),
        (_dt(days_ago=3,hours_ago=11), "analyst_note",   "Wire transfer request received from spoofed CFO email: $247,000 to unknown vendor. Finance team notified to hold.", "Manual"),
        (_dt(days_ago=3,hours_ago=10), "process_execution","revokeSignInSessions executed via Microsoft Graph — all CFO sessions terminated", "Playbook"),
        (_dt(days_ago=3,hours_ago=9),  "analyst_note",   "Inbox rule disabled (not deleted — preserved as evidence). Assigned hash: SHA-256 logged.", "Playbook"),
        (_dt(days_ago=3,hours_ago=8),  "analyst_note",   "MFA reviewed: no new authenticator devices registered. Password reset completed via help desk.", "Manual"),
        (_dt(days_ago=2,hours_ago=6),  "analyst_note",   "OAuth app inventory clear — no unauthorized grants found. Wire transfer blocked by finance. Incident contained.", "Manual"),
    ]:
        db.session.add(TimelineEvent(case_id=c1.id, event_time=ev_time,
                                     event_type=etype, description=desc, source=src,
                                     created_by=admin_id))

    ev1 = Evidence(case_id=c1.id, name="UAL export — inbox rule creation event",
                   evidence_type="log", created_by=admin_id,
                   content='{"RecordType":"InboxRule","Operation":"Set-InboxRule","UserId":"cfo@acmecorp.com","Parameters":{"Name":"Archive","ForwardTo":"external-audit2024@gmail.com"},"ClientIP":"185.220.101.47","CreationTime":"2024-01-15T02:17:44"}',
                   created_at=_dt(days_ago=3, hours_ago=11))
    ev1.content_hash = hashlib.sha256(ev1.content.encode()).hexdigest()
    db.session.add(ev1)

    ev2 = Evidence(case_id=c1.id, name="Sign-in log — attacker session from RU IP",
                   evidence_type="log", created_by=admin_id,
                   content='{"UserPrincipalName":"cfo@acmecorp.com","IPAddress":"185.220.101.47","Location":"Russia","RiskState":"atRisk","ConditionalAccessStatus":"notApplied","AuthenticationRequirement":"singleFactorAuthentication"}',
                   created_at=_dt(days_ago=3, hours_ago=12))
    ev2.content_hash = hashlib.sha256(ev2.content.encode()).hexdigest()
    db.session.add(ev2)
    db.session.flush()

    # Playbook run for Case 1
    pb1 = Playbook.query.filter_by(org_id=org_id, name="Suspicious Inbox Forwarding Rule").first()
    if pb1:
        run1 = PlaybookRun(
            org_id=org_id, case_id=c1.id, playbook_id=pb1.id, started_by=admin_id,
            mode="live", status="completed", current_step=7,
            started_at=_dt(days_ago=3, hours_ago=10),
            completed_at=_dt(days_ago=3, hours_ago=8),
        )
        run1.blast_radius_config = {"max_affected": 1, "scope": "single_user"}
        steps_log = []
        for i, (name, status) in enumerate([
            ("Identify and document the forwarding rule", "executed"),
            ("Preserve evidence — export mail rule audit log", "executed"),
            ("Revoke active sessions for the affected account", "executed"),
            ("Disable the malicious forwarding rule", "executed"),
            ("Require MFA re-enrollment if device trust is broken", "executed"),
            ("Scan for OAuth app consent grants", "executed"),
            ("Notify user and reset credentials", "executed"),
        ]):
            steps_log.append({"step": i, "name": name, "status": status,
                               "timestamp": _dt(days_ago=3, hours_ago=10-i).isoformat()})
        run1.steps_log = steps_log
        db.session.add(run1)
        db.session.flush()

        appr1 = PlaybookApproval(
            run_id=run1.id, step_index=2, step_name="Revoke active sessions for the affected account",
            requested_by=analyst_id, approved_by=admin_id, status="approved",
            reason="Confirmed attacker IP is not a known corporate VPN exit. Approved.",
            created_at=_dt(days_ago=3, hours_ago=10, minutes_ago=30),
            decided_at=_dt(days_ago=3, hours_ago=10, minutes_ago=15),
        )
        db.session.add(appr1)

    _audit("case.create", org_id, admin_id, "case", c1.id, c1.id,
           {"title": c1.title, "severity": "critical"})
    _audit("playbook.run_started", org_id, admin_id, "playbook_run", 1, c1.id,
           {"playbook": "Suspicious Inbox Forwarding Rule", "mode": "live"})
    _audit("playbook.approval_decision", org_id, admin_id, "playbook_approval", 1, c1.id,
           {"decision": "approved", "step": 2})
    _audit("case.status_change", org_id, admin_id, "case", c1.id, c1.id,
           {"from": "investigating", "to": "contained"})

    # ── Case 2: Ransomware Early Indicators (HIGH, Investigating) ────────────
    c2 = Case(
        org_id=org_id, title="Ransomware early indicators — DESKTOP-ACCT-07",
        description="EDR flagged vssadmin.exe deleting shadow copies followed by rapid file extension changes (.docx → .locked) on accounting workstation.",
        severity="high", status="investigating", source="alert",
        source_ref="EDR-2024-089", created_by=analyst_id,
        created_at=_dt(hours_ago=6), updated_at=_dt(hours_ago=4),
    )
    db.session.add(c2)
    db.session.flush()

    for etype, val in [("device","DESKTOP-ACCT-07"),("user","j.rodriguez@acmecorp.com"),
                       ("ip","10.0.14.22"),("hash","a3f5c8d9e2b14f7a8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2")]:
        db.session.add(Entity(case_id=c2.id, entity_type=etype, value=val))

    for ev_time, etype, desc, src in [
        (_dt(hours_ago=6), "alert_fired",     "EDR: vssadmin.exe Delete Shadows /All /Quiet — HIGH confidence ransomware precursor", "CrowdStrike"),
        (_dt(hours_ago=5,minutes_ago=45), "process_execution", "Process tree: explorer.exe → cmd.exe → vssadmin.exe (unsigned, from %TEMP%\\svchost32.exe)", "CrowdStrike"),
        (_dt(hours_ago=5,minutes_ago=30), "file_access",       "Mass file modifications detected: 847 files in 4 minutes. Extension changed to .locked", "CrowdStrike"),
        (_dt(hours_ago=5),  "analyst_note",   "Host network-isolated via EDR. EDR agent channel maintained for live response. DO NOT REBOOT.", "Playbook"),
        (_dt(hours_ago=4,minutes_ago=30), "analyst_note",   "Memory capture initiated via WinPMEM. Process list and netstat preserved. Binary extracted from %TEMP%\\svchost32.exe", "Manual"),
        (_dt(hours_ago=4),  "analyst_note",   "SHA-256: a3f5c8d9... — VirusTotal: 58/72 engines detect as LockBit 3.0 variant. Backup check in progress.", "Manual"),
    ]:
        db.session.add(TimelineEvent(case_id=c2.id, event_time=ev_time,
                                     event_type=etype, description=desc, source=src,
                                     created_by=analyst_id))

    db.session.add(Evidence(case_id=c2.id, name="Ransomware binary — svchost32.exe",
                             evidence_type="hash", created_by=analyst_id,
                             content="SHA-256: a3f5c8d9e2b14f7a8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2\nVirusTotal: 58/72 — LockBit 3.0 variant\nFirst seen: 2024-01-08",
                             created_at=_dt(hours_ago=4)))
    db.session.add(Evidence(case_id=c2.id, name="EDR process tree export",
                             evidence_type="log", created_by=analyst_id,
                             content="explorer.exe (PID 4821)\n  └─ cmd.exe (PID 7392) [suspicious]\n       └─ vssadmin.exe (PID 8841) Delete Shadows /All /Quiet\n       └─ %TEMP%\\svchost32.exe (PID 9012) [unsigned, packed]",
                             created_at=_dt(hours_ago=5, minutes_ago=45)))

    pb2 = Playbook.query.filter_by(org_id=org_id, name="Suspected Ransomware Execution").first()
    if pb2:
        run2 = PlaybookRun(
            org_id=org_id, case_id=c2.id, playbook_id=pb2.id, started_by=analyst_id,
            mode="live", status="pending_approval", current_step=4,
            started_at=_dt(hours_ago=5),
        )
        run2.blast_radius_config = {"max_affected": 5}
        steps_log2 = []
        for i, (name, status) in enumerate([
            ("Confirm ransomware indicators — do not reboot", "executed"),
            ("Network isolate the affected host(s)", "executed"),
            ("Preserve memory and volatile data", "executed"),
            ("Verify backup integrity — DO NOT restore yet", "executed"),
            ("Reset credentials for accounts active on affected host", "dry_run_simulated"),
        ]):
            steps_log2.append({"step": i, "name": name, "status": status,
                                "timestamp": _dt(hours_ago=5-i).isoformat()})
        run2.steps_log = steps_log2
        db.session.add(run2)
        db.session.flush()

        appr2 = PlaybookApproval(
            run_id=run2.id, step_index=4,
            step_name="Reset credentials for accounts active on affected host",
            requested_by=analyst_id, status="pending",
            created_at=_dt(hours_ago=3),
        )
        db.session.add(appr2)

    # ── Case 3: OAuth Consent Abuse (MEDIUM, Open) ───────────────────────────
    c3 = Case(
        org_id=org_id, title="OAuth app consent abuse — developer account",
        description="Security tooling flagged developer account consented to third-party app 'DocumentSync Pro' with Mail.Read, Files.ReadWrite.All, and Contacts.Read permissions.",
        severity="medium", status="open", source="alert",
        source_ref="CASB-2024-034", created_by=analyst_id,
        created_at=_dt(hours_ago=2),
    )
    db.session.add(c3)
    db.session.flush()

    for etype, val in [("user","d.park@acmecorp.com"),("saas_app","DocumentSync Pro (client_id: 8f3a-c9d2)"),("domain","documentsync-pro.io")]:
        db.session.add(Entity(case_id=c3.id, entity_type=etype, value=val))

    for ev_time, etype, desc, src in [
        (_dt(hours_ago=2), "alert_fired", "CASB: OAuth consent grant to non-approved app 'DocumentSync Pro' with high-risk permissions including Files.ReadWrite.All", "Defender for Cloud Apps"),
        (_dt(hours_ago=1, minutes_ago=45), "analyst_note", "App not in approved application inventory. Domain registrar: NameCheap, registered 14 days ago. High suspicion of credential harvesting.", "Manual"),
        (_dt(hours_ago=1), "analyst_note", "VirusTotal domain lookup: documentsync-pro.io — 3/88 vendors flag as phishing. App store listing removed.", "Manual"),
    ]:
        db.session.add(TimelineEvent(case_id=c3.id, event_time=ev_time,
                                     event_type=etype, description=desc, source=src,
                                     created_by=analyst_id))

    # ── Case 4: Impossible Travel (LOW, Closed / False Positive) ─────────────
    c4 = Case(
        org_id=org_id, title="Impossible travel alert — sales rep account",
        description="Impossible travel alert: sign-in from London 2h after sign-in from New York. Determined to be VPN usage.",
        severity="low", status="false_positive", source="alert",
        source_ref="IDP-2024-201", created_by=analyst_id,
        created_at=_dt(days_ago=1), closed_at=_dt(days_ago=1, hours_ago=-4),
    )
    db.session.add(c4)
    db.session.flush()

    for ev_time, etype, desc, src in [
        (_dt(days_ago=1, hours_ago=8), "alert_fired", "Entra ID: Impossible travel — New York to London in 127 minutes for user t.williams@acmecorp.com", "Entra ID Identity Protection"),
        (_dt(days_ago=1, hours_ago=7), "analyst_note", "Confirmed with user via phone: was using corporate VPN exiting in London while physically in NYC. False positive.", "Manual"),
    ]:
        db.session.add(TimelineEvent(case_id=c4.id, event_time=ev_time,
                                     event_type=etype, description=desc, source=src,
                                     created_by=analyst_id))

    # ── Case 5: Privileged Escalation (CRITICAL, Investigating) ──────────────
    c5 = Case(
        org_id=org_id, title="Unauthorized Global Admin role assignment — service account",
        description="Service account svc-monitoring@acmecorp.com was granted Global Administrator role at 03:47 UTC. No change ticket exists. Account was previously Monitoring Reader only.",
        severity="critical", status="investigating", source="alert",
        source_ref="SIEM-2024-512", created_by=admin_id,
        created_at=_dt(hours_ago=1),
    )
    db.session.add(c5)
    db.session.flush()

    for etype, val in [("user","svc-monitoring@acmecorp.com"),("ip","40.90.23.194"),
                       ("cloud_resource","Azure AD — Global Administrator Role")]:
        db.session.add(Entity(case_id=c5.id, entity_type=etype, value=val))

    db.session.add(TimelineEvent(
        case_id=c5.id, event_time=_dt(hours_ago=1, minutes_ago=15),
        event_type="alert_fired",
        description="SIEM correlation: Global Admin role assigned to service account outside business hours (03:47 UTC) from Azure IP 40.90.23.194. No preceding MFA event.",
        source="Microsoft Sentinel", created_by=admin_id
    ))

    # ── Threat Intel Updates ──────────────────────────────────────────────────
    for d, iocs, props in [(7, 23, 4), (14, 31, 6), (21, 18, 3)]:
        tu = ThreatUpdate(
            org_id=org_id,
            run_date=(date.today() - timedelta(days=d)),
            sources_checked=3,
            iocs_found=iocs,
            proposals_generated=props,
            created_at=_dt(days_ago=d),
        )
        tu.summary = {
            "ioc_breakdown": {"urlhaus_urls": iocs-8, "cisa_kev": 5, "otx_pulses": 3},
            "ai_threats_reviewed": 10,
            "combined_summary": f"Weekly threat intel run — {iocs} IOCs found across {3} feeds.",
        }
        db.session.add(tu)
        db.session.flush()

        for j in range(props):
            prop = ThreatProposal(
                update_id=tu.id, org_id=org_id,
                proposal_type=["detection","playbook","evidence_req"][j % 3],
                title=f"Demo Proposal #{j+1} — Week -{d}d",
                rationale="Auto-generated from threat intel feed.",
                status="approved" if d > 7 else "proposed",
                created_at=_dt(days_ago=d),
            )
            sample_det = {
                "title": prop.title,
                "mitre_technique": f"T{1000+j}",
                "sigma_rule_stub": f"title: {prop.title}\nstatus: experimental\nlogsource:\n  product: windows\n  service: security\ndetection:\n  keywords:\n    - suspicious_indicator_{j}\n  condition: keywords",
                "rationale": prop.rationale,
            }
            prop.content = sample_det
            db.session.add(prop)

    # ── Applied Security Patch ────────────────────────────────────────────────
    patch = PatchRelease(
        org_id=org_id,
        version=f"{date.today().year}.{(date.today() - timedelta(days=7)).isocalendar()[1]:02d}.1",
        week_number=(date.today() - timedelta(days=7)).isocalendar()[1],
        title=f"Weekly Security Patch — LockBit + BEC Coverage Update",
        summary="3 new detections for LockBit 3.0 pre-encryption indicators. 1 new playbook: AiTM Phishing Response. 2 evidence requirement updates for BEC cases. All low-risk — auto-applied.",
        new_playbooks=1, new_detections=3, new_evidence_reqs=2,
        status="applied", auto_applied=True,
        applied_at=_dt(days_ago=7),
        created_at=_dt(days_ago=7),
    )
    patch.changes = [
        {"type": "detection_added", "risk": "low", "title": "vssadmin Shadow Copy Deletion", "description": "Detects vssadmin.exe deleting shadow copies — LockBit 3.0 precursor", "content": {"mitre_technique": "T1490", "sigma_rule_stub": "title: VSS Shadow Copy Deletion\ndetection:\n  CommandLine|contains:\n    - 'Delete Shadows'\n    - 'resize shadowstorage'\n  condition: CommandLine"}},
        {"type": "detection_added", "risk": "low", "title": "Mass File Extension Modification", "description": "Detects rapid bulk file extension changes in short time window", "content": {"mitre_technique": "T1486", "sigma_rule_stub": "title: Mass File Extension Change\ndetection:\n  EventID: 4663\n  ObjectType: File\n  condition: count() > 200 within 5m"}},
        {"type": "detection_added", "risk": "low", "title": "Suspicious OAuth Consent Grant", "description": "Detects OAuth consent to apps with Mail.Read + Files.ReadWrite in combo", "content": {"mitre_technique": "T1528", "sigma_rule_stub": "title: Risky OAuth Consent\ndetection:\n  Operation: Add OAuth2PermissionGrant\n  Scope|contains|all:\n    - Mail.Read\n    - Files.ReadWrite\n  condition: all"}},
        {"type": "playbook_added", "risk": "low", "title": "AiTM Phishing Response", "description": "New playbook for Adversary-in-the-Middle phishing with session token theft", "content": {}},
        {"type": "evidence_req_added", "risk": "low", "title": "BEC: Wire Transfer Hold Confirmation", "description": "Finance team confirmation that wire transfer was blocked", "content": {}},
        {"type": "evidence_req_added", "risk": "low", "title": "BEC: OAuth App Inventory Snapshot", "description": "Pre/post comparison of OAuth app consent grants for affected account", "content": {}},
    ]
    patch.rollback_manifest = [
        {"action": "delete_detection", "name": "vssadmin Shadow Copy Deletion"},
        {"action": "delete_detection", "name": "Mass File Extension Modification"},
        {"action": "delete_detection", "name": "Suspicious OAuth Consent Grant"},
        {"action": "delete_playbook", "name": "AiTM Phishing Response"},
        {"action": "log_only", "description": "Evidence requirements cannot be auto-rolled back"},
    ]
    db.session.add(patch)
    db.session.flush()

    # ── Detections from the patch ─────────────────────────────────────────────
    for det_name, mitre, rule in [
        ("vssadmin Shadow Copy Deletion", "T1490",
         "title: VSS Shadow Copy Deletion\nstatus: stable\nlogsource:\n  product: windows\n  service: security\ndetection:\n  CommandLine|contains:\n    - 'Delete Shadows'\n    - 'resize shadowstorage'\n  condition: CommandLine"),
        ("Mass File Extension Modification", "T1486",
         "title: Mass File Extension Change\nstatus: experimental\nlogsource:\n  product: windows\n  service: security\ndetection:\n  EventID: 4663\n  condition: count() > 200 within 5m"),
        ("Suspicious OAuth Consent Grant", "T1528",
         "title: Risky OAuth Consent Grant\nstatus: stable\nlogsource:\n  product: azure\n  service: auditlogs\ndetection:\n  Operation: Add OAuth2PermissionGrant\n  Scope|contains|all:\n    - Mail.Read\n    - Files.ReadWrite\n  condition: all"),
    ]:
        det = Detection(
            org_id=org_id, name=det_name, mitre_technique=mitre,
            rule_type="sigma", rule_content=rule, severity="high",
            status="active", version=1, patch_version=patch.version,
            created_by=admin_id, created_at=_dt(days_ago=7),
        )
        db.session.add(det)
        db.session.flush()
        db.session.add(ChangeLog(
            org_id=org_id, patch_id=patch.id, change_type="detection_added",
            resource_type="detection", resource_id=str(det.id),
            resource_name=det_name, description=f"Added Sigma rule for {mitre}",
            risk_level="low", applied_by=admin_id, created_at=_dt(days_ago=7),
        ))

    db.session.commit()
    print("[DEMO] Demo data seeded:")
    print(f"       5 cases (critical/high/medium/low/critical)")
    print(f"       2 playbook runs (1 completed with approvals, 1 pending approval)")
    print(f"       3 threat intel updates")
    print(f"       1 applied security patch with 6 changes")
    print(f"       3 active detections in the detection library")
    print(f"       Full audit trail")
