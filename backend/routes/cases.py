from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify, current_app, session
from flask_login import login_required, current_user
from datetime import datetime, timezone
from ..models.case import Case, Entity, TimelineEvent, Evidence, SEVERITY, STATUS
from ..models.detection import DetectionRule
from ..services.audit_service import audit
from ..services.ioc_enrichment import enrich_entities_async, ENRICHABLE_TYPES
from ..app import db

cases_bp = Blueprint("cases", __name__)


@cases_bp.route("/dashboard")
@login_required
def dashboard():
    open_cases = Case.query.filter_by(org_id=current_user.org_id).filter(
        Case.status.in_(["open", "investigating"])
    ).order_by(Case.created_at.desc()).limit(20).all()

    stats = {
        "open": Case.query.filter_by(org_id=current_user.org_id, status="open").count(),
        "investigating": Case.query.filter_by(org_id=current_user.org_id, status="investigating").count(),
        "contained": Case.query.filter_by(org_id=current_user.org_id, status="contained").count(),
        "critical": Case.query.filter_by(org_id=current_user.org_id, severity="critical").filter(
            Case.status != "closed").count(),
    }

    # Onboarding — show until user dismisses or all steps complete
    show_onboarding = not session.get(f"onboarding_dismissed_{current_user.org_id}", False)

    total_cases = Case.query.filter_by(org_id=current_user.org_id).count()
    has_detections = DetectionRule.query.filter_by(org_id=current_user.org_id).first() is not None
    recent_case = Case.query.filter_by(org_id=current_user.org_id).order_by(Case.created_at.desc()).first()

    onboarding_steps = [
        {"title": "Create your account", "description": "You're in!", "url": "#", "done": True},
        {"title": "Create your first case", "description": "Track your first incident", "url": url_for("cases.create_case"), "done": total_cases > 0},
        {"title": "Connect an alert source", "description": "Ingest from Splunk, Sentinel, CrowdStrike", "url": url_for("settings.api_keys"), "done": False},
        {"title": "Configure notifications", "description": "Get paged on critical alerts", "url": url_for("settings.index"), "done": False},
        {"title": "Import detection rules", "description": "Load Sigma rules for instant coverage", "url": url_for("detections.import_rules_form"), "done": has_detections},
        {"title": "Run AI analysis", "description": "Let Claude investigate a case", "url": url_for("cases.case_detail", case_id=recent_case.id) if recent_case else url_for("cases.create_case"), "done": False},
    ]
    all_done = all(s["done"] for s in onboarding_steps)
    if all_done:
        show_onboarding = False

    return render_template("dashboard.html", cases=open_cases, stats=stats,
                           show_onboarding=show_onboarding,
                           onboarding_steps=onboarding_steps)


@cases_bp.route("/onboarding/dismiss", methods=["POST"])
@login_required
def dismiss_onboarding():
    session[f"onboarding_dismissed_{current_user.org_id}"] = True
    return redirect(url_for("cases.dashboard"))


@cases_bp.route("/cases/load-sample", methods=["POST"])
@login_required
def load_sample_case():
    """Create a realistic sample incident for onboarding."""
    sample = Case(
        org_id=current_user.org_id,
        title="[SAMPLE] Credential Stuffing Attack — Admin Portal",
        description="Multiple failed login attempts detected against the admin portal from 192.168.45.22. "
                    "23 failed attempts in 4 minutes followed by a successful login at 14:32 UTC. "
                    "Unusual session: login from new country (RU), immediate access to user export function.",
        severity="high",
        status="investigating",
        source="sentinel",
        source_ref=f"sample-{int(datetime.now(timezone.utc).timestamp())}",
        created_by=current_user.id,
    )
    db.session.add(sample)
    db.session.flush()

    entities_data = [
        ("ip", "192.168.45.22"), ("user", "admin@company.com"),
        ("domain", "company-portal.internal"), ("ip", "10.0.0.1"),
    ]
    for etype, val in entities_data:
        db.session.add(Entity(case_id=sample.id, entity_type=etype, value=val))

    events = [
        ("alert_fired", "Sentinel alert fired: Brute force threshold exceeded (23 attempts in 4 min)"),
        ("login", "Successful login from 192.168.45.22 (RU) at 14:32:07 UTC after 23 failures"),
        ("file_access", "User export function accessed — 4,200 user records queried within 90 seconds of login"),
        ("analyst_note", "[SAMPLE] This is example data. Open this case and click 'AI Analyze' to see ThreatCommand in action."),
    ]
    for i, (etype, desc) in enumerate(events):
        db.session.add(TimelineEvent(
            case_id=sample.id,
            event_time=datetime.now(timezone.utc),
            event_type=etype, description=desc,
            source="sentinel", created_by=current_user.id,
        ))

    db.session.commit()
    flash(f"Sample incident #{sample.id} loaded. Click 'AI Analyze' to see ThreatCommand in action!", "success")
    return redirect(url_for("cases.case_detail", case_id=sample.id))


@cases_bp.route("/cases")
@login_required
def list_cases():
    severity = request.args.get("severity")
    status = request.args.get("status")
    query = Case.query.filter_by(org_id=current_user.org_id)
    if severity:
        query = query.filter_by(severity=severity)
    if status:
        query = query.filter_by(status=status)
    cases = query.order_by(Case.created_at.desc()).all()
    return render_template("cases/list.html", cases=cases, severities=SEVERITY, statuses=STATUS)


@cases_bp.route("/cases/new", methods=["GET", "POST"])
@login_required
def create_case():
    if request.method == "POST":
        case = Case(
            org_id=current_user.org_id,
            title=request.form["title"],
            description=request.form.get("description"),
            severity=request.form.get("severity", "medium"),
            source=request.form.get("source", "manual"),
            created_by=current_user.id,
        )
        db.session.add(case)
        db.session.flush()

        # Parse entities
        new_entity_ids = []
        for line in request.form.get("entities", "").strip().splitlines():
            if ":" in line:
                etype, val = line.split(":", 1)
                e = Entity(case_id=case.id, entity_type=etype.strip(), value=val.strip())
                db.session.add(e)
                db.session.flush()
                if e.entity_type in ENRICHABLE_TYPES:
                    new_entity_ids.append(e.id)

        # First timeline event
        if request.form.get("initial_event"):
            te = TimelineEvent(
                case_id=case.id,
                event_time=datetime.now(timezone.utc),
                event_type="case_opened",
                description=request.form["initial_event"],
                source="manual",
                created_by=current_user.id,
            )
            db.session.add(te)

        db.session.commit()
        audit("case.create", user_id=current_user.id, org_id=current_user.org_id,
              resource_type="case", resource_id=str(case.id), case_id=case.id,
              payload={"title": case.title, "severity": case.severity})

        if new_entity_ids:
            enrich_entities_async(new_entity_ids, current_app._get_current_object())

        flash(f"Case #{case.id} created.", "success")
        return redirect(url_for("cases.case_detail", case_id=case.id))

    return render_template("cases/create.html", severities=SEVERITY)


@cases_bp.route("/cases/<int:case_id>")
@login_required
def case_detail(case_id):
    case = Case.query.filter_by(id=case_id, org_id=current_user.org_id).first_or_404()
    from ..models.playbook import Playbook
    playbooks = Playbook.query.filter_by(org_id=current_user.org_id, status="active").all()
    return render_template("cases/detail.html", case=case, playbooks=playbooks)


@cases_bp.route("/cases/<int:case_id>/status", methods=["POST"])
@login_required
def update_status(case_id):
    case = Case.query.filter_by(id=case_id, org_id=current_user.org_id).first_or_404()
    new_status = request.json.get("status")
    if new_status not in STATUS:
        return jsonify({"error": "invalid status"}), 400
    old_status = case.status
    case.status = new_status
    if new_status == "closed":
        case.closed_at = datetime.now(timezone.utc)
    db.session.commit()
    audit("case.status_change", user_id=current_user.id, org_id=current_user.org_id,
          resource_type="case", resource_id=str(case_id), case_id=case_id,
          payload={"from": old_status, "to": new_status})
    if new_status in ("contained", "closed") or case.severity == "critical":
        try:
            from ..services.notifier import Notifier
            from ..models.org import Org
            Notifier(org=Org.query.get(current_user.org_id)).status_change(
                case, old_status, new_status, current_user)
        except Exception:
            pass
    return jsonify({"status": case.status})


@cases_bp.route("/cases/<int:case_id>/timeline", methods=["POST"])
@login_required
def add_timeline_event(case_id):
    case = Case.query.filter_by(id=case_id, org_id=current_user.org_id).first_or_404()
    data = request.json
    te = TimelineEvent(
        case_id=case.id,
        event_time=datetime.fromisoformat(data["event_time"]) if data.get("event_time")
                   else datetime.now(timezone.utc),
        event_type=data.get("event_type", "analyst_note"),
        description=data["description"],
        source=data.get("source", "manual"),
        created_by=current_user.id,
    )
    db.session.add(te)
    db.session.commit()
    audit("case.timeline_event", user_id=current_user.id, org_id=current_user.org_id,
          resource_type="timeline_event", resource_id=str(te.id), case_id=case_id)
    return jsonify(te.to_dict()), 201


@cases_bp.route("/cases/<int:case_id>/evidence", methods=["POST"])
@login_required
def add_evidence(case_id):
    case = Case.query.filter_by(id=case_id, org_id=current_user.org_id).first_or_404()
    data = request.json
    ev = Evidence(
        case_id=case.id,
        name=data["name"],
        evidence_type=data.get("type", "log"),
        content=data.get("content"),
        created_by=current_user.id,
    )
    if ev.content:
        import hashlib
        ev.content_hash = hashlib.sha256(ev.content.encode()).hexdigest()
    db.session.add(ev)
    db.session.commit()
    audit("case.evidence_added", user_id=current_user.id, org_id=current_user.org_id,
          resource_type="evidence", resource_id=str(ev.id), case_id=case_id,
          payload={"name": ev.name, "type": ev.evidence_type})
    return jsonify(ev.to_dict()), 201


# ---------------------------------------------------------------------------
# Feature: Case Comments with @mentions
# ---------------------------------------------------------------------------

@cases_bp.route("/cases/<int:case_id>/comments", methods=["GET", "POST"])
@login_required
def case_comments(case_id):
    case = Case.query.filter_by(id=case_id, org_id=current_user.org_id).first_or_404()
    if request.method == "POST":
        from ..models.case import CaseComment
        from ..models.user import User
        import re, json
        body = request.json.get("body", "").strip()
        if not body:
            return jsonify({"error": "body required"}), 400
        # Extract @mentions - find @email or @display_name patterns
        mention_names = re.findall(r'@([\w.]+)', body)
        mention_ids = []
        for name in mention_names:
            u = User.query.filter(
                User.org_id == current_user.org_id,
                db.or_(User.email.ilike(f"{name}%"), User.display_name.ilike(f"{name}%"))
            ).first()
            if u:
                mention_ids.append(u.id)
        comment = CaseComment(
            case_id=case.id, author_id=current_user.id,
            body=body, mentions=json.dumps(mention_ids)
        )
        db.session.add(comment)
        db.session.commit()
        audit("case.comment", user_id=current_user.id, org_id=current_user.org_id,
              resource_type="comment", resource_id=str(comment.id), case_id=case_id)
        return jsonify(comment.to_dict()), 201
    # GET
    from ..models.case import CaseComment
    comments = CaseComment.query.filter_by(case_id=case.id).order_by(CaseComment.created_at.asc()).all()
    return jsonify([c.to_dict() for c in comments])


@cases_bp.route("/cases/api/mention-search")
@login_required
def mention_search():
    """Return org users matching a search term for @mention autocomplete."""
    from ..models.user import User
    q = request.args.get("q", "")
    users = User.query.filter(
        User.org_id == current_user.org_id,
        User.is_active == True,
        db.or_(User.email.ilike(f"%{q}%"), User.display_name.ilike(f"%{q}%"))
    ).limit(8).all()
    return jsonify([{"id": u.id, "name": u.display_name or u.email, "email": u.email} for u in users])


# ---------------------------------------------------------------------------
# Feature: Executive Case PDF Export
# ---------------------------------------------------------------------------

@cases_bp.route("/cases/<int:case_id>/export/pdf")
@login_required
def export_case_pdf(case_id):
    """Generate and download a professional PDF incident report."""
    from ..models.case import CaseComment
    case = Case.query.filter_by(id=case_id, org_id=current_user.org_id).first_or_404()
    timeline = TimelineEvent.query.filter_by(case_id=case.id).order_by(TimelineEvent.event_time.asc()).all()
    evidence = Evidence.query.filter_by(case_id=case.id).all()
    comments = CaseComment.query.filter_by(case_id=case.id).order_by(CaseComment.created_at.asc()).all()

    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib import colors
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
    from reportlab.lib.units import inch
    import io
    from flask import make_response

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter,
                            rightMargin=0.75*inch, leftMargin=0.75*inch,
                            topMargin=0.75*inch, bottomMargin=0.75*inch)
    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle('Title', parent=styles['Title'],
                                  fontSize=20, textColor=colors.HexColor('#1a1a2e'), spaceAfter=6)
    h2_style = ParagraphStyle('H2', parent=styles['Heading2'],
                               fontSize=13, textColor=colors.HexColor('#16213e'),
                               spaceBefore=14, spaceAfter=4)
    body_style = ParagraphStyle('Body', parent=styles['Normal'], fontSize=10, spaceAfter=4)
    meta_style = ParagraphStyle('Meta', parent=styles['Normal'], fontSize=9,
                                textColor=colors.grey, spaceAfter=2)

    SEV_COLORS = {'critical': '#dc3545', 'high': '#fd7e14', 'medium': '#ffc107', 'low': '#28a745'}
    sev_color = colors.HexColor(SEV_COLORS.get(case.severity, '#6c757d'))

    story = []

    # Header
    story.append(Paragraph("INCIDENT REPORT", meta_style))
    story.append(Paragraph(f"Case #{case.id}: {case.title}", title_style))
    story.append(HRFlowable(width="100%", thickness=2, color=sev_color))
    story.append(Spacer(1, 8))

    # Metadata table
    created_str = case.created_at.strftime('%Y-%m-%d %H:%M UTC') if case.created_at else 'Unknown'
    closed_str = case.closed_at.strftime('%Y-%m-%d %H:%M UTC') if case.closed_at else 'Open'
    meta_data = [
        ['Severity', case.severity.upper(), 'Status', case.status.upper()],
        ['Created', created_str, 'Closed', closed_str],
        ['Source', case.source or 'manual', 'Source Ref', case.source_ref or 'N/A'],
    ]
    meta_table = Table(meta_data, colWidths=[1.2*inch, 2.3*inch, 1.2*inch, 2.3*inch])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (0,-1), colors.HexColor('#f0f0f0')),
        ('BACKGROUND', (2,0), (2,-1), colors.HexColor('#f0f0f0')),
        ('FONTNAME', (0,0), (-1,-1), 'Helvetica'),
        ('FONTSIZE', (0,0), (-1,-1), 9),
        ('GRID', (0,0), (-1,-1), 0.5, colors.lightgrey),
        ('PADDING', (0,0), (-1,-1), 5),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 12))

    # Description
    if case.description:
        story.append(Paragraph("Description", h2_style))
        story.append(Paragraph(case.description or "No description provided.", body_style))
        story.append(Spacer(1, 8))

    # Entities
    if case.entities:
        story.append(Paragraph("Entities / Indicators of Compromise", h2_style))
        ent_data = [['Type', 'Value']] + [[e.entity_type, e.value] for e in case.entities]
        ent_table = Table(ent_data, colWidths=[1.5*inch, 5.5*inch])
        ent_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#16213e')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 9),
            ('GRID', (0,0), (-1,-1), 0.5, colors.lightgrey),
            ('PADDING', (0,0), (-1,-1), 5),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#f8f9fa')]),
        ]))
        story.append(ent_table)
        story.append(Spacer(1, 8))

    # Timeline
    if timeline:
        story.append(Paragraph("Investigation Timeline", h2_style))
        for te in timeline:
            ts = te.event_time.strftime('%Y-%m-%d %H:%M UTC') if te.event_time else ''
            story.append(Paragraph(f"<b>{ts}</b> — {te.event_type}", meta_style))
            story.append(Paragraph(te.description or '', body_style))
        story.append(Spacer(1, 8))

    # Evidence
    if evidence:
        story.append(Paragraph("Evidence", h2_style))
        for ev in evidence:
            story.append(Paragraph(f"<b>{ev.name}</b> ({ev.evidence_type})", body_style))
            if ev.content_hash:
                story.append(Paragraph(f"SHA-256: {ev.content_hash}", meta_style))
        story.append(Spacer(1, 8))

    # Analyst comments
    if comments:
        story.append(Paragraph("Analyst Notes", h2_style))
        for c in comments:
            ts = c.created_at.strftime('%Y-%m-%d %H:%M UTC') if c.created_at else ''
            author = c.author.display_name or c.author.email if c.author else 'Unknown'
            story.append(Paragraph(f"<b>{author}</b> — {ts}", meta_style))
            story.append(Paragraph(c.body, body_style))
        story.append(Spacer(1, 8))

    # Footer
    story.append(HRFlowable(width="100%", thickness=1, color=colors.lightgrey))
    story.append(Paragraph(f"Generated by ThreatCommand — {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}", meta_style))

    doc.build(story)
    buf.seek(0)

    response = make_response(buf.read())
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'attachment; filename="incident-{case.id}-report.pdf"'
    return response
