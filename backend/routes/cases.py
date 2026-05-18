from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify, current_app
from flask_login import login_required, current_user
from datetime import datetime, timezone
from ..models.case import Case, Entity, TimelineEvent, Evidence, SEVERITY, STATUS
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
    return render_template("dashboard.html", cases=open_cases, stats=stats)


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
