import json
from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify
from flask_login import login_required, current_user
from ..app import db
from ..models.detection import DetectionRule
from ..services.sigma_parser import parse_sigma_yaml, split_sigma_rules

detections_bp = Blueprint("detections", __name__, url_prefix="/detections")

SEVERITIES = ("critical", "high", "medium", "low")
SOURCES = ("SigmaHQ", "custom", "AI", "other")


# ── List ─────────────────────────────────────────────────────────────────────

@detections_bp.route("/")
@login_required
def list_rules():
    severity = request.args.get("severity")
    status = request.args.get("status")
    source = request.args.get("source")

    query = DetectionRule.query.filter(
        DetectionRule.org_id == current_user.org_id,
        DetectionRule.status != "deleted",
    )
    if severity:
        query = query.filter_by(severity=severity)
    if status:
        query = query.filter_by(status=status)
    if source:
        query = query.filter_by(source=source)

    rules = query.order_by(DetectionRule.created_at.desc()).all()

    # Stats
    base = DetectionRule.query.filter(
        DetectionRule.org_id == current_user.org_id,
        DetectionRule.status != "deleted",
    )
    stats = {
        "total": base.count(),
        "active": base.filter_by(status="active").count(),
        "critical": DetectionRule.query.filter(
            DetectionRule.org_id == current_user.org_id,
            DetectionRule.severity == "critical",
            DetectionRule.status != "deleted",
        ).count(),
        "high": DetectionRule.query.filter(
            DetectionRule.org_id == current_user.org_id,
            DetectionRule.severity == "high",
            DetectionRule.status != "deleted",
        ).count(),
    }

    return render_template(
        "detections/list.html",
        rules=rules,
        stats=stats,
        severities=SEVERITIES,
        sources=SOURCES,
        current_severity=severity,
        current_status=status,
        current_source=source,
    )


# ── Import ────────────────────────────────────────────────────────────────────

@detections_bp.route("/import", methods=["GET"])
@login_required
def import_rules_form():
    return render_template("detections/import.html")


@detections_bp.route("/import", methods=["POST"])
@login_required
def import_rules():
    yaml_text = ""

    # Check file upload first
    uploaded_file = request.files.get("yaml_file")
    if uploaded_file and uploaded_file.filename:
        try:
            yaml_text = uploaded_file.read().decode("utf-8", errors="replace")
        except Exception as exc:
            flash(f"Could not read uploaded file: {exc}", "danger")
            return redirect(url_for("detections.import_rules_form"))
    else:
        yaml_text = request.form.get("yaml_text", "").strip()

    if not yaml_text:
        flash("Please upload a file or paste YAML content.", "warning")
        return redirect(url_for("detections.import_rules_form"))

    source_label = request.form.get("source", "SigmaHQ")

    # Split into individual rules
    rule_texts = split_sigma_rules(yaml_text)
    if not rule_texts:
        flash("No rules found in the provided content.", "warning")
        return redirect(url_for("detections.import_rules_form"))

    imported = 0
    errors = []

    for i, rule_text in enumerate(rule_texts, start=1):
        try:
            parsed = parse_sigma_yaml(rule_text)
        except (ValueError, Exception) as exc:
            errors.append(f"Rule #{i} ({str(exc)[:80]})")
            continue

        rule = DetectionRule(
            org_id=current_user.org_id,
            name=parsed["title"],
            description=parsed["description"],
            rule_type="sigma",
            status="active",
            severity=parsed["severity"],
            mitre_tactics=json.dumps(parsed["mitre_tactics"]),
            mitre_techniques=json.dumps(parsed["mitre_techniques"]),
            sigma_yaml=rule_text,
            detection_logic=parsed["detection_logic"],
            tags=json.dumps(parsed["tags"]),
            source=source_label,
            false_positive_notes=parsed["false_positive_notes"],
            created_by=current_user.id,
        )
        db.session.add(rule)
        imported += 1

    if imported:
        db.session.commit()
        flash(
            f"Successfully imported {imported} detection rule{'s' if imported != 1 else ''}.",
            "success",
        )
    if errors:
        flash(
            f"{len(errors)} rule(s) could not be parsed and were skipped: "
            + "; ".join(errors[:5])
            + ("..." if len(errors) > 5 else ""),
            "warning",
        )
    if not imported and not errors:
        flash("No rules were imported.", "warning")

    return redirect(url_for("detections.list_rules"))


# ── Toggle ────────────────────────────────────────────────────────────────────

@detections_bp.route("/<int:rule_id>/toggle", methods=["POST"])
@login_required
def toggle_rule(rule_id):
    rule = DetectionRule.query.filter_by(
        id=rule_id, org_id=current_user.org_id
    ).first_or_404()

    if rule.status == "active":
        rule.status = "disabled"
    elif rule.status in ("disabled", "draft"):
        rule.status = "active"
    # if "deleted" leave it

    db.session.commit()

    # JSON response if called via fetch; otherwise redirect
    if request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html:
        return jsonify({"status": rule.status})
    flash(
        f"Rule '{rule.name}' is now {rule.status}.",
        "success" if rule.status == "active" else "secondary",
    )
    return redirect(url_for("detections.list_rules"))


# ── Delete (soft) ─────────────────────────────────────────────────────────────

@detections_bp.route("/<int:rule_id>/delete", methods=["POST"])
@login_required
def delete_rule(rule_id):
    rule = DetectionRule.query.filter_by(
        id=rule_id, org_id=current_user.org_id
    ).first_or_404()
    rule.status = "deleted"
    db.session.commit()
    flash(f"Rule '{rule.name}' has been deleted.", "info")
    return redirect(url_for("detections.list_rules"))


# ── API ───────────────────────────────────────────────────────────────────────

@detections_bp.route("/api/list")
@login_required
def api_list():
    rules = (
        DetectionRule.query.filter(
            DetectionRule.org_id == current_user.org_id,
            DetectionRule.status == "active",
        )
        .order_by(DetectionRule.created_at.desc())
        .limit(100)
        .all()
    )
    return jsonify([r.to_dict() for r in rules])
