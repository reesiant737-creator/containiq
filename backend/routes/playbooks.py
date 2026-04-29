from flask import Blueprint, render_template, request, jsonify, flash, redirect, url_for
from flask_login import login_required, current_user
from datetime import datetime, timezone
from ..models.playbook import Playbook, PlaybookRun, PlaybookApproval
from ..models.case import Case
from ..services.playbook_runner import PlaybookRunner
from ..services.audit_service import audit
from ..app import db

playbooks_bp = Blueprint("playbooks", __name__, url_prefix="/playbooks")


@playbooks_bp.route("/")
@login_required
def list_playbooks():
    playbooks = Playbook.query.filter_by(org_id=current_user.org_id, status="active").all()
    return render_template("playbooks/list.html", playbooks=playbooks)


@playbooks_bp.route("/<int:pb_id>/run", methods=["GET", "POST"])
@login_required
def run_playbook(pb_id):
    pb = Playbook.query.filter_by(id=pb_id, org_id=current_user.org_id).first_or_404()
    cases = Case.query.filter_by(org_id=current_user.org_id).filter(
        Case.status.in_(["open", "investigating"])
    ).order_by(Case.created_at.desc()).all()

    if request.method == "POST":
        case_id = int(request.form["case_id"])
        mode = request.form.get("mode", "dry_run")
        case = Case.query.filter_by(id=case_id, org_id=current_user.org_id).first_or_404()

        runner = PlaybookRunner(pb, case, current_user, mode=mode)
        run = runner.initialize_run()
        db.session.add(run)
        db.session.commit()

        audit("playbook.run_started", user_id=current_user.id, org_id=current_user.org_id,
              resource_type="playbook_run", resource_id=str(run.id), case_id=case_id,
              payload={"playbook": pb.name, "mode": mode})

        return redirect(url_for("playbooks.run_detail", run_id=run.id))

    return render_template("playbooks/runner.html", playbook=pb, cases=cases)


@playbooks_bp.route("/runs/<int:run_id>")
@login_required
def run_detail(run_id):
    run = PlaybookRun.query.filter_by(id=run_id, org_id=current_user.org_id).first_or_404()
    return render_template("playbooks/run_detail.html", run=run, playbook=run.playbook)


@playbooks_bp.route("/runs/<int:run_id>/advance", methods=["POST"])
@login_required
def advance_step(run_id):
    run = PlaybookRun.query.filter_by(id=run_id, org_id=current_user.org_id).first_or_404()
    runner = PlaybookRunner.from_run(run, current_user)
    result = runner.advance()
    db.session.commit()
    audit("playbook.step_advanced", user_id=current_user.id, org_id=current_user.org_id,
          resource_type="playbook_run", resource_id=str(run_id), case_id=run.case_id,
          payload=result)
    return jsonify(result)


@playbooks_bp.route("/runs/<int:run_id>/approve/<int:approval_id>", methods=["POST"])
@login_required
def approve_step(run_id, approval_id):
    if not current_user.can_approve():
        return jsonify({"error": "insufficient permissions"}), 403

    approval = PlaybookApproval.query.filter_by(id=approval_id, run_id=run_id).first_or_404()
    data = request.json
    approval.status = data.get("decision", "approved")
    approval.reason = data.get("reason", "")
    approval.approved_by = current_user.id
    approval.decided_at = datetime.now(timezone.utc)
    db.session.commit()

    audit("playbook.approval_decision", user_id=current_user.id, org_id=current_user.org_id,
          resource_type="playbook_approval", resource_id=str(approval_id),
          case_id=approval.run.case_id,
          payload={"decision": approval.status, "step": approval.step_index})

    return jsonify(approval.to_dict())


@playbooks_bp.route("/runs/<int:run_id>/rollback", methods=["POST"])
@login_required
def rollback_run(run_id):
    run = PlaybookRun.query.filter_by(id=run_id, org_id=current_user.org_id).first_or_404()
    runner = PlaybookRunner.from_run(run, current_user)
    result = runner.rollback()
    db.session.commit()
    audit("playbook.rollback", user_id=current_user.id, org_id=current_user.org_id,
          resource_type="playbook_run", resource_id=str(run_id), case_id=run.case_id)
    return jsonify(result)


@playbooks_bp.route("/api/runs/<int:run_id>")
@login_required
def api_run_status(run_id):
    run = PlaybookRun.query.filter_by(id=run_id, org_id=current_user.org_id).first_or_404()
    return jsonify(run.to_dict())
