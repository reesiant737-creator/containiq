from flask import Blueprint, render_template, request, jsonify
from flask_login import login_required, current_user
from ..models.threat import ThreatUpdate, ThreatProposal
from ..services.threat_intel import ThreatIntelService
from ..services.audit_service import audit
from ..app import db

threat_feed_bp = Blueprint("threat_feed", __name__, url_prefix="/threats")


@threat_feed_bp.route("/")
@login_required
def threat_dashboard():
    updates = ThreatUpdate.query.filter_by(org_id=current_user.org_id).order_by(
        ThreatUpdate.run_date.desc()
    ).limit(30).all()
    pending_proposals = ThreatProposal.query.filter_by(
        org_id=current_user.org_id, status="proposed"
    ).order_by(ThreatProposal.created_at.desc()).all()
    return render_template("threats/dashboard.html", updates=updates,
                           proposals=pending_proposals)


@threat_feed_bp.route("/run-now", methods=["POST"])
@login_required
def run_now():
    """Manual trigger for threat intel pipeline."""
    if current_user.role not in ("admin", "analyst"):
        return jsonify({"error": "insufficient permissions"}), 403
    svc = ThreatIntelService(current_user.org_id)
    update = svc.run()
    audit("threat_feed.manual_run", user_id=current_user.id, org_id=current_user.org_id,
          resource_type="threat_update", resource_id=str(update.id),
          payload={"iocs": update.iocs_found, "proposals": update.proposals_generated})
    return jsonify(update.to_dict())


@threat_feed_bp.route("/proposals/<int:prop_id>/review", methods=["POST"])
@login_required
def review_proposal(prop_id):
    proposal = ThreatProposal.query.filter_by(
        id=prop_id, org_id=current_user.org_id
    ).first_or_404()
    decision = request.json.get("decision")  # "approved" | "rejected"
    if decision not in ("approved", "rejected"):
        return jsonify({"error": "invalid decision"}), 400

    proposal.status = decision
    from datetime import datetime, timezone
    proposal.reviewed_at = datetime.now(timezone.utc)
    proposal.reviewed_by = current_user.id
    db.session.commit()

    audit("threat_feed.proposal_reviewed", user_id=current_user.id, org_id=current_user.org_id,
          resource_type="threat_proposal", resource_id=str(prop_id),
          payload={"decision": decision, "title": proposal.title})
    return jsonify(proposal.to_dict())


@threat_feed_bp.route("/api/latest")
@login_required
def api_latest():
    update = ThreatUpdate.query.filter_by(org_id=current_user.org_id).order_by(
        ThreatUpdate.run_date.desc()
    ).first()
    if not update:
        return jsonify({"message": "no threat updates yet"})
    return jsonify(update.to_dict())
