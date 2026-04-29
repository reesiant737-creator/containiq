from flask import Blueprint, render_template, request, jsonify
from flask_login import login_required, current_user
from ..models.patch import PatchRelease, Detection, ChangeLog
from ..services.patch_manager import PatchManager
from ..services.audit_service import audit
from ..app import db

patches_bp = Blueprint("patches", __name__, url_prefix="/patches")


@patches_bp.route("/")
@login_required
def patch_dashboard():
    patches = PatchRelease.query.filter_by(org_id=current_user.org_id).order_by(
        PatchRelease.created_at.desc()
    ).limit(52).all()  # last year of weekly patches
    pending = [p for p in patches if p.status == "ready"]
    return render_template("patches/dashboard.html", patches=patches, pending=pending)


@patches_bp.route("/generate", methods=["POST"])
@login_required
def generate_patch():
    if current_user.role not in ("admin", "analyst"):
        return jsonify({"error": "insufficient permissions"}), 403
    mgr = PatchManager(current_user.org_id)
    patch = mgr.generate_weekly_patch()
    audit("patch.generated", user_id=current_user.id, org_id=current_user.org_id,
          resource_type="patch", resource_id=str(patch.id),
          payload={"version": patch.version, "status": patch.status})
    return jsonify(patch.to_dict())


@patches_bp.route("/<int:patch_id>")
@login_required
def patch_detail(patch_id):
    patch = PatchRelease.query.filter_by(
        id=patch_id, org_id=current_user.org_id
    ).first_or_404()
    changelog = ChangeLog.query.filter_by(
        org_id=current_user.org_id, patch_id=patch_id
    ).order_by(ChangeLog.created_at.desc()).all()
    return render_template("patches/detail.html", patch=patch, changelog=changelog)


@patches_bp.route("/<int:patch_id>/apply", methods=["POST"])
@login_required
def apply_patch(patch_id):
    if not current_user.can_approve() and current_user.role != "analyst":
        return jsonify({"error": "insufficient permissions"}), 403
    patch = PatchRelease.query.filter_by(
        id=patch_id, org_id=current_user.org_id
    ).first_or_404()
    mgr = PatchManager(current_user.org_id)
    result = mgr.apply_patch(patch, current_user.id)
    if result["ok"]:
        audit("patch.applied", user_id=current_user.id, org_id=current_user.org_id,
              resource_type="patch", resource_id=str(patch_id),
              payload={"version": patch.version, "changes": result["applied"]})
    return jsonify(result)


@patches_bp.route("/<int:patch_id>/rollback", methods=["POST"])
@login_required
def rollback_patch(patch_id):
    if not current_user.can_approve():
        return jsonify({"error": "approver role required for rollback"}), 403
    patch = PatchRelease.query.filter_by(
        id=patch_id, org_id=current_user.org_id
    ).first_or_404()
    mgr = PatchManager(current_user.org_id)
    result = mgr.rollback_patch(patch, current_user.id)
    if result["ok"]:
        audit("patch.rolled_back", user_id=current_user.id, org_id=current_user.org_id,
              resource_type="patch", resource_id=str(patch_id),
              payload={"version": patch.version, "reversed": result["rolled_back"]})
    return jsonify(result)


@patches_bp.route("/detections")
@login_required
def detection_library():
    detections = Detection.query.filter_by(
        org_id=current_user.org_id, status="active"
    ).order_by(Detection.created_at.desc()).all()
    return render_template("patches/detections.html", detections=detections)


@patches_bp.route("/changelog")
@login_required
def full_changelog():
    entries = ChangeLog.query.filter_by(org_id=current_user.org_id).order_by(
        ChangeLog.created_at.desc()
    ).limit(200).all()
    return render_template("patches/changelog.html", entries=entries)


@patches_bp.route("/api/pending-count")
@login_required
def api_pending_count():
    count = PatchRelease.query.filter_by(
        org_id=current_user.org_id, status="ready", auto_applied=False
    ).count()
    return jsonify({"pending": count})
