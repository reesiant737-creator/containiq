"""
Settings routes — org config, user management, API key display.
"""
import json
from flask import (Blueprint, render_template, redirect, url_for,
                   flash, request, current_app)
from flask_login import login_required, current_user
from ..app import db
from ..models.org import Org
from ..models.user import User, ROLES
from ..services.audit_service import audit

settings_bp = Blueprint("settings", __name__, url_prefix="/settings")


# ── Index ──────────────────────────────────────────────────────────────────────

@settings_bp.route("/")
@login_required
def index():
    org = Org.query.get(current_user.org_id)
    raw_key = current_app.config.get("INGEST_API_KEY", "")
    masked_key = _mask_key(raw_key)

    # Notification config stored as JSON in org.notification_config (if column exists),
    # otherwise fall back to an empty dict so the template always has values.
    notif = _get_notif_config(org)

    return render_template(
        "settings/index.html",
        org=org,
        masked_key=masked_key,
        notif=notif,
    )


# ── Org name ──────────────────────────────────────────────────────────────────

@settings_bp.route("/org", methods=["POST"])
@login_required
def update_org():
    if current_user.role != "admin":
        flash("Only admins can change org settings.", "danger")
        return redirect(url_for("settings.index"))

    org = Org.query.get(current_user.org_id)
    new_name = request.form.get("org_name", "").strip()
    if not new_name:
        flash("Org name cannot be empty.", "danger")
        return redirect(url_for("settings.index"))

    org.name = new_name
    db.session.commit()
    audit("settings.update", user_id=current_user.id, org_id=org.id,
          resource_type="org", resource_id=str(org.id),
          payload={"field": "name", "new_value": new_name})
    flash("Organisation name updated.", "success")
    return redirect(url_for("settings.index"))


# ── Notification webhooks ─────────────────────────────────────────────────────

@settings_bp.route("/notifications", methods=["POST"])
@login_required
def update_notifications():
    if current_user.role != "admin":
        flash("Only admins can change notification settings.", "danger")
        return redirect(url_for("settings.index"))

    org = Org.query.get(current_user.org_id)
    notif = {
        "slack_webhook":  request.form.get("slack_webhook", "").strip(),
        "teams_webhook":  request.form.get("teams_webhook", "").strip(),
        "smtp_host":      request.form.get("smtp_host", "").strip(),
        "smtp_port":      request.form.get("smtp_port", "").strip(),
        "smtp_from":      request.form.get("smtp_from", "").strip(),
    }

    # Persist to notification_config column if it exists; silently skip otherwise.
    _set_notif_config(org, notif)
    db.session.commit()
    audit("settings.update", user_id=current_user.id, org_id=org.id,
          resource_type="org", resource_id=str(org.id),
          payload={"field": "notifications"})
    flash("Notification settings saved.", "success")
    return redirect(url_for("settings.index"))


# ── Users list ────────────────────────────────────────────────────────────────

@settings_bp.route("/users")
@login_required
def users():
    if current_user.role != "admin":
        flash("Only admins can manage users.", "danger")
        return redirect(url_for("settings.index"))

    org_users = (
        User.query
        .filter_by(org_id=current_user.org_id)
        .order_by(User.created_at.asc())
        .all()
    )
    return render_template("settings/users.html", org_users=org_users, roles=ROLES)


# ── Invite user ───────────────────────────────────────────────────────────────

@settings_bp.route("/users/invite", methods=["POST"])
@login_required
def invite_user():
    if current_user.role != "admin":
        flash("Only admins can invite users.", "danger")
        return redirect(url_for("settings.users"))

    email    = request.form.get("email", "").strip().lower()
    role     = request.form.get("role", "analyst")
    password = request.form.get("password", "")

    if not email or not password:
        flash("Email and password are required.", "danger")
        return redirect(url_for("settings.users"))

    if role not in ROLES:
        flash("Invalid role selected.", "danger")
        return redirect(url_for("settings.users"))

    if User.query.filter_by(email=email).first():
        flash(f"A user with email {email} already exists.", "danger")
        return redirect(url_for("settings.users"))

    user = User(
        org_id=current_user.org_id,
        email=email,
        role=role,
        display_name=email.split("@")[0],
        is_active=True,
    )
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    audit("settings.user_invited", user_id=current_user.id, org_id=current_user.org_id,
          resource_type="user", resource_id=str(user.id),
          payload={"email": email, "role": role})
    flash(f"User {email} created with role {role}.", "success")
    return redirect(url_for("settings.users"))


# ── Deactivate user ───────────────────────────────────────────────────────────

@settings_bp.route("/users/<int:user_id>/deactivate", methods=["POST"])
@login_required
def deactivate_user(user_id):
    if current_user.role != "admin":
        flash("Only admins can deactivate users.", "danger")
        return redirect(url_for("settings.users"))

    if user_id == current_user.id:
        flash("You cannot deactivate your own account.", "danger")
        return redirect(url_for("settings.users"))

    user = User.query.filter_by(id=user_id, org_id=current_user.org_id).first_or_404()
    user.is_active = False
    db.session.commit()
    audit("settings.user_deactivated", user_id=current_user.id, org_id=current_user.org_id,
          resource_type="user", resource_id=str(user.id),
          payload={"email": user.email})
    flash(f"User {user.email} deactivated.", "success")
    return redirect(url_for("settings.users"))


# ── API keys (read-only display) ──────────────────────────────────────────────

@settings_bp.route("/api-keys")
@login_required
def api_keys():
    if current_user.role != "admin":
        flash("Only admins can view API keys.", "danger")
        return redirect(url_for("settings.index"))

    raw_key = current_app.config.get("INGEST_API_KEY", "")
    masked_key = _mask_key(raw_key)
    return render_template("settings/index.html",
                           org=Org.query.get(current_user.org_id),
                           masked_key=masked_key,
                           notif=_get_notif_config(Org.query.get(current_user.org_id)),
                           scroll_to="api-keys")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _mask_key(key: str) -> str:
    """Show only first 4 and last 4 characters; mask the rest."""
    if not key or len(key) <= 8:
        return "••••••••"
    return key[:4] + "•" * (len(key) - 8) + key[-4:]


def _get_notif_config(org) -> dict:
    """Safely read notification_config from org; return empty dict if column missing."""
    try:
        raw = getattr(org, "notification_config", None)
        if raw:
            return json.loads(raw) if isinstance(raw, str) else raw
    except Exception:
        pass
    return {
        "slack_webhook": "",
        "teams_webhook": "",
        "smtp_host": "",
        "smtp_port": "",
        "smtp_from": "",
    }


def _set_notif_config(org, config: dict):
    """Safely write notification_config to org if the column exists."""
    try:
        org.notification_config = json.dumps(config)
    except Exception:
        pass  # column doesn't exist yet — migrations will add it later
