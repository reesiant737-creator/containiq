from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user
from datetime import datetime, timezone
from ..models.user import User
from ..services.audit_service import audit
from ..app import db

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("cases.dashboard"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = User.query.filter_by(email=email).first()

        if user and user.is_active and user.check_password(password):
            login_user(user, remember=request.form.get("remember") == "on")
            user.last_login = datetime.now(timezone.utc)
            db.session.commit()
            audit("auth.login", user_id=user.id, org_id=user.org_id,
                  resource_type="user", resource_id=str(user.id))
            return redirect(url_for("cases.dashboard"))

        audit("auth.login_failed", payload={"email": email},
              outcome="failure", org_id=user.org_id if user else None)
        flash("Invalid credentials.", "danger")

    return render_template("login.html")


@auth_bp.route("/logout")
@login_required
def logout():
    audit("auth.logout", user_id=current_user.id, org_id=current_user.org_id,
          resource_type="user", resource_id=str(current_user.id))
    logout_user()
    return redirect(url_for("auth.login"))
