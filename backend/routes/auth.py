from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user
from datetime import datetime, timezone
import re
from ..models.user import User
from ..models.org import Org
from ..services.audit_service import audit
from ..app import db

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("cases.dashboard"))

    if request.method == "POST":
        org_name = request.form.get("org_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")

        # Basic validation
        if not org_name or not email or not password:
            flash("All fields are required.", "danger")
            return render_template("register.html")
        if password != confirm:
            flash("Passwords do not match.", "danger")
            return render_template("register.html")
        if len(password) < 8:
            flash("Password must be at least 8 characters.", "danger")
            return render_template("register.html")
        if User.query.filter_by(email=email).first():
            flash("An account with that email already exists.", "danger")
            return render_template("register.html")

        # Create org slug from name
        slug = re.sub(r"[^a-z0-9]+", "-", org_name.lower()).strip("-")[:48]
        if Org.query.filter_by(slug=slug).first():
            slug = f"{slug}-{int(datetime.now().timestamp()) % 10000}"

        org = Org(name=org_name, slug=slug)
        db.session.add(org)
        db.session.flush()

        display_name = email.split("@")[0].replace(".", " ").replace("_", " ").title()
        user = User(org_id=org.id, email=email, role="admin",
                    is_active=True, display_name=display_name)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        audit("auth.register", user_id=user.id, org_id=org.id,
              resource_type="user", resource_id=str(user.id))
        login_user(user)
        flash(f"Welcome to ThreatCommand, {org_name}! Your free account is ready.", "success")
        return redirect(url_for("cases.dashboard"))

    return render_template("register.html")


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
