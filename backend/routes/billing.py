"""
Stripe billing routes.
Handles subscription checkout, webhooks, and the customer portal.
"""
import stripe
from flask import (Blueprint, render_template, redirect, url_for,
                   request, flash, current_app, jsonify)
from flask_login import login_required, current_user
from ..app import db
from ..models.org import Org
from ..services.audit_service import audit

billing_bp = Blueprint("billing", __name__, url_prefix="/billing")


def _stripe():
    stripe.api_key = current_app.config.get("STRIPE_SECRET_KEY", "")
    return stripe


# ── Dashboard ─────────────────────────────────────────────────────────────────

@billing_bp.route("/")
@login_required
def dashboard():
    org = Org.query.get(current_user.org_id)
    return render_template("billing/dashboard.html",
                           org=org,
                           publishable_key=current_app.config.get("STRIPE_PUBLISHABLE_KEY", ""),
                           price_display=current_app.config.get("STRIPE_PRO_PRICE_DISPLAY", "$99/month"))


# ── Checkout ──────────────────────────────────────────────────────────────────

@billing_bp.route("/checkout", methods=["POST"])
@login_required
def checkout():
    s = _stripe()
    if not s.api_key:
        flash("Billing is not configured yet. Add STRIPE_SECRET_KEY to your environment.", "warning")
        return redirect(url_for("billing.dashboard"))

    org = Org.query.get(current_user.org_id)

    try:
        # Create or retrieve Stripe customer
        if not org.stripe_customer_id:
            customer = s.Customer.create(
                email=current_user.email,
                name=org.name,
                metadata={"org_id": org.id, "org_slug": org.slug},
            )
            org.stripe_customer_id = customer.id
            db.session.commit()

        price_id = current_app.config.get("STRIPE_PRO_PRICE_ID", "")
        if not price_id:
            flash("Stripe price ID not configured. Set STRIPE_PRO_PRICE_ID in your environment.", "warning")
            return redirect(url_for("billing.dashboard"))

        session = s.checkout.Session.create(
            customer=org.stripe_customer_id,
            payment_method_types=["card"],
            line_items=[{"price": price_id, "quantity": 1}],
            mode="subscription",
            success_url=url_for("billing.success", _external=True) + "?session_id={CHECKOUT_SESSION_ID}",
            cancel_url=url_for("billing.cancel", _external=True),
            metadata={"org_id": org.id},
        )
        audit("billing.checkout_started", user_id=current_user.id, org_id=org.id,
              resource_type="org", resource_id=str(org.id))
        return redirect(session.url, code=303)

    except s.error.StripeError as e:
        flash(f"Payment error: {e.user_message}", "danger")
        return redirect(url_for("billing.dashboard"))


# ── Success / Cancel ──────────────────────────────────────────────────────────

@billing_bp.route("/success")
@login_required
def success():
    flash("You're now on the Pro plan. Thank you!", "success")
    audit("billing.checkout_success", user_id=current_user.id, org_id=current_user.org_id,
          resource_type="org", resource_id=str(current_user.org_id))
    return redirect(url_for("billing.dashboard"))


@billing_bp.route("/cancel")
@login_required
def cancel():
    flash("Checkout cancelled — you haven't been charged.", "info")
    return redirect(url_for("billing.dashboard"))


# ── Customer Portal ───────────────────────────────────────────────────────────

@billing_bp.route("/portal", methods=["POST"])
@login_required
def portal():
    s = _stripe()
    if not s.api_key:
        flash("Billing is not configured.", "warning")
        return redirect(url_for("billing.dashboard"))

    org = Org.query.get(current_user.org_id)
    if not org.stripe_customer_id:
        flash("No active subscription found.", "warning")
        return redirect(url_for("billing.dashboard"))

    try:
        session = s.billing_portal.Session.create(
            customer=org.stripe_customer_id,
            return_url=url_for("billing.dashboard", _external=True),
        )
        return redirect(session.url, code=303)
    except s.error.StripeError as e:
        flash(f"Portal error: {e.user_message}", "danger")
        return redirect(url_for("billing.dashboard"))


# ── Webhook ───────────────────────────────────────────────────────────────────

@billing_bp.route("/webhook", methods=["POST"])
def webhook():
    s = _stripe()
    payload = request.get_data()
    sig = request.headers.get("Stripe-Signature", "")
    webhook_secret = current_app.config.get("STRIPE_WEBHOOK_SECRET", "")

    try:
        event = s.Webhook.construct_event(payload, sig, webhook_secret)
    except s.error.SignatureVerificationError:
        return jsonify({"error": "Invalid signature"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 400

    _handle_event(event)
    return jsonify({"received": True}), 200


def _handle_event(event):
    s = _stripe()
    etype = event["type"]
    data = event["data"]["object"]

    if etype == "checkout.session.completed":
        org_id = data.get("metadata", {}).get("org_id")
        subscription_id = data.get("subscription")
        if org_id:
            org = Org.query.get(int(org_id))
            if org:
                org.plan = "pro"
                org.plan_status = "active"
                org.stripe_subscription_id = subscription_id
                db.session.commit()

    elif etype in ("customer.subscription.updated", "customer.subscription.created"):
        sub = data
        org = Org.query.filter_by(stripe_subscription_id=sub["id"]).first()
        if not org:
            org = Org.query.filter_by(stripe_customer_id=sub.get("customer")).first()
        if org:
            status = sub.get("status")  # active | past_due | cancelled | trialing
            org.stripe_subscription_id = sub["id"]
            org.plan = "pro" if status in ("active", "trialing") else "free"
            org.plan_status = status
            db.session.commit()

    elif etype == "customer.subscription.deleted":
        sub = data
        org = Org.query.filter_by(stripe_subscription_id=sub["id"]).first()
        if org:
            org.plan = "free"
            org.plan_status = "cancelled"
            org.stripe_subscription_id = None
            db.session.commit()

    elif etype == "invoice.payment_failed":
        customer_id = data.get("customer")
        org = Org.query.filter_by(stripe_customer_id=customer_id).first()
        if org:
            org.plan_status = "past_due"
            db.session.commit()
