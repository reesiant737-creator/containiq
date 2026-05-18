from datetime import datetime, timezone
from ..app import db


class Org(db.Model):
    __tablename__ = "orgs"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False)
    slug = db.Column(db.String(64), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    # ── Stripe billing ────────────────────────────────────────────────────
    plan = db.Column(db.String(32), default="free")               # free | pro
    plan_status = db.Column(db.String(32), default="active")      # active | past_due | cancelled
    stripe_customer_id = db.Column(db.String(128))
    stripe_subscription_id = db.Column(db.String(128))
    plan_expires_at = db.Column(db.DateTime)

    # Notification config — JSON: {slack_url, teams_url, smtp_host, smtp_port, smtp_user, smtp_pass, notify_email}
    notification_config = db.Column(db.Text, default="{}")

    users = db.relationship("User", back_populates="org", lazy="dynamic")
    cases = db.relationship("Case", back_populates="org", lazy="dynamic")
    playbooks = db.relationship("Playbook", back_populates="org", lazy="dynamic")

    @property
    def is_pro(self):
        return self.plan == "pro" and self.plan_status == "active"

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "slug": self.slug,
            "plan": self.plan,
            "plan_status": self.plan_status,
            "is_pro": self.is_pro,
        }
