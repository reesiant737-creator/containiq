from datetime import datetime, timezone
from ..app import db
import json


class AuditLog(db.Model):
    """Immutable, append-only audit log. Never UPDATE or DELETE rows here."""
    __tablename__ = "audit_log"

    id = db.Column(db.Integer, primary_key=True)
    org_id = db.Column(db.Integer, db.ForeignKey("orgs.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    action = db.Column(db.String(128), nullable=False)   # e.g. "case.create", "playbook.execute"
    resource_type = db.Column(db.String(64))             # e.g. "case", "playbook_run"
    resource_id = db.Column(db.String(64))
    case_id = db.Column(db.Integer, db.ForeignKey("cases.id"))
    _payload = db.Column("payload", db.Text, default="{}")
    ip_address = db.Column(db.String(64))
    outcome = db.Column(db.String(32), default="success")  # success | failure | pending
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    user = db.relationship("User", foreign_keys=[user_id])

    @property
    def payload(self):
        return json.loads(self._payload or "{}")

    @payload.setter
    def payload(self, value):
        self._payload = json.dumps(value)

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "action": self.action,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "case_id": self.case_id,
            "outcome": self.outcome,
            "ip_address": self.ip_address,
            "created_at": self.created_at.isoformat(),
            "payload": self.payload,
        }

    # Block mutating operations at the model level
    @classmethod
    def _guard_immutability(cls):
        raise RuntimeError("AuditLog is immutable — no updates or deletes allowed.")
