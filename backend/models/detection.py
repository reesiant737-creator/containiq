from datetime import datetime, timezone
import json
from ..app import db


class DetectionRule(db.Model):
    __tablename__ = "detection_rules"

    id = db.Column(db.Integer, primary_key=True)
    org_id = db.Column(db.Integer, db.ForeignKey("orgs.id"), nullable=False)
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    rule_type = db.Column(db.String(32), default="sigma")   # sigma | custom
    status = db.Column(db.String(32), default="active")     # active | disabled | draft | deleted
    severity = db.Column(db.String(32), default="medium")   # critical | high | medium | low
    mitre_tactics = db.Column(db.Text)    # JSON list e.g. ["TA0001", "TA0003"]
    mitre_techniques = db.Column(db.Text) # JSON list e.g. ["T1078", "T1059"]
    sigma_yaml = db.Column(db.Text)       # raw Sigma YAML if imported
    detection_logic = db.Column(db.Text)  # parsed/normalized detection as JSON
    tags = db.Column(db.Text)             # JSON list of tags
    source = db.Column(db.String(128))    # e.g. "SigmaHQ", "custom", "AI"
    false_positive_notes = db.Column(db.Text)
    created_by = db.Column(db.Integer, db.ForeignKey("users.id"))
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    org = db.relationship("Org", backref=db.backref("detection_rules", lazy="dynamic"))
    creator = db.relationship("User", foreign_keys=[created_by])

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "rule_type": self.rule_type,
            "status": self.status,
            "severity": self.severity,
            "mitre_tactics": json.loads(self.mitre_tactics or "[]"),
            "mitre_techniques": json.loads(self.mitre_techniques or "[]"),
            "tags": json.loads(self.tags or "[]"),
            "source": self.source,
            "false_positive_notes": self.false_positive_notes,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
