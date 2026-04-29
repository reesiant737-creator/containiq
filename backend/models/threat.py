from datetime import datetime, timezone
from ..app import db
import json

PROPOSAL_STATUS = ("proposed", "testing", "approved", "deployed", "rejected")


class ThreatUpdate(db.Model):
    """Daily threat intel ingestion record."""
    __tablename__ = "threat_updates"

    id = db.Column(db.Integer, primary_key=True)
    org_id = db.Column(db.Integer, db.ForeignKey("orgs.id"), nullable=False)
    run_date = db.Column(db.Date, nullable=False)
    sources_checked = db.Column(db.Integer, default=0)
    iocs_found = db.Column(db.Integer, default=0)
    proposals_generated = db.Column(db.Integer, default=0)
    _summary = db.Column("summary", db.Text, default="{}")
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    proposals = db.relationship("ThreatProposal", back_populates="update",
                                cascade="all, delete-orphan")

    @property
    def summary(self):
        return json.loads(self._summary or "{}")

    @summary.setter
    def summary(self, value):
        self._summary = json.dumps(value)

    def to_dict(self):
        return {
            "id": self.id,
            "run_date": self.run_date.isoformat(),
            "sources_checked": self.sources_checked,
            "iocs_found": self.iocs_found,
            "proposals_generated": self.proposals_generated,
            "summary": self.summary,
        }


class ThreatProposal(db.Model):
    """A proposed change (new detection, updated playbook) generated from threat intel."""
    __tablename__ = "threat_proposals"

    id = db.Column(db.Integer, primary_key=True)
    update_id = db.Column(db.Integer, db.ForeignKey("threat_updates.id"), nullable=False)
    org_id = db.Column(db.Integer, db.ForeignKey("orgs.id"), nullable=False)
    proposal_type = db.Column(db.String(32))  # detection | playbook | evidence_req | alert_rule
    title = db.Column(db.String(256), nullable=False)
    rationale = db.Column(db.Text)
    _content = db.Column("content", db.Text, default="{}")
    status = db.Column(db.String(32), default="proposed")
    reviewed_by = db.Column(db.Integer, db.ForeignKey("users.id"))
    reviewed_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    update = db.relationship("ThreatUpdate", back_populates="proposals")

    @property
    def content(self):
        return json.loads(self._content or "{}")

    @content.setter
    def content(self, value):
        self._content = json.dumps(value)

    def to_dict(self):
        return {
            "id": self.id,
            "type": self.proposal_type,
            "title": self.title,
            "rationale": self.rationale,
            "content": self.content,
            "status": self.status,
            "created_at": self.created_at.isoformat(),
        }
