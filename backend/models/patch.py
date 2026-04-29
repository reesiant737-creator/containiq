from datetime import datetime, timezone
from ..app import db
import json

PATCH_STATUS = ("draft", "ready", "applying", "applied", "rolled_back", "failed")
CHANGE_RISK = ("low", "medium", "high")


class PatchRelease(db.Model):
    """Weekly security patch bundle — bundles approved threat proposals into a versioned release."""
    __tablename__ = "patch_releases"

    id = db.Column(db.Integer, primary_key=True)
    org_id = db.Column(db.Integer, db.ForeignKey("orgs.id"), nullable=False)
    version = db.Column(db.String(32), nullable=False)        # e.g. "2026.17.1" (year.week.patch)
    status = db.Column(db.String(32), default="draft")
    title = db.Column(db.String(256))
    summary = db.Column(db.Text)

    # Change counts by type
    new_playbooks = db.Column(db.Integer, default=0)
    updated_playbooks = db.Column(db.Integer, default=0)
    new_detections = db.Column(db.Integer, default=0)
    updated_detections = db.Column(db.Integer, default=0)
    new_evidence_reqs = db.Column(db.Integer, default=0)

    _changes = db.Column("changes", db.Text, default="[]")       # list of change records
    _rollback_manifest = db.Column("rollback_manifest", db.Text, default="[]")

    auto_applied = db.Column(db.Boolean, default=False)           # True if all changes were low-risk
    applied_by = db.Column(db.Integer, db.ForeignKey("users.id"))
    applied_at = db.Column(db.DateTime)
    rolled_back_by = db.Column(db.Integer, db.ForeignKey("users.id"))
    rolled_back_at = db.Column(db.DateTime)

    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    week_number = db.Column(db.Integer)   # ISO week number

    @property
    def changes(self):
        return json.loads(self._changes or "[]")

    @changes.setter
    def changes(self, value):
        self._changes = json.dumps(value)

    @property
    def rollback_manifest(self):
        return json.loads(self._rollback_manifest or "[]")

    @rollback_manifest.setter
    def rollback_manifest(self, value):
        self._rollback_manifest = json.dumps(value)

    def to_dict(self):
        return {
            "id": self.id,
            "version": self.version,
            "status": self.status,
            "title": self.title,
            "summary": self.summary,
            "new_playbooks": self.new_playbooks,
            "updated_playbooks": self.updated_playbooks,
            "new_detections": self.new_detections,
            "updated_detections": self.updated_detections,
            "new_evidence_reqs": self.new_evidence_reqs,
            "auto_applied": self.auto_applied,
            "week_number": self.week_number,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "applied_at": self.applied_at.isoformat() if self.applied_at else None,
            "changes": self.changes,
        }


class Detection(db.Model):
    """Detection rule library — Sigma, SPL, KQL rules versioned and tracked."""
    __tablename__ = "detections"

    id = db.Column(db.Integer, primary_key=True)
    org_id = db.Column(db.Integer, db.ForeignKey("orgs.id"), nullable=False)
    name = db.Column(db.String(256), nullable=False)
    description = db.Column(db.Text)
    mitre_technique = db.Column(db.String(32))      # e.g. "T1114.003"
    rule_type = db.Column(db.String(32))            # sigma | splunk_spl | kql | eql | yara
    rule_content = db.Column(db.Text)               # the actual rule
    severity = db.Column(db.String(16), default="medium")
    status = db.Column(db.String(32), default="active")  # draft | active | deprecated
    version = db.Column(db.Integer, default=1)
    patch_version = db.Column(db.String(32))         # which patch introduced/updated this
    created_by = db.Column(db.Integer, db.ForeignKey("users.id"))
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc),
                           onupdate=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "mitre_technique": self.mitre_technique,
            "rule_type": self.rule_type,
            "rule_content": self.rule_content,
            "severity": self.severity,
            "status": self.status,
            "version": self.version,
            "patch_version": self.patch_version,
        }


class ChangeLog(db.Model):
    """Immutable log of every content change applied to the platform."""
    __tablename__ = "change_log"

    id = db.Column(db.Integer, primary_key=True)
    org_id = db.Column(db.Integer, db.ForeignKey("orgs.id"), nullable=False)
    patch_id = db.Column(db.Integer, db.ForeignKey("patch_releases.id"))
    change_type = db.Column(db.String(64))     # playbook_added | playbook_updated | detection_added | etc.
    resource_type = db.Column(db.String(32))
    resource_id = db.Column(db.String(64))
    resource_name = db.Column(db.String(256))
    description = db.Column(db.Text)
    risk_level = db.Column(db.String(16), default="low")
    applied_by = db.Column(db.Integer, db.ForeignKey("users.id"))
    _before_state = db.Column("before_state", db.Text)
    _after_state = db.Column("after_state", db.Text)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    @property
    def before_state(self):
        return json.loads(self._before_state) if self._before_state else None

    @before_state.setter
    def before_state(self, value):
        self._before_state = json.dumps(value) if value else None

    @property
    def after_state(self):
        return json.loads(self._after_state) if self._after_state else None

    @after_state.setter
    def after_state(self, value):
        self._after_state = json.dumps(value) if value else None

    def to_dict(self):
        return {
            "id": self.id,
            "patch_id": self.patch_id,
            "change_type": self.change_type,
            "resource_name": self.resource_name,
            "description": self.description,
            "risk_level": self.risk_level,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
