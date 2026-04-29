from datetime import datetime, timezone
from ..app import db
import json

RUN_STATUS = ("pending_approval", "running", "completed", "failed", "rolled_back", "dry_run_complete")
APPROVAL_STATUS = ("pending", "approved", "rejected")


class Playbook(db.Model):
    __tablename__ = "playbooks"

    id = db.Column(db.Integer, primary_key=True)
    org_id = db.Column(db.Integer, db.ForeignKey("orgs.id"), nullable=False)
    name = db.Column(db.String(256), nullable=False)
    description = db.Column(db.Text)
    pack = db.Column(db.String(32))             # pack_a, pack_b, pack_c
    version = db.Column(db.String(16), default="1.0")
    _content = db.Column("content", db.Text, default="{}")
    status = db.Column(db.String(32), default="active")  # draft, active, archived
    created_by = db.Column(db.Integer, db.ForeignKey("users.id"))
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc),
                           onupdate=lambda: datetime.now(timezone.utc))

    org = db.relationship("Org", back_populates="playbooks")
    runs = db.relationship("PlaybookRun", back_populates="playbook")

    @property
    def content(self):
        return json.loads(self._content or "{}")

    @content.setter
    def content(self, value):
        self._content = json.dumps(value)

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "pack": self.pack,
            "version": self.version,
            "status": self.status,
            "content": self.content,
        }


class PlaybookRun(db.Model):
    __tablename__ = "playbook_runs"

    id = db.Column(db.Integer, primary_key=True)
    org_id = db.Column(db.Integer, db.ForeignKey("orgs.id"), nullable=False)
    case_id = db.Column(db.Integer, db.ForeignKey("cases.id"), nullable=False)
    playbook_id = db.Column(db.Integer, db.ForeignKey("playbooks.id"), nullable=False)
    started_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    mode = db.Column(db.String(16), default="dry_run")   # dry_run | live
    status = db.Column(db.String(32), default="pending_approval")
    current_step = db.Column(db.Integer, default=0)
    _steps_log = db.Column("steps_log", db.Text, default="[]")
    _approvals = db.Column("approvals", db.Text, default="{}")
    _blast_radius_config = db.Column("blast_radius_config", db.Text, default="{}")
    started_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    completed_at = db.Column(db.DateTime)

    case = db.relationship("Case", back_populates="playbook_runs")
    playbook = db.relationship("Playbook", back_populates="runs")
    approval_requests = db.relationship("PlaybookApproval", back_populates="run",
                                        cascade="all, delete-orphan")
    starter = db.relationship("User", foreign_keys=[started_by])

    @property
    def steps_log(self):
        return json.loads(self._steps_log or "[]")

    @steps_log.setter
    def steps_log(self, value):
        self._steps_log = json.dumps(value)

    @property
    def blast_radius_config(self):
        return json.loads(self._blast_radius_config or "{}")

    @blast_radius_config.setter
    def blast_radius_config(self, value):
        self._blast_radius_config = json.dumps(value)

    def to_dict(self):
        return {
            "id": self.id,
            "case_id": self.case_id,
            "playbook_id": self.playbook_id,
            "mode": self.mode,
            "status": self.status,
            "current_step": self.current_step,
            "steps_log": self.steps_log,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }


class PlaybookApproval(db.Model):
    __tablename__ = "playbook_approvals"

    id = db.Column(db.Integer, primary_key=True)
    run_id = db.Column(db.Integer, db.ForeignKey("playbook_runs.id"), nullable=False)
    step_index = db.Column(db.Integer, nullable=False)
    step_name = db.Column(db.String(256))
    requested_by = db.Column(db.Integer, db.ForeignKey("users.id"))
    approved_by = db.Column(db.Integer, db.ForeignKey("users.id"))
    status = db.Column(db.String(32), default="pending")
    reason = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    decided_at = db.Column(db.DateTime)

    run = db.relationship("PlaybookRun", back_populates="approval_requests")
    requester = db.relationship("User", foreign_keys=[requested_by])
    approver = db.relationship("User", foreign_keys=[approved_by])

    def to_dict(self):
        return {
            "id": self.id,
            "run_id": self.run_id,
            "step_index": self.step_index,
            "step_name": self.step_name,
            "status": self.status,
            "reason": self.reason,
            "created_at": self.created_at.isoformat(),
            "decided_at": self.decided_at.isoformat() if self.decided_at else None,
        }
