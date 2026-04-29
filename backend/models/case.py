from datetime import datetime, timezone
from ..app import db
import json

SEVERITY = ("critical", "high", "medium", "low", "informational")
STATUS = ("open", "investigating", "contained", "closed", "false_positive")
ENTITY_TYPES = ("user", "device", "ip", "domain", "cloud_resource", "saas_app", "file", "hash")


class Case(db.Model):
    __tablename__ = "cases"

    id = db.Column(db.Integer, primary_key=True)
    org_id = db.Column(db.Integer, db.ForeignKey("orgs.id"), nullable=False)
    title = db.Column(db.String(256), nullable=False)
    description = db.Column(db.Text)
    severity = db.Column(db.String(32), default="medium")
    status = db.Column(db.String(32), default="open")
    source = db.Column(db.String(64))           # e.g. "manual", "alert", "threat_feed"
    source_ref = db.Column(db.String(128))      # external alert ID
    assigned_to = db.Column(db.Integer, db.ForeignKey("users.id"))
    created_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc),
                           onupdate=lambda: datetime.now(timezone.utc))
    closed_at = db.Column(db.DateTime)
    _entity_summary = db.Column("entity_summary", db.Text, default="{}")

    org = db.relationship("Org", back_populates="cases")
    entities = db.relationship("Entity", back_populates="case", cascade="all, delete-orphan")
    timeline = db.relationship("TimelineEvent", back_populates="case",
                               order_by="TimelineEvent.event_time", cascade="all, delete-orphan")
    evidence = db.relationship("Evidence", back_populates="case", cascade="all, delete-orphan")
    playbook_runs = db.relationship("PlaybookRun", back_populates="case")
    creator = db.relationship("User", foreign_keys=[created_by])
    assignee = db.relationship("User", foreign_keys=[assigned_to])

    @property
    def entity_summary(self):
        return json.loads(self._entity_summary or "{}")

    @entity_summary.setter
    def entity_summary(self, value):
        self._entity_summary = json.dumps(value)

    def to_dict(self, include_relations=False):
        d = {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "status": self.status,
            "source": self.source,
            "created_by": self.created_by,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "entity_summary": self.entity_summary,
        }
        if include_relations:
            d["entities"] = [e.to_dict() for e in self.entities]
            d["timeline"] = [t.to_dict() for t in self.timeline]
            d["evidence"] = [e.to_dict() for e in self.evidence]
        return d


class Entity(db.Model):
    __tablename__ = "entities"

    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey("cases.id"), nullable=False)
    entity_type = db.Column(db.String(32), nullable=False)
    value = db.Column(db.String(512), nullable=False)
    _context = db.Column("context", db.Text, default="{}")
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    case = db.relationship("Case", back_populates="entities")

    @property
    def context(self):
        return json.loads(self._context or "{}")

    @context.setter
    def context(self, value):
        self._context = json.dumps(value)

    def to_dict(self):
        return {
            "id": self.id,
            "type": self.entity_type,
            "value": self.value,
            "context": self.context,
        }


class TimelineEvent(db.Model):
    __tablename__ = "timeline_events"

    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey("cases.id"), nullable=False)
    event_time = db.Column(db.DateTime, nullable=False)
    event_type = db.Column(db.String(64))       # e.g. "login", "file_access", "alert_fired"
    description = db.Column(db.Text, nullable=False)
    source = db.Column(db.String(128))          # e.g. "Splunk", "Sentinel", "manual"
    _evidence_refs = db.Column("evidence_refs", db.Text, default="[]")
    created_by = db.Column(db.Integer, db.ForeignKey("users.id"))
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    case = db.relationship("Case", back_populates="timeline")

    @property
    def evidence_refs(self):
        return json.loads(self._evidence_refs or "[]")

    @evidence_refs.setter
    def evidence_refs(self, value):
        self._evidence_refs = json.dumps(value)

    def to_dict(self):
        return {
            "id": self.id,
            "event_time": self.event_time.isoformat(),
            "event_type": self.event_type,
            "description": self.description,
            "source": self.source,
            "evidence_refs": self.evidence_refs,
        }


class Evidence(db.Model):
    __tablename__ = "evidence"

    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey("cases.id"), nullable=False)
    name = db.Column(db.String(256), nullable=False)
    evidence_type = db.Column(db.String(32))    # log, screenshot, file, url, ioc
    content = db.Column(db.Text)               # inline text content
    file_path = db.Column(db.String(512))      # for uploaded files
    content_hash = db.Column(db.String(64))    # SHA-256 integrity
    created_by = db.Column(db.Integer, db.ForeignKey("users.id"))
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    case = db.relationship("Case", back_populates="evidence")

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "type": self.evidence_type,
            "content": self.content,
            "hash": self.content_hash,
            "created_at": self.created_at.isoformat(),
        }
