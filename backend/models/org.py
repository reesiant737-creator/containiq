from datetime import datetime, timezone
from ..app import db


class Org(db.Model):
    __tablename__ = "orgs"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False)
    slug = db.Column(db.String(64), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    users = db.relationship("User", back_populates="org", lazy="dynamic")
    cases = db.relationship("Case", back_populates="org", lazy="dynamic")
    playbooks = db.relationship("Playbook", back_populates="org", lazy="dynamic")

    def to_dict(self):
        return {"id": self.id, "name": self.name, "slug": self.slug}
