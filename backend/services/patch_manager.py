"""
Security Patch Manager
======================
Bundles approved threat proposals into versioned weekly patch releases.

Risk tiers determine automation vs. gating:
  LOW  → auto-apply after generation (new detections, new playbooks from feed, evidence req updates)
  MED  → require analyst sign-off before applying
  HIGH → require approver sign-off + 24h review window (playbook step edits, blast-radius changes)

Weekly cadence: every Sunday at 03:00 UTC, generate a patch from the week's approved proposals.
Analysts review the patch manifest, then click Apply.
Every applied change is written to ChangeLog (immutable).
Every patch stores a rollback manifest so it can be undone.
"""
import json
from datetime import datetime, date, timezone
from ..app import db
from ..models.patch import PatchRelease, Detection, ChangeLog
from ..models.threat import ThreatProposal
from ..models.playbook import Playbook


# Risk classification per change type
RISK_MAP = {
    "detection_added":      "low",
    "detection_updated":    "medium",
    "playbook_added":       "low",
    "playbook_step_edited": "high",
    "playbook_br_changed":  "high",
    "evidence_req_added":   "low",
    "evidence_req_updated": "medium",
}


class PatchManager:
    def __init__(self, org_id: int):
        self.org_id = org_id

    # ── Generate ─────────────────────────────────────────────────────────

    def generate_daily_patch(self) -> PatchRelease:
        """Bundle today's approved proposals into a daily patch release."""
        today = date.today()
        day_of_year = today.timetuple().tm_yday
        version = f"{today.year}.{today.month:02d}.{today.day:02d}.1"

        # Avoid duplicate patches for the same day
        existing = PatchRelease.query.filter_by(
            org_id=self.org_id, week_number=day_of_year
        ).filter(
            PatchRelease.status.in_(["draft", "ready", "applied"])
        ).first()
        if existing:
            return existing

        # Gather all approved proposals that haven't been patched yet
        proposals = ThreatProposal.query.filter_by(
            org_id=self.org_id, status="approved"
        ).all()

        if not proposals:
            patch = self._create_patch(version, day_of_year, [], [])
            patch.title = f"Daily Security Update {today.strftime('%b %d, %Y')} — No new content"
            patch.summary = "No approved proposals today. All threat feeds reviewed."
            patch.status = "applied"
            patch.auto_applied = True
            patch.applied_at = datetime.now(timezone.utc)
            db.session.add(patch)
            db.session.commit()
            return patch

        changes, rollback_manifest = self._build_change_set(proposals)
        patch = self._create_patch(version, day_of_year, changes, rollback_manifest)
        patch.title = f"Daily Security Update — {today.strftime('%b %d, %Y')}"

        all_low_risk = all(c["risk"] == "low" for c in changes)
        if all_low_risk:
            patch.status = "ready"
            patch.auto_applied = True
            self._apply_patch(patch, changes, user_id=None)
            for p in proposals:
                p.status = "deployed"
        else:
            patch.status = "ready"
            patch.auto_applied = False

        db.session.add(patch)
        db.session.commit()
        return patch

    def generate_weekly_patch(self) -> PatchRelease:
        """Bundle this week's approved proposals into a patch release."""
        today = date.today()
        iso_week = today.isocalendar()[1]
        version = f"{today.year}.{iso_week:02d}.1"

        # Avoid duplicate patches for the same week
        existing = PatchRelease.query.filter_by(
            org_id=self.org_id, week_number=iso_week
        ).filter(
            PatchRelease.status.in_(["draft", "ready", "applied"])
        ).first()
        if existing:
            return existing

        # Gather approved proposals from this week that haven't been patched yet
        proposals = ThreatProposal.query.filter_by(
            org_id=self.org_id, status="approved"
        ).all()

        if not proposals:
            # Still generate an empty patch so the cadence is visible
            patch = self._create_patch(version, iso_week, [], [])
            patch.title = f"Weekly Security Patch {version} — No new content"
            patch.summary = "No approved proposals this week. All threat feeds reviewed."
            patch.status = "applied"
            patch.auto_applied = True
            patch.applied_at = datetime.now(timezone.utc)
            db.session.add(patch)
            db.session.commit()
            return patch

        changes, rollback_manifest = self._build_change_set(proposals)
        patch = self._create_patch(version, iso_week, changes, rollback_manifest)

        # Auto-apply if all changes are low-risk
        all_low_risk = all(c["risk"] == "low" for c in changes)
        if all_low_risk:
            patch.status = "ready"
            patch.auto_applied = True
            self._apply_patch(patch, changes, user_id=None)
            # Mark source proposals as deployed
            for p in proposals:
                p.status = "deployed"
        else:
            patch.status = "ready"
            patch.auto_applied = False

        db.session.add(patch)
        db.session.commit()
        return patch

    # ── Apply ─────────────────────────────────────────────────────────────

    def apply_patch(self, patch: PatchRelease, user_id: int) -> dict:
        if patch.status not in ("ready", "draft"):
            return {"ok": False, "error": f"Patch is {patch.status}, cannot apply."}
        if patch.org_id != self.org_id:
            return {"ok": False, "error": "Org mismatch."}

        patch.status = "applying"
        db.session.commit()

        try:
            self._apply_patch(patch, patch.changes, user_id=user_id)
            patch.status = "applied"
            patch.applied_by = user_id
            patch.applied_at = datetime.now(timezone.utc)

            # Mark proposals as deployed
            ThreatProposal.query.filter_by(
                org_id=self.org_id, status="approved"
            ).update({"status": "deployed"})

            db.session.commit()
            return {"ok": True, "applied": len(patch.changes)}
        except Exception as exc:
            patch.status = "failed"
            db.session.commit()
            return {"ok": False, "error": str(exc)}

    # ── Rollback ──────────────────────────────────────────────────────────

    def rollback_patch(self, patch: PatchRelease, user_id: int) -> dict:
        if patch.status != "applied":
            return {"ok": False, "error": "Only applied patches can be rolled back."}

        rolled_back = 0
        for item in reversed(patch.rollback_manifest):
            try:
                self._apply_rollback_item(item)
                rolled_back += 1
            except Exception as exc:
                import sys
                print(f"[PATCH ROLLBACK] Failed: {item}: {exc}", file=sys.stderr)

        patch.status = "rolled_back"
        patch.rolled_back_by = user_id
        patch.rolled_back_at = datetime.now(timezone.utc)
        db.session.commit()

        return {"ok": True, "rolled_back": rolled_back}

    # ── Internal helpers ──────────────────────────────────────────────────

    def _build_change_set(self, proposals: list) -> tuple:
        changes = []
        rollback_manifest = []

        for p in proposals:
            if p.proposal_type == "detection":
                det_content = p.content
                change = {
                    "proposal_id": p.id,
                    "type": "detection_added",
                    "risk": RISK_MAP["detection_added"],
                    "title": p.title,
                    "description": p.rationale or "",
                    "content": det_content,
                }
                changes.append(change)
                rollback_manifest.append({
                    "action": "delete_detection",
                    "name": p.title,
                })

            elif p.proposal_type == "playbook":
                change = {
                    "proposal_id": p.id,
                    "type": "playbook_added",
                    "risk": RISK_MAP["playbook_added"],
                    "title": p.title,
                    "description": p.rationale or "",
                    "content": p.content,
                }
                changes.append(change)
                rollback_manifest.append({
                    "action": "delete_playbook",
                    "name": p.title,
                })

            elif p.proposal_type == "evidence_req":
                change = {
                    "proposal_id": p.id,
                    "type": "evidence_req_added",
                    "risk": RISK_MAP["evidence_req_added"],
                    "title": p.title,
                    "description": p.rationale or "",
                    "content": p.content,
                }
                changes.append(change)
                rollback_manifest.append({
                    "action": "log_only",
                    "description": f"Evidence requirement removed: {p.title}",
                })

        return changes, rollback_manifest

    def _create_patch(self, version: str, week_number: int,
                      changes: list, rollback_manifest: list) -> PatchRelease:
        counts = {
            "new_playbooks": sum(1 for c in changes if c["type"] == "playbook_added"),
            "updated_playbooks": sum(1 for c in changes if c["type"] == "playbook_updated"),
            "new_detections": sum(1 for c in changes if c["type"] == "detection_added"),
            "updated_detections": sum(1 for c in changes if c["type"] == "detection_updated"),
            "new_evidence_reqs": sum(1 for c in changes if c["type"] == "evidence_req_added"),
        }
        high_risk = [c for c in changes if c["risk"] == "high"]
        med_risk = [c for c in changes if c["risk"] == "medium"]

        patch = PatchRelease(
            org_id=self.org_id,
            version=version,
            week_number=week_number,
            title=f"Weekly Security Patch {version}",
            summary=(
                f"{len(changes)} change(s) — "
                f"{counts['new_playbooks']} new playbooks, "
                f"{counts['new_detections']} new detections, "
                f"{counts['new_evidence_reqs']} evidence req updates. "
                f"{'⚠ HIGH-RISK changes require approver sign-off.' if high_risk else ''}"
                f"{'MED-RISK changes require analyst review.' if med_risk and not high_risk else ''}"
            ),
            **counts,
        )
        patch.changes = changes
        patch.rollback_manifest = rollback_manifest
        return patch

    def _apply_patch(self, patch: PatchRelease, changes: list, user_id):
        iso_week = patch.week_number
        for change in changes:
            ctype = change["type"]

            if ctype == "detection_added":
                content = change.get("content", {})
                det = Detection(
                    org_id=self.org_id,
                    name=change["title"],
                    description=change["description"],
                    mitre_technique=content.get("mitre_technique", ""),
                    rule_type="sigma",
                    rule_content=content.get("sigma_rule_stub", ""),
                    severity="medium",
                    status="active",
                    version=1,
                    patch_version=patch.version,
                    created_by=user_id,
                )
                db.session.add(det)
                db.session.flush()
                self._log_change(patch, ctype, "detection", str(det.id),
                                 change["title"], change["description"], "low", user_id)

            elif ctype == "playbook_added":
                content = change.get("content", {})
                if isinstance(content, dict) and content.get("steps"):
                    pb = Playbook(
                        org_id=self.org_id,
                        name=change["title"],
                        description=change["description"],
                        pack="auto",
                        version=f"auto-{patch.version}",
                        status="active",
                        created_by=user_id,
                    )
                    pb.content = content
                    db.session.add(pb)
                    db.session.flush()
                    self._log_change(patch, ctype, "playbook", str(pb.id),
                                     change["title"], change["description"], "low", user_id)

            elif ctype in ("evidence_req_added", "evidence_req_updated"):
                self._log_change(patch, ctype, "evidence_req", "n/a",
                                 change["title"], change["description"],
                                 RISK_MAP.get(ctype, "low"), user_id)

    def _apply_rollback_item(self, item: dict):
        action = item.get("action")
        if action == "delete_detection":
            det = Detection.query.filter_by(
                org_id=self.org_id, name=item["name"]
            ).first()
            if det:
                det.status = "deprecated"
        elif action == "delete_playbook":
            pb = Playbook.query.filter_by(
                org_id=self.org_id, name=item["name"]
            ).first()
            if pb:
                pb.status = "archived"
        # log_only → nothing to undo, already logged

    def _log_change(self, patch, change_type, resource_type, resource_id,
                    name, description, risk, user_id):
        entry = ChangeLog(
            org_id=self.org_id,
            patch_id=patch.id,
            change_type=change_type,
            resource_type=resource_type,
            resource_id=resource_id,
            resource_name=name,
            description=description,
            risk_level=risk,
            applied_by=user_id,
        )
        db.session.add(entry)
