"""
Playbook execution engine.
Supports: dry-run preview, approval gates, blast-radius limits, rollback, verification.
"""
from datetime import datetime, timezone
from ..models.playbook import PlaybookRun, PlaybookApproval
from ..app import db


class PlaybookRunner:
    def __init__(self, playbook, case, user, mode: str = "dry_run"):
        self.playbook = playbook
        self.case = case
        self.user = user
        self.mode = mode

    @classmethod
    def from_run(cls, run: PlaybookRun, user):
        instance = cls.__new__(cls)
        instance.run = run
        instance.playbook = run.playbook
        instance.case = run.case
        instance.user = user
        instance.mode = run.mode
        return instance

    def initialize_run(self) -> PlaybookRun:
        content = self.playbook.content
        steps = content.get("steps", [])

        run = PlaybookRun(
            org_id=self.user.org_id,
            case_id=self.case.id,
            playbook_id=self.playbook.id,
            started_by=self.user.id,
            mode=self.mode,
            status="pending_approval" if self._first_step_needs_approval(steps) else "running",
            current_step=0,
        )

        # Generate dry-run preview for all steps
        preview = self._generate_preview(steps)
        run.steps_log = preview

        # Check blast-radius constraints
        br = content.get("blast_radius_limits", {})
        run.blast_radius_config = br

        if run.status == "pending_approval":
            self.run = run
            db.session.add(run)
            db.session.flush()
            self._request_approval(run, 0, steps[0])
        else:
            self.run = run

        return run

    def advance(self) -> dict:
        run = self.run
        content = self.playbook.content
        steps = content.get("steps", [])
        step_idx = run.current_step

        if step_idx >= len(steps):
            run.status = "completed"
            run.completed_at = datetime.now(timezone.utc)
            return {"status": "completed", "message": "All steps complete."}

        step = steps[step_idx]
        log = run.steps_log

        if run.mode == "dry_run":
            entry = {
                "step": step_idx,
                "name": step["name"],
                "status": "dry_run_simulated",
                "preview": step.get("dry_run_preview", "Action would be executed here."),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        else:
            # Check approval gate
            if step.get("requires_approval"):
                pending = PlaybookApproval.query.filter_by(
                    run_id=run.id, step_index=step_idx, status="pending"
                ).first()
                if pending:
                    return {"status": "pending_approval", "step": step_idx,
                            "message": f"Waiting for approval on: {step['name']}"}

                approved = PlaybookApproval.query.filter_by(
                    run_id=run.id, step_index=step_idx, status="approved"
                ).first()
                if not approved:
                    self._request_approval(run, step_idx, step)
                    run.status = "pending_approval"
                    return {"status": "pending_approval", "step": step_idx,
                            "message": f"Approval requested for: {step['name']}"}

            # Check blast radius
            br_check = self._check_blast_radius(step, run)
            if not br_check["ok"]:
                return {"status": "blast_radius_exceeded",
                        "message": br_check["reason"], "step": step_idx}

            # Execute (simulation — real integrations hook in here)
            entry = {
                "step": step_idx,
                "name": step["name"],
                "status": "executed",
                "action_type": step.get("action_type", "manual"),
                "result": self._execute_step(step),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

            # Run verification check
            if step.get("verification"):
                entry["verification"] = self._run_verification(step["verification"])

        log.append(entry)
        run.steps_log = log
        run.current_step = step_idx + 1

        next_idx = step_idx + 1
        if next_idx < len(steps) and run.mode == "live":
            next_step = steps[next_idx]
            if next_step.get("requires_approval"):
                self._request_approval(run, next_idx, next_step)
                run.status = "pending_approval"
            else:
                run.status = "running"
        elif next_idx >= len(steps):
            if run.mode == "dry_run":
                run.status = "dry_run_complete"
            else:
                run.status = "completed"
            run.completed_at = datetime.now(timezone.utc)

        return {"status": run.status, "step": step_idx, "log_entry": entry}

    def rollback(self) -> dict:
        run = self.run
        content = self.playbook.content
        steps = content.get("steps", [])
        log = run.steps_log
        rollback_log = []

        # Reverse through executed steps
        executed = [e for e in log if e.get("status") == "executed"]
        for entry in reversed(executed):
            step_idx = entry["step"]
            step = steps[step_idx]
            rollback_action = step.get("rollback", {})
            rb_entry = {
                "step": step_idx,
                "name": f"ROLLBACK: {step['name']}",
                "rollback_action": rollback_action,
                "status": "rolled_back",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            rollback_log.append(rb_entry)

        log.extend(rollback_log)
        run.steps_log = log
        run.status = "rolled_back"
        run.completed_at = datetime.now(timezone.utc)
        return {"status": "rolled_back", "steps_reversed": len(rollback_log)}

    def _first_step_needs_approval(self, steps: list) -> bool:
        return bool(steps and steps[0].get("requires_approval"))

    def _generate_preview(self, steps: list) -> list:
        return [
            {
                "step": i,
                "name": s["name"],
                "status": "previewed",
                "preview": s.get("dry_run_preview", "No preview available."),
                "requires_approval": s.get("requires_approval", False),
                "approval_tier": s.get("approval_tier", "analyst"),
                "blast_radius": s.get("blast_radius", {}),
                "rollback_available": bool(s.get("rollback")),
                "safety_constraints": s.get("safety_constraints", []),
            }
            for i, s in enumerate(steps)
        ]

    def _request_approval(self, run: PlaybookRun, step_idx: int, step: dict):
        existing = PlaybookApproval.query.filter_by(
            run_id=run.id, step_index=step_idx
        ).first()
        if existing:
            return

        approval = PlaybookApproval(
            run_id=run.id,
            step_index=step_idx,
            step_name=step["name"],
            requested_by=self.user.id,
            status="pending",
        )
        db.session.add(approval)
        db.session.flush()

        try:
            from .notifier import Notifier
            Notifier().approval_needed(run, approval)
        except Exception:
            pass

    def _check_blast_radius(self, step: dict, run: PlaybookRun) -> dict:
        limit = run.blast_radius_config.get("max_affected")
        step_radius = step.get("blast_radius", {})
        max_affected = step_radius.get("max_affected", 1)
        if limit and max_affected > limit:
            return {"ok": False, "reason": f"Step affects up to {max_affected} entities — exceeds run limit of {limit}"}
        return {"ok": True}

    def _execute_step(self, step: dict) -> dict:
        action_type = step.get("action_type", "manual")
        if action_type == "manual":
            return {"result": "manual_action_required", "instructions": step.get("description")}
        # Future: dispatch to integration adapters (MS Graph, Okta, AWS, etc.)
        return {"result": "simulated_ok", "action_type": action_type}

    def _run_verification(self, verification: dict) -> dict:
        # Future: real check via integration adapters
        return {
            "check": verification.get("check"),
            "expected": verification.get("expected"),
            "result": "verification_requires_manual_confirmation",
        }
