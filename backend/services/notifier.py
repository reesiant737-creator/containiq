"""
Notification service — Slack webhooks + email (SMTP).
Fires on: new critical/high case, playbook approval needed, patch ready for review.
Degrades gracefully if no credentials are configured.
"""
import os, json, smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timezone

try:
    import requests as _requests
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False


SEV_EMOJI = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🟢",
}


class Notifier:
    def __init__(self, org=None):
        """
        org: Org model instance (optional). If provided, reads notification_config
        from the org first, then falls back to environment variables.
        """
        # Load org-level config if available
        org_cfg = {}
        if org and org.notification_config:
            try:
                org_cfg = json.loads(org.notification_config) if isinstance(org.notification_config, str) else org.notification_config
            except Exception:
                org_cfg = {}

        def _get(key, env_key, default=""):
            return org_cfg.get(key) or os.environ.get(env_key, default)

        self.slack_url    = _get("slack_url",    "SLACK_WEBHOOK_URL")
        self.teams_url    = _get("teams_url",    "TEAMS_WEBHOOK_URL")
        self.smtp_host    = _get("smtp_host",    "SMTP_HOST")
        self.smtp_port    = int(_get("smtp_port", "SMTP_PORT") or 587)
        self.smtp_user    = _get("smtp_user",    "SMTP_USER")
        self.smtp_pass    = _get("smtp_pass",    "SMTP_PASS")
        self.notify_email = _get("notify_email", "NOTIFY_EMAIL")
        self.base_url     = os.environ.get("BASE_URL", "http://localhost:5001")

    # ── Public API ────────────────────────────────────────────────────────────

    def new_case(self, case):
        emoji = SEV_EMOJI.get(case.severity, "⚪")
        title = f"{emoji} [{case.severity.upper()}] New Case #{case.id}: {case.title}"
        body  = (f"*Severity:* {case.severity}\n"
                 f"*Source:* {case.source or 'manual'}\n"
                 f"*Status:* {case.status}\n"
                 f"<{self.base_url}/cases/{case.id}|Open in ThreatCommand>")
        self._send_slack(title, body, color=self._sev_color(case.severity))
        self._send_email(title, f"{title}\n\n{body}\n\n{self.base_url}/cases/{case.id}")

    def status_change(self, case, old_status: str, new_status: str, user=None):
        emoji = SEV_EMOJI.get(case.severity, "⚪")
        who = user.display_name or user.email if user else "System"
        title = f"{emoji} Case #{case.id} → {new_status.upper()}: {case.title}"
        body  = (f"*Changed by:* {who}\n"
                 f"*Status:* {old_status} → {new_status}\n"
                 f"*Severity:* {case.severity}\n"
                 f"<{self.base_url}/cases/{case.id}|Open in ThreatCommand>")
        self._send_slack(title, body, color=self._sev_color(case.severity))
        self._send_teams(title, body)
        self._send_email(title, f"{title}\n\n{body.replace('<', '').replace('>', '')}")

    def sla_breach(self, case, hours_open: float):
        title = f"⏰ SLA Breach — Case #{case.id} open {hours_open:.0f}h: {case.title}"
        body  = (f"*Severity:* {case.severity}\n"
                 f"*Status:* {case.status}\n"
                 f"*Time open:* {hours_open:.1f} hours\n"
                 f"<{self.base_url}/cases/{case.id}|Investigate Now>")
        self._send_slack(title, body, color="#dc3545")
        self._send_teams(title, body)
        self._send_email(title, f"{title}\n\n{body.replace('<', '').replace('>', '')}")

    def approval_needed(self, run, approval):
        title = f"🔑 Approval Required — Playbook Step: {approval.step_name}"
        body  = (f"*Playbook:* {run.playbook.name}\n"
                 f"*Case:* #{run.case_id} — {run.case.title}\n"
                 f"*Step {approval.step_index + 1}:* {approval.step_name}\n"
                 f"<{self.base_url}/playbooks/runs/{run.id}|Review & Approve>")
        self._send_slack(title, body, color="#ffc107")
        self._send_email(title, f"{title}\n\n{body}")

    def patch_ready(self, patch):
        title = f"🩹 Security Patch Ready: {patch.version}"
        body  = (f"*Changes:* {len(patch.changes)} — "
                 f"{patch.new_playbooks} playbooks, {patch.new_detections} detections\n"
                 f"*Auto-apply:* {'Yes (all low-risk)' if patch.auto_applied else 'No — requires review'}\n"
                 f"<{self.base_url}/patches/{patch.id}|Review Patch>")
        self._send_slack(title, body, color="#198754")
        self._send_email(title, f"{title}\n\n{body}")

    def threat_intel_complete(self, update):
        if update.iocs_found == 0 and update.proposals_generated == 0:
            return  # Don't spam for empty runs
        title = f"🛰 Daily Threat Intel: {update.iocs_found} IOCs, {update.proposals_generated} proposals"
        body  = (f"*Date:* {update.run_date}\n"
                 f"*Sources checked:* {update.sources_checked}\n"
                 f"*Proposals queued for review:* {update.proposals_generated}\n"
                 f"<{self.base_url}/threats|Review Proposals>")
        self._send_slack(title, body, color="#0dcaf0")

    # ── Transport ─────────────────────────────────────────────────────────────

    def _send_slack(self, title: str, body: str, color: str = "#0d6efd"):
        if not self.slack_url or not _HAS_REQUESTS:
            return
        payload = {
            "attachments": [{
                "color": color,
                "title": title,
                "text": body,
                "footer": "ThreatCommand",
                "ts": int(datetime.now(timezone.utc).timestamp()),
            }]
        }
        try:
            _requests.post(self.slack_url, json=payload, timeout=5)
        except Exception as e:
            import sys
            print(f"[NOTIFY] Slack failed: {e}", file=sys.stderr)

    def _send_teams(self, title: str, body: str):
        if not self.teams_url or not _HAS_REQUESTS:
            return
        payload = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "summary": title,
            "themeColor": "0078D7",
            "title": title,
            "text": body,
        }
        try:
            _requests.post(self.teams_url, json=payload, timeout=5)
        except Exception as e:
            import sys
            print(f"[NOTIFY] Teams failed: {e}", file=sys.stderr)

    def _send_email(self, subject: str, body: str):
        if not all([self.smtp_host, self.smtp_user, self.smtp_pass, self.notify_email]):
            return
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"[ThreatCommand] {subject}"
            msg["From"]    = self.smtp_user
            msg["To"]      = self.notify_email
            msg.attach(MIMEText(body, "plain"))
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                server.starttls()
                server.login(self.smtp_user, self.smtp_pass)
                server.sendmail(self.smtp_user, self.notify_email, msg.as_string())
        except Exception as e:
            import sys
            print(f"[NOTIFY] Email failed: {e}", file=sys.stderr)

    @staticmethod
    def _sev_color(severity: str) -> str:
        return {"critical": "#7c0a02", "high": "#dc3545",
                "medium": "#ffc107", "low": "#198754"}.get(severity, "#6c757d")
