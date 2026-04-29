"""
Daily threat intelligence pipeline.
Pulls from open threat feeds, synthesizes with Claude, and queues proposals.
Covers: traditional threats + AI-specific threats (prompt injection, model theft,
adversarial ML, AI-assisted phishing/deepfake, LLM-powered recon/exploit).
"""
import requests
from datetime import datetime, date, timezone
from flask import current_app
from apscheduler.schedulers.background import BackgroundScheduler
from ..app import db
from ..models.threat import ThreatUpdate, ThreatProposal
from ..models.playbook import Playbook

# ── Open threat feed endpoints ──────────────────────────────────────────────

FEEDS = {
    "urlhaus": "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/25/",
    "feodo": "https://feodotracker.abuse.ch/downloads/ipblocklist_aggressive.json",
    "otx_pulses": None,    # AlienVault OTX — requires API key
    "cisa_kev": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
}

# AI-specific threat categories to track every run
AI_THREAT_CATEGORIES = [
    "Prompt injection / jailbreaking against enterprise AI",
    "LLM-assisted spear phishing / BEC",
    "Deepfake voice/video for executive impersonation",
    "Model inversion / training data extraction",
    "AI-powered credential stuffing and CAPTCHA bypass",
    "Adversarial ML evasion of security model detections",
    "Indirect prompt injection via poisoned web content",
    "AI-generated malware / polymorphic code",
    "Shadow AI / unauthorized LLM usage inside org",
    "Data exfiltration via AI tool integrations (copilots, assistants)",
]


class ThreatIntelService:
    def __init__(self, org_id: int):
        self.org_id = org_id

    def run(self) -> ThreatUpdate:
        update = ThreatUpdate(
            org_id=self.org_id,
            run_date=date.today(),
        )
        db.session.add(update)
        db.session.flush()

        ioc_data = self._pull_feeds()
        ai_threat_context = self._build_ai_threat_context()
        combined_summary = self._build_summary(ioc_data, ai_threat_context)

        update.sources_checked = len([v for v in ioc_data.values() if v])
        update.iocs_found = sum(len(v) for v in ioc_data.values() if isinstance(v, list))

        # Use Claude to generate proposals from today's intel
        try:
            from .ai_analyst import AIAnalyst
            analyst = AIAnalyst()
            playbooks = Playbook.query.filter_by(org_id=self.org_id, status="active").all()
            proposals_data = analyst.generate_threat_proposals(combined_summary, playbooks)
            count = self._save_proposals(update, proposals_data)
            update.proposals_generated = count
        except Exception as e:
            import sys
            print(f"[THREAT INTEL] AI proposal generation failed: {e}", file=sys.stderr)

        update.summary = {
            "ioc_breakdown": {k: len(v) if isinstance(v, list) else 0
                              for k, v in ioc_data.items()},
            "ai_threats_reviewed": len(AI_THREAT_CATEGORIES),
            "combined_summary": combined_summary[:2000],
        }
        db.session.commit()

        try:
            from .notifier import Notifier
            Notifier().threat_intel_complete(update)
        except Exception:
            pass

        return update

    def _pull_feeds(self) -> dict:
        results = {}

        # URLhaus — recent malicious URLs
        try:
            r = requests.post(FEEDS["urlhaus"], timeout=10)
            if r.ok:
                data = r.json()
                results["urlhaus_urls"] = [
                    {"url": u.get("url"), "threat": u.get("threat"), "tags": u.get("tags")}
                    for u in data.get("urls", [])[:20]
                ]
        except Exception:
            results["urlhaus_urls"] = []

        # CISA KEV — known exploited vulnerabilities (always current, no key needed)
        try:
            r = requests.get(FEEDS["cisa_kev"], timeout=15)
            if r.ok:
                kev = r.json()
                vulns = kev.get("vulnerabilities", [])
                # Last 5 added
                recent = sorted(vulns, key=lambda x: x.get("dateAdded", ""), reverse=True)[:5]
                results["cisa_kev"] = [
                    {"cve": v.get("cveID"), "product": v.get("product"),
                     "vendor": v.get("vendorProject"), "description": v.get("shortDescription"),
                     "due": v.get("dueDate")}
                    for v in recent
                ]
        except Exception:
            results["cisa_kev"] = []

        # AlienVault OTX — if key is set
        otx_key = current_app.config.get("OTX_API_KEY", "")
        if otx_key:
            try:
                r = requests.get(
                    "https://otx.alienvault.com/api/v1/pulses/subscribed?limit=10",
                    headers={"X-OTX-API-KEY": otx_key},
                    timeout=15,
                )
                if r.ok:
                    pulses = r.json().get("results", [])
                    results["otx_pulses"] = [
                        {"name": p.get("name"), "tags": p.get("tags"),
                         "ioc_count": p.get("indicator_count")}
                        for p in pulses
                    ]
            except Exception:
                results["otx_pulses"] = []

        return results

    def _build_ai_threat_context(self) -> str:
        lines = ["=== AI-Specific Threat Categories (checked this run) ==="]
        for cat in AI_THREAT_CATEGORIES:
            lines.append(f"• {cat}")
        return "\n".join(lines)

    def _build_summary(self, ioc_data: dict, ai_context: str) -> str:
        parts = [f"Threat Intel Run — {date.today().isoformat()}", ""]

        cisa = ioc_data.get("cisa_kev", [])
        if cisa:
            parts.append("CISA Known Exploited Vulnerabilities (recent additions):")
            for v in cisa:
                parts.append(f"  {v['cve']} — {v['vendor']} {v['product']}: {v['description']} (due: {v['due']})")
            parts.append("")

        urlhaus = ioc_data.get("urlhaus_urls", [])
        if urlhaus:
            parts.append(f"URLhaus: {len(urlhaus)} recent malicious URLs detected")
            for u in urlhaus[:5]:
                parts.append(f"  [{u['threat']}] {u['url']}")
            parts.append("")

        otx = ioc_data.get("otx_pulses", [])
        if otx:
            parts.append(f"AlienVault OTX: {len(otx)} active threat pulses")
            for p in otx[:5]:
                parts.append(f"  {p['name']} ({p['ioc_count']} IOCs)")
            parts.append("")

        parts.append(ai_context)
        return "\n".join(parts)

    def _save_proposals(self, update: ThreatUpdate, data: dict) -> int:
        count = 0
        if isinstance(data, dict):
            for det in data.get("new_detections", []):
                p = ThreatProposal(
                    update_id=update.id,
                    org_id=self.org_id,
                    proposal_type="detection",
                    title=det.get("title", "New Detection"),
                    rationale=det.get("rationale", ""),
                )
                p.content = det
                db.session.add(p)
                count += 1

            for upd in data.get("playbook_updates", []):
                p = ThreatProposal(
                    update_id=update.id,
                    org_id=self.org_id,
                    proposal_type="playbook",
                    title=f"Update: {upd.get('target_playbook_name', 'playbook')}",
                    rationale=upd.get("change_description", ""),
                )
                p.content = upd
                db.session.add(p)
                count += 1

            for req in data.get("new_evidence_requirements", []):
                p = ThreatProposal(
                    update_id=update.id,
                    org_id=self.org_id,
                    proposal_type="evidence_req",
                    title=req.get("title", "New Evidence Requirement"),
                    rationale=req.get("description", ""),
                )
                p.content = req
                db.session.add(p)
                count += 1

        return count


_scheduler: BackgroundScheduler = None


def start_scheduler(app):
    global _scheduler
    if _scheduler and _scheduler.running:
        return

    _scheduler = BackgroundScheduler(timezone="UTC")
    hour = app.config.get("THREAT_FEED_HOUR", 6)

    # ── Daily: pull threat feeds, generate proposals ────────────────────
    def _daily_intel_job():
        with app.app_context():
            from ..models.org import Org
            for org in Org.query.all():
                try:
                    svc = ThreatIntelService(org.id)
                    svc.run()
                    print(f"[THREAT INTEL] Daily run complete for org {org.id}")
                except Exception as e:
                    import sys
                    print(f"[THREAT INTEL] Failed for org {org.id}: {e}", file=sys.stderr)

    # ── Weekly (Sunday 03:00 UTC): generate patch release from approved proposals ──
    def _weekly_patch_job():
        with app.app_context():
            from ..models.org import Org
            from .patch_manager import PatchManager
            for org in Org.query.all():
                try:
                    mgr = PatchManager(org.id)
                    patch = mgr.generate_weekly_patch()
                    status = "auto-applied" if patch.auto_applied else "ready for review"
                    print(f"[PATCH] Weekly patch {patch.version} generated for org {org.id} — {status}")
                except Exception as e:
                    import sys
                    print(f"[PATCH] Failed for org {org.id}: {e}", file=sys.stderr)

    _scheduler.add_job(_daily_intel_job, "cron", hour=hour, minute=0, id="daily_threat_intel")
    _scheduler.add_job(_weekly_patch_job, "cron", day_of_week="sun", hour=3, minute=0,
                       id="weekly_security_patch")
    _scheduler.start()
    print(f"[THREAT INTEL] Scheduler started — daily @ {hour:02d}:00 UTC, weekly patch @ Sun 03:00 UTC")
