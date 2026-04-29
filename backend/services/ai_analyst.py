"""
Claude-powered AI analyst with prompt caching for cost efficiency.
All calls use the system prompt cache anchor so repeated analysis on the same
case only pays for the incremental tokens.
"""
import anthropic
from flask import current_app
from typing import Optional


SYSTEM_PROMPT = """You are ContainIQ's AI security analyst — an expert SOC analyst and incident responder embedded in a governed response platform.

Your role:
- Analyze security incidents with precision and urgency
- Recommend containment actions with explicit blast-radius awareness
- Generate threat hunting queries (Splunk SPL, KQL, Sigma)
- Map findings to MITRE ATT&CK tactics and techniques
- Write clear, audit-ready incident reports
- Recommend appropriate playbooks from the available library

Always structure your output as valid JSON when responding to structured requests.
Never hallucinate IOCs, CVEs, or technique IDs — if uncertain, say so explicitly.
Flag if any entity shows signs of lateral movement, persistence, or exfiltration.
"""


def _make_client():
    key = current_app.config.get("ANTHROPIC_API_KEY", "")
    if not key:
        return None
    return anthropic.Anthropic(api_key=key)


def _case_context(case) -> str:
    lines = [
        f"Case #{case.id}: {case.title}",
        f"Severity: {case.severity} | Status: {case.status}",
        f"Created: {case.created_at}",
        "",
        "Entities:",
    ]
    for e in case.entities:
        lines.append(f"  [{e.entity_type}] {e.value}")

    if case.timeline:
        lines.append("\nTimeline (chronological):")
        for t in case.timeline:
            lines.append(f"  {t.event_time.isoformat()} [{t.event_type}] {t.description}")

    if case.evidence:
        lines.append("\nEvidence:")
        for ev in case.evidence:
            lines.append(f"  [{ev.evidence_type}] {ev.name}")

    return "\n".join(lines)


class AIAnalyst:
    def __init__(self):
        self.client = _make_client()
        self.model = current_app.config.get("ANTHROPIC_MODEL", "claude-sonnet-4-6")

    def _chat(self, messages: list, use_cache: bool = True) -> str:
        if not self.client:
            return '{"error": "No ANTHROPIC_API_KEY configured — set it in .env"}'

        system = [{"type": "text", "text": SYSTEM_PROMPT}]
        if use_cache:
            system[0]["cache_control"] = {"type": "ephemeral"}

        response = self.client.messages.create(
            model=self.model,
            max_tokens=2048,
            system=system,
            messages=messages,
        )
        return response.content[0].text

    def analyze_case(self, case) -> dict:
        ctx = _case_context(case)
        prompt = f"""Analyze this security incident and return a JSON object with these keys:
- summary: 2-3 sentence executive summary
- attack_stage: most likely kill-chain stage (recon/weaponize/deliver/exploit/install/c2/actions)
- mitre_techniques: list of {{id, name, confidence}} objects
- severity_rationale: why this severity level is correct
- immediate_actions: list of recommended immediate containment steps
- investigation_gaps: what evidence is missing
- threat_actor_hypothesis: possible threat actor or campaign (or "unknown")

Case context:
{ctx}

Return only valid JSON."""
        raw = self._chat([{"role": "user", "content": prompt}])
        try:
            import json
            return json.loads(raw)
        except Exception:
            return {"raw": raw}

    def generate_hunt_queries(self, case, question: str, siem: str = "splunk") -> dict:
        ctx = _case_context(case)
        siem_map = {
            "splunk": "Splunk SPL",
            "sentinel": "Microsoft Sentinel KQL",
            "elastic": "Elastic EQL/KQL",
        }
        siem_label = siem_map.get(siem, "Splunk SPL")
        prompt = f"""Generate threat hunting queries for {siem_label}.

Case context:
{ctx}

Analyst question: {question}

Return a JSON object with:
- queries: list of {{name, description, query, expected_results, false_positive_notes}}
- hunting_hypothesis: the underlying threat hypothesis being tested
- recommended_timeframe: suggested lookback window

Return only valid JSON."""
        raw = self._chat([{"role": "user", "content": prompt}])
        try:
            import json
            return json.loads(raw)
        except Exception:
            return {"raw": raw}

    def ask(self, case, question: str) -> dict:
        ctx = _case_context(case)
        prompt = f"""Case context:
{ctx}

Analyst question: {question}

Answer as a senior SOC analyst. Be direct and specific. If recommending an action, note any blast-radius considerations."""
        answer = self._chat([{"role": "user", "content": prompt}], use_cache=False)
        return {"answer": answer}

    def explain_severity(self, case) -> dict:
        ctx = _case_context(case)
        prompt = f"""Evaluate the severity assignment for this case.

Case context:
{ctx}

Return a JSON object with:
- current_severity: the assigned severity
- assessment: "accurate" | "too_high" | "too_low"
- rationale: why
- suggested_severity: your recommendation
- key_factors: list of factors driving severity

Return only valid JSON."""
        raw = self._chat([{"role": "user", "content": prompt}])
        try:
            import json
            return json.loads(raw)
        except Exception:
            return {"raw": raw}

    def recommend_playbook(self, case, playbooks: list) -> dict:
        ctx = _case_context(case)
        pb_list = "\n".join(
            f"  [{pb.id}] {pb.name} (pack: {pb.pack}): {pb.description}" for pb in playbooks
        )
        prompt = f"""Given this incident, recommend the best matching playbook.

Case context:
{ctx}

Available playbooks:
{pb_list}

Return a JSON object with:
- recommended_id: playbook ID
- recommended_name: playbook name
- rationale: why this playbook fits
- confidence: high | medium | low
- secondary_options: list of other applicable playbook IDs

Return only valid JSON."""
        raw = self._chat([{"role": "user", "content": prompt}])
        try:
            import json
            return json.loads(raw)
        except Exception:
            return {"raw": raw}

    def generate_threat_proposals(self, threat_summary: str, existing_playbooks: list) -> dict:
        """Daily pipeline: given today's threat intel, propose detection/playbook updates."""
        pb_names = ", ".join(pb.name for pb in existing_playbooks)
        prompt = f"""You are reviewing today's threat intelligence and proposing updates to a SOC platform.

Today's threat intelligence summary:
{threat_summary}

Existing playbooks: {pb_names}

Generate a JSON object with:
- new_detections: list of {{title, rationale, sigma_rule_stub, mitre_technique}}
- playbook_updates: list of {{target_playbook_name, change_description, priority}}
- new_evidence_requirements: list of {{title, description, evidence_type}}
- threat_summary: 3-4 sentence briefing for analysts
- top_iocs: list of {{type, value, context}} (max 10, only verified from the intelligence)

Return only valid JSON."""
        raw = self._chat([{"role": "user", "content": prompt}], use_cache=False)
        try:
            import json
            return json.loads(raw)
        except Exception:
            return {"raw": raw}
