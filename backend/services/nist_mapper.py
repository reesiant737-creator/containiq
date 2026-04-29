"""
NIST Cybersecurity Framework 2.0 mapping engine.
Maps case activity to GV/ID/PR/DE/RS/RC functions and generates actionable gaps.
"""

NIST_FUNCTIONS = {
    "GV": {
        "name": "GOVERN",
        "description": "Org context, risk strategy, supply chain, policies, oversight",
        "color": "#6f42c1",
        "categories": {
            "GV.OC": "Organizational Context",
            "GV.RM": "Risk Management Strategy",
            "GV.RR": "Roles, Responsibilities & Authorities",
            "GV.PO": "Policy",
            "GV.OV": "Oversight",
            "GV.SC": "Cybersecurity Supply Chain Risk",
        },
    },
    "ID": {
        "name": "IDENTIFY",
        "description": "Asset management, risk assessment, improvement",
        "color": "#fd7e14",
        "categories": {
            "ID.AM": "Asset Management",
            "ID.RA": "Risk Assessment",
            "ID.IM": "Improvement",
        },
    },
    "PR": {
        "name": "PROTECT",
        "description": "Identity management, awareness, data security, platform security",
        "color": "#198754",
        "categories": {
            "PR.AA": "Identity Management & Access Control",
            "PR.AT": "Awareness & Training",
            "PR.DS": "Data Security",
            "PR.PS": "Platform Security",
            "PR.IR": "Technology Infrastructure Resilience",
        },
    },
    "DE": {
        "name": "DETECT",
        "description": "Continuous monitoring, adverse event analysis",
        "color": "#0dcaf0",
        "categories": {
            "DE.CM": "Continuous Monitoring",
            "DE.AE": "Adverse Event Analysis",
        },
    },
    "RS": {
        "name": "RESPOND",
        "description": "Incident management, analysis, mitigation, reporting",
        "color": "#dc3545",
        "categories": {
            "RS.MA": "Incident Management",
            "RS.AN": "Incident Analysis",
            "RS.CO": "Incident Response Reporting & Communication",
            "RS.MI": "Incident Mitigation",
        },
    },
    "RC": {
        "name": "RECOVER",
        "description": "Recovery plan, communication",
        "color": "#0d6efd",
        "categories": {
            "RC.RP": "Incident Recovery Plan Execution",
            "RC.CO": "Incident Recovery Communication",
        },
    },
}

# Map case severity/event_types to NIST function coverage
ACTIVITY_MAPPING = {
    "case_opened": ["RS.MA", "DE.AE"],
    "evidence_added": ["RS.AN", "DE.AE"],
    "timeline_event": ["RS.AN", "DE.CM"],
    "playbook_executed": ["RS.MI", "RS.MA"],
    "report_generated": ["RS.CO", "GV.OV"],
    "audit_packet_generated": ["GV.OV", "GV.PO"],
    "case_closed": ["RC.RP", "RS.MA"],
    "threat_feed_reviewed": ["ID.RA", "DE.CM"],
    "identity_alert": ["PR.AA", "DE.AE", "RS.AN"],
    "phishing": ["PR.AT", "DE.AE", "RS.MI"],
    "ransomware": ["PR.DS", "RS.MI", "RC.RP"],
    "privilege_escalation": ["PR.AA", "DE.CM", "RS.AN"],
    "lateral_movement": ["DE.CM", "RS.MI", "PR.IR"],
}


class NistMapper:
    def __init__(self, case):
        self.case = case

    def generate_mapping(self) -> dict:
        if not self.case:
            return {}

        covered = set()
        rationale = {}
        actions = []

        # Map from timeline event types
        for event in (self.case.timeline or []):
            et = event.event_type
            mapped = ACTIVITY_MAPPING.get(et, [])
            for cat in mapped:
                covered.add(cat)
                rationale.setdefault(cat, []).append(event.description[:80])

        # Map from playbook runs
        for run in (self.case.playbook_runs or []):
            if run.status in ("completed", "dry_run_complete"):
                for cat in ["RS.MA", "RS.MI", "RS.AN"]:
                    covered.add(cat)
                    rationale.setdefault(cat, []).append(f"Playbook: {run.playbook.name}")

        # Map from evidence
        if self.case.evidence:
            for cat in ["RS.AN", "DE.AE"]:
                covered.add(cat)

        # Identify gaps and generate actionable recommendations
        all_cats = set()
        for func in NIST_FUNCTIONS.values():
            all_cats.update(func["categories"].keys())

        gaps = all_cats - covered
        for gap in sorted(gaps):
            func_key = gap.split(".")[0]
            func = NIST_FUNCTIONS.get(func_key, {})
            cat_name = func.get("categories", {}).get(gap, gap)
            actions.append({
                "category": gap,
                "category_name": cat_name,
                "function": func.get("name"),
                "action": _gap_action(gap),
                "priority": _gap_priority(gap),
            })

        actions.sort(key=lambda x: {"high": 0, "medium": 1, "low": 2}[x["priority"]])

        return {
            "case_id": self.case.id,
            "covered_categories": sorted(covered),
            "gap_categories": sorted(gaps),
            "coverage_pct": round(len(covered) / len(all_cats) * 100, 1) if all_cats else 0,
            "rationale": rationale,
            "actionable_gaps": actions[:10],
            "functions_summary": self._functions_summary(covered),
        }

    def org_coverage(self, cases: list) -> dict:
        all_covered = set()
        for c in cases:
            self.case = c
            result = self.generate_mapping()
            all_covered.update(result.get("covered_categories", []))

        all_cats = set()
        for func in NIST_FUNCTIONS.values():
            all_cats.update(func["categories"].keys())

        return {
            "total_cases": len(cases),
            "covered_categories": sorted(all_covered),
            "gap_categories": sorted(all_cats - all_covered),
            "coverage_pct": round(len(all_covered) / len(all_cats) * 100, 1) if all_cats else 0,
            "functions": NIST_FUNCTIONS,
            "functions_summary": self._functions_summary(all_covered),
        }

    def _functions_summary(self, covered: set) -> list:
        summary = []
        for key, func in NIST_FUNCTIONS.items():
            cats = func["categories"]
            func_covered = [c for c in cats if c in covered]
            summary.append({
                "key": key,
                "name": func["name"],
                "color": func["color"],
                "total": len(cats),
                "covered": len(func_covered),
                "pct": round(len(func_covered) / len(cats) * 100) if cats else 0,
            })
        return summary


def _gap_action(category: str) -> str:
    actions = {
        "GV.OC": "Document organizational context and risk appetite in your security policy.",
        "GV.RM": "Define a formal risk management strategy with tolerance thresholds.",
        "GV.RR": "Assign explicit cybersecurity roles and escalation paths.",
        "GV.PO": "Publish and enforce written cybersecurity policies.",
        "GV.OV": "Establish executive oversight of cybersecurity program metrics.",
        "GV.SC": "Assess supply chain and third-party vendor security risks.",
        "ID.AM": "Maintain an up-to-date asset inventory (hardware, software, data).",
        "ID.RA": "Conduct formal risk assessments and track findings.",
        "ID.IM": "Establish a continuous improvement process from lessons learned.",
        "PR.AA": "Enforce MFA, least-privilege access, and periodic access reviews.",
        "PR.AT": "Run security awareness training and phishing simulations.",
        "PR.DS": "Classify and protect sensitive data at rest and in transit.",
        "PR.PS": "Harden platform configurations against CIS Benchmarks.",
        "PR.IR": "Build infrastructure resilience: redundancy, backups, DR plans.",
        "DE.CM": "Deploy continuous monitoring: SIEM, EDR, cloud log ingestion.",
        "DE.AE": "Enable automated adverse event analysis and alerting.",
        "RS.MA": "Activate and follow your incident management process.",
        "RS.AN": "Perform structured incident analysis with documented findings.",
        "RS.CO": "Communicate incident status to stakeholders per your plan.",
        "RS.MI": "Execute containment and mitigation steps with evidence.",
        "RC.RP": "Execute your recovery plan and validate restoration.",
        "RC.CO": "Communicate recovery status to affected parties.",
    }
    return actions.get(category, f"Address {category} per NIST CSF 2.0 guidance.")


def _gap_priority(category: str) -> str:
    high = {"RS.MA", "RS.MI", "DE.CM", "DE.AE", "PR.AA", "ID.RA"}
    low = {"GV.SC", "ID.IM", "PR.AT", "RC.CO"}
    if category in high:
        return "high"
    if category in low:
        return "low"
    return "medium"
