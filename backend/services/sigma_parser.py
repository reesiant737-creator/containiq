"""Parse Sigma YAML detection rules into the ThreatCommand normalized format."""
import json
import re

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore


# Map Sigma tactic slugs → display names
_TACTIC_MAP = {
    "reconnaissance": "Reconnaissance",
    "resource_development": "Resource Development",
    "initial_access": "Initial Access",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege_escalation": "Privilege Escalation",
    "defense_evasion": "Defense Evasion",
    "credential_access": "Credential Access",
    "discovery": "Discovery",
    "lateral_movement": "Lateral Movement",
    "collection": "Collection",
    "command_and_control": "Command and Control",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
}

# Map Sigma level → our severity
_LEVEL_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "low",
}


def _extract_mitre(tags: list) -> tuple[list, list]:
    """Return (tactics, techniques) extracted from Sigma tags list."""
    tactics = []
    techniques = []
    for tag in tags:
        tag_lower = tag.lower()
        if not tag_lower.startswith("attack."):
            continue
        slug = tag_lower[len("attack."):]
        # Technique IDs look like t1059, t1059.001
        if re.match(r"^t\d{4}", slug):
            techniques.append(slug.upper())
        else:
            # Tactic slug
            display = _TACTIC_MAP.get(slug, slug.replace("_", " ").title())
            if display not in tactics:
                tactics.append(display)
    return tactics, techniques


def parse_sigma_yaml(yaml_text: str) -> dict:
    """Parse a single Sigma rule YAML string and return a normalized dict.

    Returns a dict with keys:
        title, description, severity, mitre_tactics, mitre_techniques,
        tags, detection_logic, false_positive_notes
    Raises ValueError on parse failure.
    """
    if yaml is None:
        raise RuntimeError("PyYAML is not installed. Add pyyaml to requirements.txt.")

    try:
        data = yaml.safe_load(yaml_text)
    except yaml.YAMLError as exc:
        raise ValueError(f"Invalid YAML: {exc}") from exc

    if not isinstance(data, dict):
        raise ValueError("Sigma rule must be a YAML mapping at the top level.")

    title = data.get("title") or data.get("name") or "Untitled Rule"
    description = data.get("description") or ""

    # Severity
    level = str(data.get("level", "medium")).lower()
    severity = _LEVEL_MAP.get(level, "medium")

    # MITRE tags
    raw_tags = data.get("tags") or []
    if isinstance(raw_tags, str):
        raw_tags = [raw_tags]
    tactics, techniques = _extract_mitre(raw_tags)

    # Non-attack tags
    other_tags = [
        t for t in raw_tags
        if not t.lower().startswith("attack.")
    ]

    # Detection logic — store as JSON-serialized dict
    detection = data.get("detection") or {}
    detection_logic = json.dumps(detection, default=str)

    # False positives
    fp = data.get("falsepositives") or []
    if isinstance(fp, list):
        false_positive_notes = "\n".join(str(x) for x in fp)
    else:
        false_positive_notes = str(fp)

    return {
        "title": title,
        "description": description,
        "severity": severity,
        "mitre_tactics": tactics,
        "mitre_techniques": techniques,
        "tags": other_tags,
        "detection_logic": detection_logic,
        "false_positive_notes": false_positive_notes,
    }


def split_sigma_rules(text: str) -> list[str]:
    """Split a multi-rule YAML document (separated by ---) into individual rule strings.

    Each returned string is a single Sigma rule YAML.
    """
    # Split on YAML document separator; keep non-empty chunks
    parts = re.split(r"(?m)^---\s*$", text)
    rules = []
    for part in parts:
        stripped = part.strip()
        if stripped:
            rules.append(stripped)
    return rules
