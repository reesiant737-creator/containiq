"""
IOC auto-enrichment service.

Queries VirusTotal and AbuseIPDB for IPs, domains, and file hashes
and stores results in Entity.context. Runs in a background thread
so it never blocks case creation or alert ingestion.

Supported entity types: ip, domain, hash
Gracefully skips enrichment if API keys are not configured.
"""
import threading
import requests
from datetime import datetime, timezone
from flask import current_app


_VT_BASE = "https://www.virustotal.com/api/v3"
_ABUSE_BASE = "https://api.abuseipdb.com/api/v2"

ENRICHABLE_TYPES = {"ip", "domain", "hash"}


def enrich_entities_async(entity_ids: list[int], app):
    """Kick off enrichment in a background thread — non-blocking."""
    t = threading.Thread(target=_run_enrichment, args=(entity_ids, app), daemon=True)
    t.start()


def _run_enrichment(entity_ids: list[int], app):
    with app.app_context():
        from ..models.case import Entity
        from ..app import db

        vt_key = app.config.get("VIRUSTOTAL_API_KEY", "")
        abuse_key = app.config.get("ABUSEIPDB_API_KEY", "")

        if not vt_key and not abuse_key:
            return

        for eid in entity_ids:
            entity = Entity.query.get(eid)
            if not entity or entity.entity_type not in ENRICHABLE_TYPES:
                continue
            try:
                result = _enrich(entity.entity_type, entity.value, vt_key, abuse_key)
                if result:
                    ctx = entity.context
                    ctx.update(result)
                    ctx["enriched_at"] = datetime.now(timezone.utc).isoformat()
                    entity.context = ctx
                    db.session.commit()
            except Exception as exc:
                import sys
                print(f"[IOC ENRICHMENT] Failed for {entity.entity_type}:{entity.value} — {exc}", file=sys.stderr)


def _enrich(entity_type: str, value: str, vt_key: str, abuse_key: str) -> dict:
    result = {}

    if entity_type == "ip":
        if vt_key:
            vt = _vt_ip(value, vt_key)
            if vt:
                result["virustotal"] = vt
        if abuse_key:
            abuse = _abuseipdb(value, abuse_key)
            if abuse:
                result["abuseipdb"] = abuse

    elif entity_type == "domain":
        if vt_key:
            vt = _vt_domain(value, vt_key)
            if vt:
                result["virustotal"] = vt

    elif entity_type == "hash":
        if vt_key:
            vt = _vt_hash(value, vt_key)
            if vt:
                result["virustotal"] = vt

    return result


def _vt_ip(ip: str, api_key: str) -> dict | None:
    try:
        r = requests.get(
            f"{_VT_BASE}/ip_addresses/{ip}",
            headers={"x-apikey": api_key},
            timeout=10,
        )
        if r.status_code != 200:
            return None
        data = r.json().get("data", {}).get("attributes", {})
        stats = data.get("last_analysis_stats", {})
        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "reputation": data.get("reputation", 0),
            "country": data.get("country", ""),
            "as_owner": data.get("as_owner", ""),
            "source": "virustotal",
        }
    except Exception:
        return None


def _vt_domain(domain: str, api_key: str) -> dict | None:
    try:
        r = requests.get(
            f"{_VT_BASE}/domains/{domain}",
            headers={"x-apikey": api_key},
            timeout=10,
        )
        if r.status_code != 200:
            return None
        data = r.json().get("data", {}).get("attributes", {})
        stats = data.get("last_analysis_stats", {})
        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "reputation": data.get("reputation", 0),
            "categories": list(data.get("categories", {}).values())[:3],
            "source": "virustotal",
        }
    except Exception:
        return None


def _vt_hash(file_hash: str, api_key: str) -> dict | None:
    try:
        r = requests.get(
            f"{_VT_BASE}/files/{file_hash}",
            headers={"x-apikey": api_key},
            timeout=10,
        )
        if r.status_code != 200:
            return None
        data = r.json().get("data", {}).get("attributes", {})
        stats = data.get("last_analysis_stats", {})
        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "meaningful_name": data.get("meaningful_name", ""),
            "type_description": data.get("type_description", ""),
            "size": data.get("size", 0),
            "source": "virustotal",
        }
    except Exception:
        return None


def _abuseipdb(ip: str, api_key: str) -> dict | None:
    try:
        r = requests.get(
            f"{_ABUSE_BASE}/check",
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": False},
            timeout=10,
        )
        if r.status_code != 200:
            return None
        data = r.json().get("data", {})
        return {
            "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
            "total_reports": data.get("totalReports", 0),
            "country_code": data.get("countryCode", ""),
            "usage_type": data.get("usageType", ""),
            "isp": data.get("isp", ""),
            "is_tor": data.get("isTor", False),
            "source": "abuseipdb",
        }
    except Exception:
        return None


def threat_level(entity) -> str:
    """Return 'high', 'medium', 'low', or 'unknown' based on enrichment context."""
    ctx = entity.context
    vt = ctx.get("virustotal", {})
    abuse = ctx.get("abuseipdb", {})

    malicious = vt.get("malicious", 0)
    score = abuse.get("abuse_confidence_score", 0)

    if malicious >= 5 or score >= 75:
        return "high"
    if malicious >= 1 or score >= 25:
        return "medium"
    if ctx.get("enriched_at"):
        return "low"
    return "unknown"
