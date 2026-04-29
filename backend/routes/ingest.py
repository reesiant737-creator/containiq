"""
Alert Ingestion API — accepts alerts from external security tools and auto-creates cases.

Supported formats (auto-detected):
  - Microsoft Sentinel (Common Alert Schema)
  - Splunk (JSON alert payload)
  - CrowdStrike Falcon (detection webhook)
  - Elastic SIEM (ES|QL alert)
  - Generic (key-value JSON — always works)

Auth: API key via X-API-Key header or ?api_key= query param.
"""
from flask import Blueprint, request, jsonify
from datetime import datetime, timezone
from ..models.case import Case, Entity, TimelineEvent, SEVERITY
from ..models.user import User
from ..services.audit_service import audit
from ..services.notifier import Notifier
from ..app import db
import hashlib, hmac, os

ingest_bp = Blueprint("ingest", __name__, url_prefix="/api/v1")

# ── Auth ──────────────────────────────────────────────────────────────────────

def _resolve_api_key():
    key = (request.headers.get("X-API-Key") or
           request.args.get("api_key") or "")
    return key.strip()

def _get_org_by_key(api_key: str):
    """Resolve org from API key. For MVP: any key matching env var maps to default org."""
    from ..models.org import Org
    configured = os.environ.get("INGEST_API_KEY", "")
    if not configured or not api_key:
        return None
    if not hmac.compare_digest(api_key, configured):
        return None
    return Org.query.first()


# ── Normalizers ───────────────────────────────────────────────────────────────

def _normalize_sentinel(payload: dict) -> dict:
    props = payload.get("properties", {})
    ents = props.get("relatedEntities", []) or []
    return {
        "title": props.get("title", "Microsoft Sentinel Alert"),
        "description": props.get("description", ""),
        "severity": _map_severity(props.get("severity", "Medium")),
        "source": "microsoft_sentinel",
        "source_ref": payload.get("id", ""),
        "entities": [
            {"type": _sentinel_entity_type(e.get("kind", "")),
             "value": e.get("properties", {}).get("address")
                   or e.get("properties", {}).get("hostName")
                   or e.get("properties", {}).get("accountName")
                   or str(e.get("properties", {}))}
            for e in ents if e.get("properties")
        ],
        "initial_event": f"Sentinel alert: {props.get('alertDisplayName', props.get('title', ''))}",
    }

def _normalize_splunk(payload: dict) -> dict:
    result = payload.get("result", payload)
    return {
        "title": payload.get("search_name", result.get("source", "Splunk Alert")),
        "description": payload.get("message", ""),
        "severity": _map_severity(result.get("severity", result.get("urgency", "medium"))),
        "source": "splunk",
        "source_ref": payload.get("sid", ""),
        "entities": _extract_generic_entities(result),
        "initial_event": f"Splunk alert fired: {payload.get('search_name', 'unknown search')}",
    }

def _normalize_crowdstrike(payload: dict) -> dict:
    evt = payload.get("event", {})
    behaviors = payload.get("behaviors", [{}])
    b = behaviors[0] if behaviors else {}
    severity_int = b.get("severity", evt.get("Severity", 50))
    return {
        "title": b.get("display_name", evt.get("Name", "CrowdStrike Detection")),
        "description": b.get("description", ""),
        "severity": _cs_severity(severity_int),
        "source": "crowdstrike",
        "source_ref": payload.get("detection_id", ""),
        "entities": [
            {"type": "device",  "value": payload.get("device", {}).get("hostname", "unknown")},
            {"type": "user",    "value": b.get("user_name", "")},
            {"type": "hash",    "value": b.get("sha256", "")},
            {"type": "ip",      "value": payload.get("device", {}).get("local_ip", "")},
        ],
        "initial_event": f"CrowdStrike: {b.get('display_name', 'detection')} on {payload.get('device', {}).get('hostname', 'unknown host')}",
    }

def _normalize_elastic(payload: dict) -> dict:
    signal = payload.get("signal", {})
    rule = signal.get("rule", {})
    return {
        "title": rule.get("name", "Elastic SIEM Alert"),
        "description": rule.get("description", ""),
        "severity": _map_severity(signal.get("severity", rule.get("severity", "medium"))),
        "source": "elastic_siem",
        "source_ref": payload.get("_id", ""),
        "entities": _extract_generic_entities(payload.get("_source", {})),
        "initial_event": f"Elastic SIEM: {rule.get('name', 'alert')} — {signal.get('reason', '')}",
    }

def _normalize_generic(payload: dict) -> dict:
    return {
        "title": (payload.get("title") or payload.get("name") or
                  payload.get("alert_name") or payload.get("rule_name") or "Ingested Alert"),
        "description": (payload.get("description") or payload.get("message") or
                        payload.get("details") or ""),
        "severity": _map_severity(payload.get("severity") or payload.get("urgency") or "medium"),
        "source": payload.get("source") or "api_ingest",
        "source_ref": str(payload.get("id") or payload.get("alert_id") or ""),
        "entities": _extract_generic_entities(payload),
        "initial_event": payload.get("summary") or payload.get("title") or "Alert ingested via API",
    }

def _extract_generic_entities(d: dict) -> list:
    entities = []
    ip_keys = ["src_ip","dest_ip","source_ip","remote_ip","ip","client_ip","attacker_ip"]
    for k in ip_keys:
        if d.get(k):
            entities.append({"type": "ip", "value": str(d[k])})
    user_keys = ["user","username","user_name","principal","account","email"]
    for k in user_keys:
        if d.get(k):
            entities.append({"type": "user", "value": str(d[k])})
    host_keys = ["host","hostname","device","computer","endpoint","machine"]
    for k in host_keys:
        if d.get(k):
            entities.append({"type": "device", "value": str(d[k])})
    hash_keys = ["sha256","md5","sha1","file_hash","hash"]
    for k in hash_keys:
        if d.get(k):
            entities.append({"type": "hash", "value": str(d[k])})
    domain_keys = ["domain","fqdn","dest_domain","url"]
    for k in domain_keys:
        if d.get(k):
            entities.append({"type": "domain", "value": str(d[k])})
    # Deduplicate
    seen = set()
    unique = []
    for e in entities:
        key = f"{e['type']}:{e['value']}"
        if key not in seen and e["value"]:
            seen.add(key)
            unique.append(e)
    return unique

def _detect_format(payload: dict) -> str:
    if "properties" in payload and "alertDisplayName" in str(payload.get("properties", {})):
        return "sentinel"
    if "search_name" in payload or "result" in payload:
        return "splunk"
    if "behaviors" in payload or "detection_id" in payload:
        return "crowdstrike"
    if "signal" in payload and "rule" in payload.get("signal", {}):
        return "elastic"
    return "generic"

def _map_severity(raw) -> str:
    if not raw:
        return "medium"
    s = str(raw).lower()
    if s in ("critical", "4", "fatal"):         return "critical"
    if s in ("high", "3", "error"):              return "high"
    if s in ("medium", "2", "warning", "moderate"): return "medium"
    if s in ("low", "1", "info", "informational"):  return "low"
    return "medium"

def _cs_severity(n) -> str:
    try:
        n = int(n)
        if n >= 90: return "critical"
        if n >= 70: return "high"
        if n >= 40: return "medium"
        return "low"
    except (ValueError, TypeError):
        return "medium"

def _sentinel_entity_type(kind: str) -> str:
    m = {"ip": "ip", "host": "device", "account": "user",
         "url": "domain", "file": "file", "malware": "hash"}
    return m.get(kind.lower(), "ip")


# ── Endpoints ─────────────────────────────────────────────────────────────────

@ingest_bp.route("/alerts", methods=["POST"])
def ingest_alert():
    """
    Generic alert ingestion endpoint. Auto-detects format.
    POST /api/v1/alerts
    Headers: X-API-Key: <your-ingest-key>
    Body: JSON alert payload (Sentinel, Splunk, CrowdStrike, Elastic, or generic)
    """
    org = _get_org_by_key(_resolve_api_key())
    if not org:
        return jsonify({"error": "unauthorized — provide valid X-API-Key header"}), 401

    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 400

    payload = request.get_json(force=True) or {}
    fmt = request.args.get("format") or _detect_format(payload)

    normalizers = {
        "sentinel": _normalize_sentinel,
        "splunk": _normalize_splunk,
        "crowdstrike": _normalize_crowdstrike,
        "elastic": _normalize_elastic,
        "generic": _normalize_generic,
    }
    normalized = normalizers.get(fmt, _normalize_generic)(payload)

    # De-duplicate: don't create if source_ref already exists
    if normalized["source_ref"]:
        existing = Case.query.filter_by(
            org_id=org.id, source_ref=normalized["source_ref"]
        ).first()
        if existing:
            return jsonify({
                "status": "duplicate",
                "case_id": existing.id,
                "message": f"Case #{existing.id} already exists for this alert ID.",
            }), 200

    # Find or use system user
    system_user = User.query.filter_by(org_id=org.id, role="admin").first()
    user_id = system_user.id if system_user else None

    case = Case(
        org_id=org.id,
        title=normalized["title"][:255],
        description=normalized["description"],
        severity=normalized["severity"],
        status="open",
        source=normalized["source"],
        source_ref=normalized["source_ref"],
        created_by=user_id,
    )
    db.session.add(case)
    db.session.flush()

    # Add entities
    for e in normalized["entities"]:
        if e.get("value"):
            db.session.add(Entity(
                case_id=case.id,
                entity_type=e["type"],
                value=str(e["value"])[:511],
            ))

    # Add initial timeline event
    if normalized["initial_event"]:
        db.session.add(TimelineEvent(
            case_id=case.id,
            event_time=datetime.now(timezone.utc),
            event_type="alert_fired",
            description=normalized["initial_event"],
            source=normalized["source"],
            created_by=user_id,
        ))

    db.session.commit()

    audit("case.ingested", org_id=org.id, user_id=user_id,
          resource_type="case", resource_id=str(case.id), case_id=case.id,
          payload={"format": fmt, "severity": case.severity,
                   "source": case.source, "source_ref": case.source_ref})

    # Notify if critical
    if case.severity in ("critical", "high"):
        try:
            Notifier().new_case(case)
        except Exception:
            pass

    return jsonify({
        "status": "created",
        "case_id": case.id,
        "severity": case.severity,
        "title": case.title,
        "url": f"/cases/{case.id}",
        "entities_extracted": len(normalized["entities"]),
        "format_detected": fmt,
    }), 201


@ingest_bp.route("/alerts/test", methods=["POST"])
def test_ingest():
    """Test endpoint — validates payload and returns normalized form without creating a case."""
    org = _get_org_by_key(_resolve_api_key())
    if not org:
        return jsonify({"error": "unauthorized"}), 401

    payload = request.get_json(force=True) or {}
    fmt = request.args.get("format") or _detect_format(payload)
    normalizers = {
        "sentinel": _normalize_sentinel, "splunk": _normalize_splunk,
        "crowdstrike": _normalize_crowdstrike, "elastic": _normalize_elastic,
        "generic": _normalize_generic,
    }
    normalized = normalizers.get(fmt, _normalize_generic)(payload)
    return jsonify({"format_detected": fmt, "normalized": normalized})


@ingest_bp.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "ContainIQ", "version": "1.0.0"})
